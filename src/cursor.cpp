#include "lmdb-js.h"
#include <string.h>

using namespace Napi;

CursorWrap::CursorWrap(const CallbackInfo& info) {
    this->keyType = LmdbKeyType::StringKey;
    this->freeKey = nullptr;
    this->endKey.mv_size = 0; // indicates no end key (yet)
    if (info.Length() < 1) {
      return Nan::ThrowError("Wrong number of arguments");
    }

    DbiWrap *dw;
    napi_unwrap(info.Env(), info[0], &dw);

    // Open the cursor
    MDB_cursor *cursor;
    MDB_txn *txn = dw->ew->getReadTxn();
    int rc = mdb_cursor_open(txn, dw->dbi, &cursor);
    if (rc != 0) {
        return throwLmdbError(info.Env(), rc);
    }

    this->cursor = cursor;
    this->dw = dw;
    this->txn = txn;
    this->keyType = keyType;
    this->Wrap(info.This());

    return info.GetReturnValue().Set(info.This());
}

CursorWrap::~CursorWrap() {
    if (this->cursor) {
        this->dw->Unref();
        // Don't close cursor here, it is possible that the environment may already be closed, which causes it to crash
        //mdb_cursor_close(this->cursor);
    }
    if (this->freeKey) {
        this->freeKey(this->key);
    }
}

napi_value CursorWrap::close(const CallbackInfo& info) {
    if (!this->cursor) {
      return ThrowError(info.Env(), "cursor.close: Attempt to close a closed cursor!");
    }
    mdb_cursor_close(this->cursor);
    this->dw->Unref();
    this->cursor = nullptr;
}
extern "C" EXTERN void cursorClose(double cwPointer) {
    CursorWrap *cw = (CursorWrap*) (size_t) cwPointer;
    mdb_cursor_close(cw->cursor);
    cw->cursor = nullptr;
}

napi_value CursorWrap::del(const CallbackInfo& info) {
    int flags = 0;

    if (info.Length() == 1) {
        if (!info[0].IsObject()) {
            return Nan::ThrowError("cursor.del: Invalid options argument. It should be an object.");
        }
        
        auto options = info[0].As<Object>();
        setFlagFromValue(&flags, MDB_NODUPDATA, "noDupData", false, options);
    }

    int rc = mdb_cursor_del(this->cursor, flags);
    if (rc != 0) {
        return throwLmdbError(info.Env(), rc);
    }
}
int CursorWrap::returnEntry(int lastRC, MDB_val &key, MDB_val &data) {
    if (lastRC) {
        if (lastRC == MDB_NOTFOUND)
            return 0;
        else {
            return lastRC | 0x10000000;
        }
    }   
    if (endKey.mv_size > 0) {
        int comparison;
        if (flags & 0x800)
            comparison = mdb_dcmp(txn, dw->dbi, &endKey, &data);
        else
            comparison = mdb_cmp(txn, dw->dbi, &endKey, &key);
        if ((flags & 0x400) ? comparison >= 0 : (comparison <= 0)) {
            return 0;
        }
    }
	char* keyBuffer = dw->ew->keyBuffer;
	if (flags & 0x100) {
        bool result = getVersionAndUncompress(data, dw);
        if (result)
            result = valToBinaryFast(data, dw);
		*((size_t*)keyBuffer) = data.mv_size;
	}
	if (!(flags & 0x800))
        memcpy(keyBuffer + 32, key.mv_data, key.mv_size);

    return key.mv_size;
}

const int START_ADDRESS_POSITION = 4064;
uint32_t CursorWrap::doPosition(uint32_t offset, uint32_t keySize, uint64_t endKeyAddress) {
    //char* keyBuffer = dw->ew->keyBuffer;
    MDB_val key, data;
    int rc;
    if (flags & 0x2000) // TODO: check the txn_id to determine if we need to renew
        mdb_cursor_renew(txn = dw->ew->getReadTxn(), cursor);
    if (endKeyAddress) {
        uint32_t* keyBuffer = (uint32_t*) endKeyAddress;
        endKey.mv_size = *keyBuffer;
        endKey.mv_data = (char*)(keyBuffer + 1);
    } else
        endKey.mv_size = 0;
    iteratingOp = (flags & 0x400) ?
        (flags & 0x100) ?
            (flags & 0x800) ? MDB_PREV_DUP : MDB_PREV :
            MDB_PREV_NODUP :
        (flags & 0x100) ?
            (flags & 0x800) ? MDB_NEXT_DUP : MDB_NEXT :
            MDB_NEXT_NODUP;
    key.mv_size = keySize;
    key.mv_data = dw->ew->keyBuffer;
    if (keySize == 0) {
        rc = mdb_cursor_get(cursor, &key, &data, flags & 0x400 ? MDB_LAST : MDB_FIRST);  
    } else {
        if (flags & 0x800) { // only values for this key
            // take the next part of the key buffer as a pointer to starting data
            uint32_t* startValueBuffer = (uint32_t*)(size_t)(*(double*)(dw->ew->keyBuffer + START_ADDRESS_POSITION));
            data.mv_size = endKeyAddress ? *((uint32_t*)startValueBuffer) : 0;
            data.mv_data = startValueBuffer + 1;
            if (flags & 0x400) {// reverse through values
                MDB_val startValue = data; // save it for comparison
                rc = mdb_cursor_get(cursor, &key, &data, data.mv_size ? MDB_GET_BOTH_RANGE : MDB_SET_KEY);
                if (rc) {
                    if (startValue.mv_size) {
                        // value specified, but not found, so find key and go to last item
                        rc = mdb_cursor_get(cursor, &key, &data, MDB_SET_KEY);
                        if (!rc)
                            rc = mdb_cursor_get(cursor, &key, &data, MDB_LAST_DUP);
                    } // else just couldn't find the key
                } else { // found entry
                    if (startValue.mv_size == 0) // no value specified, so go to last value
                        rc = mdb_cursor_get(cursor, &key, &data, MDB_LAST_DUP);
                    else if (mdb_dcmp(txn, dw->dbi, &startValue, &data)) // the range found the next value *after* the start
                        rc = mdb_cursor_get(cursor, &key, &data, MDB_PREV_DUP);
                }
            } else // forward, just do a get by range
                rc = mdb_cursor_get(cursor, &key, &data, data.mv_size ?
                    (flags & 0x4000) ? MDB_GET_BOTH : MDB_GET_BOTH_RANGE : MDB_SET_KEY);

            if (rc == MDB_NOTFOUND)
                return 0;
            if (flags & 0x1000 && (!endKeyAddress || (flags & 0x4000))) {
                size_t count;
                rc = mdb_cursor_count(cursor, &count);
                if (rc)
                    throwLmdbError(info.Env(), rc);
                return count;
            }
        } else {
            if (flags & 0x400) {// reverse
                MDB_val firstKey = key; // save it for comparison
                rc = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
                if (rc)
                    rc = mdb_cursor_get(cursor, &key, &data, MDB_LAST);
                else if (mdb_cmp(txn, dw->dbi, &firstKey, &key)) // the range found the next entry *after* the start
                    rc = mdb_cursor_get(cursor, &key, &data, MDB_PREV);
            } else // forward, just do a get by range
                rc = mdb_cursor_get(cursor, &key, &data, (flags & 0x4000) ? MDB_SET_KEY : MDB_SET_RANGE);
        }
    }
    while (offset-- > 0 && !rc) {
        rc = mdb_cursor_get(cursor, &key, &data, iteratingOp);
    }
    if (flags & 0x1000) {
        uint32_t count = 0;
        bool useCursorCount = false;
        // if we are in a dupsort database, and we are iterating over all entries, we can just count all the values for each key
        if (dw->flags & MDB_DUPSORT) {
            if (iteratingOp == MDB_PREV) {
                iteratingOp = MDB_PREV_NODUP;
                useCursorCount = true;
            }
            if (iteratingOp == MDB_NEXT) {
                iteratingOp = MDB_NEXT_NODUP;
                useCursorCount = true;
            }
        }

        while (!rc) {
            if (endKey.mv_size > 0) {
                int comparison;
                if (flags & 0x800)
                    comparison = mdb_dcmp(txn, dw->dbi, &endKey, &data);
                else
                    comparison = mdb_cmp(txn, dw->dbi, &endKey, &key);
                if ((flags & 0x400) ? comparison >= 0 : (comparison <=0)) {
                    return count;
                }
            }
            if (useCursorCount) {
                size_t countForKey;
                rc = mdb_cursor_count(cursor, &countForKey);
                if (rc)
                    throwLmdbError(info.Env(), rc);
                count += countForKey;
            } else
                count++;
            rc = mdb_cursor_get(cursor, &key, &data, iteratingOp);
        }
        return count;
    }
    // TODO: Handle count?
    return returnEntry(rc, key, data);
}
#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
uint32_t CursorWrap::positionFast(Local<Object> receiver_obj, uint32_t flags, uint32_t offset, uint32_t keySize, uint64_t endKeyAddress, FastApiCallbackOptions& options) {
    CursorWrap* cw = static_cast<CursorWrap*>(
        receiver_obj->GetAlignedPointerFromInternalField(0));
    DbiWrap* dw = cw->dw;
    dw->getFast = true;
    cw->flags = flags;
    uint32_t result = cw->doPosition(offset, keySize, endKeyAddress);
    if (dw->getFast)
        dw->getFast = false;
    else
        options.fallback = true;
    return result;
}
#endif
Napi::Value CursorWrap::position(const CallbackInfo& info) {
    this->flags = info[0]->As<Number>();
    uint32_t offset = info[1]->As<Number>();
    uint32_t keySize = info[2]->As<Number>();
    uint64_t endKeyAddress = info[3]->As<Number>();
    uint32_t result = this->doPosition(offset, keySize, endKeyAddress);
    return Number::New(result);
}
extern "C" EXTERN int cursorPosition(double cwPointer, uint32_t flags, uint32_t offset, uint32_t keySize, double endKeyAddress) {
    CursorWrap *cw = (CursorWrap*) (size_t) cwPointer;
    cw->flags = flags;
    return cw->doPosition(offset, keySize, (uint64_t) endKeyAddress);
}

#ifdef ENABLE_FAST_API
int32_t CursorWrap::iterateFast(Local<Object> receiver_obj, FastApiCallbackOptions& options) {
    CursorWrap* cw = static_cast<CursorWrap*>(
        receiver_obj->GetAlignedPointerFromInternalField(0));
    DbiWrap* dw = cw->dw;
    dw->getFast = true;
    MDB_val key, data;
    int rc = mdb_cursor_get(cw->cursor, &key, &data, cw->iteratingOp);
    return cw->returnEntry(rc, key, data);
}
#endif
Napi::Value CursorWrap::iterate(const CallbackInfo& info) {
    MDB_val key, data;
    int rc = mdb_cursor_get(this->cursor, &key, &data, this->iteratingOp);
    return Number:New(info.Env(), this->returnEntry(rc, key, data));
}
extern "C" EXTERN int cursorIterate(double cwPointer) {
    CursorWrap *cw = (CursorWrap*) (size_t) cwPointer;
    MDB_val key, data;
    int rc = mdb_cursor_get(cw->cursor, &key, &data, cw->iteratingOp);
    return cw->returnEntry(rc, key, data);
}
napi_value CursorWrap::getCurrentValue(const CallbackInfo& info) {
    MDB_val key, data;
    int rc = mdb_cursor_get(this->cursor, &key, &data, MDB_GET_CURRENT);
    return Number:New(info.Env(), this->returnEntry(rc, key, data));
}
extern "C" EXTERN int cursorCurrentValue(double cwPointer) {
    CursorWrap *cw = (CursorWrap*) (size_t) cwPointer;
    MDB_val key, data;
    int rc = mdb_cursor_get(cw->cursor, &key, &data, MDB_GET_CURRENT);
    return cw->returnEntry(rc, key, data);
}
Napi::Value CursorWrap::renew(const CallbackInfo& info) {
    int rc = mdb_cursor_renew(this->txn = this->dw->ew->getReadTxn(), this->cursor);
    if (rc != 0) {
        return throwLmdbError(info.Env(), rc);
    }
}
extern "C" EXTERN int cursorRenew(double cwPointer) {
    CursorWrap *cw = (CursorWrap*) (size_t) cwPointer;
    return mdb_cursor_renew(cw->txn = cw->dw->ew->getReadTxn(), cw->cursor);
}
void CursorWrap::setupExports(Napi::Env env, Object exports) {
    // CursorWrap: Prepare constructor template
    Function CursorClass = DefineClass(env, "Cursor", {
    // CursorWrap: Add functions to the prototype
        CursorWrap::InstanceMethod("close", &CursorWrap::close),
        CursorWrap::InstanceMethod("del", &CursorWrap::del),
        CursorWrap::InstanceMethod("getCurrentValue", &CursorWrap::getCurrentValue),
        CursorWrap::InstanceMethod("renew", &CursorWrap::renew),

    #ifdef ENABLE_FAST_API
    Isolate *isolate = Isolate::GetCurrent();
    auto positionFast = CFunction::Make(CursorWrap::positionFast);
    cursorTpl->PrototypeTemplate()->Set(isolate, "position", v8::FunctionTemplate::New(
          isolate, CursorWrap::position, v8::Local<v8::Value>(),
          v8::Local<v8::Signature>(), 0, v8::ConstructorBehavior::kThrow,
          v8::SideEffectType::kHasNoSideEffect, &positionFast));

    auto iterateFast = CFunction::Make(CursorWrap::iterateFast);
    cursorTpl->PrototypeTemplate()->Set(isolate, "iterate", v8::FunctionTemplate::New(
          isolate, CursorWrap::iterate, v8::Local<v8::Value>(),
          v8::Local<v8::Signature>(), 0, v8::ConstructorBehavior::kThrow,
          v8::SideEffectType::kHasNoSideEffect, &iterateFast));
    #else
        CursorWrap::InstanceMethod("position", &CursorWrap::position),
        CursorWrap::InstanceMethod("iterate", &CursorWrap::iterate),
    #endif
    });
    exports.Set("Cursor", CursorClass);

//    cursorTpl->InstanceTemplate()->SetInternalFieldCount(1);
}

// This file contains code from the node-lmdb project
// Copyright (c) 2013-2017 Timur Kristóf
// Copyright (c) 2021 Kristopher Tate
// Licensed to you under the terms of the MIT license
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

