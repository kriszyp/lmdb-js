#include "lmdb-js.h"
#include <cstdio>

using namespace v8;
using namespace node;

void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Local<Object> options);

DbiWrap::DbiWrap(MDB_env *env, MDB_dbi dbi) {
    this->env = env;
    this->dbi = dbi;
    this->keyType = LmdbKeyType::DefaultKey;
    this->compression = nullptr;
    this->isOpen = false;
    this->getFast = false;
    this->ew = nullptr;
}

DbiWrap::~DbiWrap() {
    // Imagine the following JS:
    // ------------------------
    //     var dbi1 = env.openDbi({ name: "hello" });
    //     var dbi2 = env.openDbi({ name: "hello" });
    //     dbi1.close();
    //     txn.putString(dbi2, "world");
    // -----
    // The above DbiWrap objects would both wrap the same MDB_dbi, and if closing the first one called mdb_dbi_close,
    // that'd also render the second DbiWrap instance unusable.
    //
    // For this reason, we will never call mdb_dbi_close
    // NOTE: according to LMDB authors, it is perfectly fine if mdb_dbi_close is never called on an MDB_dbi
}

NAN_METHOD(DbiWrap::ctor) {
    Nan::HandleScope scope;

    MDB_dbi dbi;
    MDB_txn *txn;
    int rc;
    int flags = 0;
    int txnFlags = 0;
    Local<String> name;
    bool nameIsNull = false;
    LmdbKeyType keyType = LmdbKeyType::DefaultKey;
    bool needsTransaction = true;
    bool isOpen = false;
    bool hasVersions = false;

    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(Local<Object>::Cast(info[0]));
    Compression* compression = nullptr;

    /*
    // TODO: Consolidate to this
    DbiWrap* dw = new DbiWrap(ew->env, 0);
    dw->ew = ew;
    int flags = info[0]->IntegerValue(Nan::GetCurrentContext()).FromJust();
    char* name = node::Buffer::Data(info[1]);
    LmdbKeyType keyType = (LmdbKeyType) info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
    Compression* compression = (Compression*) (size_t) Local<Number>::Cast(info[3])->Value();
    int rc = dw->open(flags & ~HAS_VERSIONS, name, flags & HAS_VERSIONS,
        keyType, compression);
    if (rc) {
        delete dw;
        return rc;
    }
    return info.GetReturnValue().Set(info.This());
*/

    if (info[1]->IsObject()) {
        Local<Object> options = Local<Object>::Cast(info[1]);
        nameIsNull = options->Get(Nan::GetCurrentContext(), Nan::New<String>("name").ToLocalChecked()).ToLocalChecked()->IsNull();
        name = Local<String>::Cast(options->Get(Nan::GetCurrentContext(), Nan::New<String>("name").ToLocalChecked()).ToLocalChecked());

        // Get flags from options

        // NOTE: mdb_set_relfunc is not exposed because MDB_FIXEDMAP is "highly experimental"
        // NOTE: mdb_set_relctx is not exposed because MDB_FIXEDMAP is "highly experimental"
        setFlagFromValue(&flags, MDB_REVERSEKEY, "reverseKey", false, options);
        setFlagFromValue(&flags, MDB_DUPSORT, "dupSort", false, options);
        setFlagFromValue(&flags, MDB_DUPFIXED, "dupFixed", false, options);
        setFlagFromValue(&flags, MDB_INTEGERDUP, "integerDup", false, options);
        setFlagFromValue(&flags, MDB_REVERSEDUP, "reverseDup", false, options);
        setFlagFromValue(&flags, MDB_CREATE, "create", false, options);

        // TODO: wrap mdb_set_compare
        // TODO: wrap mdb_set_dupsort

        keyType = keyTypeFromOptions(options);
        if (keyType == LmdbKeyType::InvalidKey) {
            // NOTE: Error has already been thrown inside keyTypeFromOptions
            return;
        }
        
        if (keyType == LmdbKeyType::Uint32Key) {
            flags |= MDB_INTEGERKEY;
        }
        Local<Value> compressionOption = options->Get(Nan::GetCurrentContext(), Nan::New<String>("compression").ToLocalChecked()).ToLocalChecked();
        if (compressionOption->IsObject()) {
            compression = Nan::ObjectWrap::Unwrap<Compression>(Nan::To<v8::Object>(compressionOption).ToLocalChecked());
        }

        // Set flags for txn used to open database
        Local<Value> create = options->Get(Nan::GetCurrentContext(), Nan::New<String>("create").ToLocalChecked()).ToLocalChecked();
        #if NODE_VERSION_AT_LEAST(12,0,0)
        if (create->IsBoolean() ? !create->BooleanValue(Isolate::GetCurrent()) : true) {
        #else
        if (create->IsBoolean() ? !create->BooleanValue(Nan::GetCurrentContext()).FromJust() : true) {
        #endif
            txnFlags |= MDB_RDONLY;
        }
        Local<Value> hasVersionsLocal = options->Get(Nan::GetCurrentContext(), Nan::New<String>("useVersions").ToLocalChecked()).ToLocalChecked();
        hasVersions = hasVersionsLocal->IsTrue();

        if (ew->writeTxn) {
            needsTransaction = false;
            txn = ew->writeTxn->txn;
        }
    }
    else {
        return Nan::ThrowError("Invalid parameters.");
    }
    if (info[2]->IsNumber()) {
        keyType = (LmdbKeyType) info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
    }
    if (needsTransaction) {
        // Open transaction
        rc = mdb_txn_begin(ew->env, nullptr, txnFlags, &txn);
        if (rc != 0) {
            // No need to call mdb_txn_abort, because mdb_txn_begin already cleans up after itself
            return throwLmdbError(rc);
        }
    }

    // Open database
    // NOTE: nullptr in place of the name means using the unnamed database.
    #if NODE_VERSION_AT_LEAST(12,0,0)
    rc = mdb_dbi_open(txn, nameIsNull ? nullptr : *String::Utf8Value(Isolate::GetCurrent(), name), flags, &dbi);
    #else
    rc = mdb_dbi_open(txn, nameIsNull ? nullptr : *String::Utf8Value(name), flags, &dbi);
    #endif
    if (rc != 0) {
        if (needsTransaction) {
            mdb_txn_abort(txn);
        }
        return throwLmdbError(rc);
    }
    else {
        isOpen = true;
    }
    // Create wrapper
    DbiWrap* dw = new DbiWrap(ew->env, dbi);
    if (isOpen) {
        dw->ew = ew;
    }
    if (keyType == LmdbKeyType::DefaultKey && !nameIsNull) { // use the fast compare, but can't do it if we have db table/names mixed in
        mdb_set_compare(txn, dbi, compareFast);
    }
    if (needsTransaction) {
        // Commit transaction
        rc = mdb_txn_commit(txn);
        if (rc != 0) {
            return throwLmdbError(rc);
        }
    }

    dw->keyType = keyType;
    dw->flags = flags;
    dw->isOpen = isOpen;
    dw->compression = compression;
    dw->hasVersions = hasVersions;
    dw->Wrap(info.This());
    info.This()->Set(Nan::GetCurrentContext(), Nan::New<String>("dbi").ToLocalChecked(), Nan::New<Number>(dbi));

    return info.GetReturnValue().Set(info.This());
}

int DbiWrap::open(int flags, char* name, bool hasVersions, LmdbKeyType keyType, Compression* compression) {
    MDB_txn* txn = ew->getReadTxn();
    this->hasVersions = hasVersions;
    this->compression = compression;
    this->keyType = keyType;
    flags &= ~HAS_VERSIONS;
    if (keyType == LmdbKeyType::Uint32Key)
        flags |= MDB_INTEGERKEY;
    int rc = mdb_dbi_open(txn, name, flags, &this->dbi);
    if (rc == EACCES) {
        if (!ew->writeTxn) {
            rc = mdb_txn_begin(ew->env, nullptr, 0, &txn);
            if (!rc) {
                rc = mdb_dbi_open(txn, name, flags, &this->dbi);
                if (rc)
                    mdb_txn_abort(txn);
                else
                    mdb_txn_commit(txn);
            }
        }
    }
    if (rc)
        return rc;
    this->isOpen = true;
    if (keyType == LmdbKeyType::DefaultKey && name) { // use the fast compare, but can't do it if we have db table/names mixed in
        mdb_set_compare(txn, dbi, compareFast);
    }

    return 0;
}
extern "C" EXTERN uint32_t getDbi(double dw) {
    return (uint32_t) ((DbiWrap*) (size_t) dw)->dbi;
}

NAN_METHOD(DbiWrap::close) {
    Nan::HandleScope scope;

    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info.This());
    if (dw->isOpen) {
        mdb_dbi_close(dw->env, dw->dbi);
        dw->isOpen = false;
        dw->ew = nullptr;
    }
    else {
        return Nan::ThrowError("The Dbi is not open, you can't close it.");
    }
}

NAN_METHOD(DbiWrap::drop) {
    Nan::HandleScope scope;

    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info.This());
    int del = 1;
    int rc;
    if (!dw->isOpen) {
        return Nan::ThrowError("The Dbi is not open, you can't drop it.");
    }

    // Check if the database should be deleted
    if (info.Length() == 1 && info[0]->IsObject()) {
        Local<Object> options = Local<Object>::Cast(info[0]);
        
        // Just free pages
        Local<Value> opt = options->Get(Nan::GetCurrentContext(), Nan::New<String>("justFreePages").ToLocalChecked()).ToLocalChecked();
        #if NODE_VERSION_AT_LEAST(12,0,0)
        del = opt->IsBoolean() ? !(opt->BooleanValue(Isolate::GetCurrent())) : 1;
        #else
        del = opt->IsBoolean() ? !(opt->BooleanValue(Nan::GetCurrentContext()).FromJust()) : 1;
        #endif
    }

    // Drop database
    rc = mdb_drop(dw->ew->writeTxn->txn, dw->dbi, del);
    if (rc != 0) {
        return throwLmdbError(rc);
    }

    // Only close database if del == 1
    if (del == 1) {
        dw->isOpen = false;
        dw->ew = nullptr;
    }
}

NAN_METHOD(DbiWrap::stat) {
    Nan::HandleScope scope;

    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info.This());

    if (info.Length() != 1) {
        return Nan::ThrowError("dbi.stat should be called with a single argument which is a txn.");
    }

    TxnWrap *txn = Nan::ObjectWrap::Unwrap<TxnWrap>(Local<Object>::Cast(info[0]));

    MDB_stat stat;
    mdb_stat(txn->txn, dw->dbi, &stat);

    Local<Context> context = Nan::GetCurrentContext();
    Local<Object> obj = Nan::New<Object>();
    (void)obj->Set(context, Nan::New<String>("pageSize").ToLocalChecked(), Nan::New<Number>(stat.ms_psize));
    (void)obj->Set(context, Nan::New<String>("treeDepth").ToLocalChecked(), Nan::New<Number>(stat.ms_depth));
    (void)obj->Set(context, Nan::New<String>("treeBranchPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_branch_pages));
    (void)obj->Set(context, Nan::New<String>("treeLeafPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_leaf_pages));
    (void)obj->Set(context, Nan::New<String>("entryCount").ToLocalChecked(), Nan::New<Number>(stat.ms_entries));
    (void)obj->Set(context, Nan::New<String>("overflowPages").ToLocalChecked(), Nan::New<Number>(stat.ms_overflow_pages));

    info.GetReturnValue().Set(obj);
}

#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
uint32_t DbiWrap::getByBinaryFast(Local<Object> receiver_obj, uint32_t keySize) {
	DbiWrap* dw = static_cast<DbiWrap*>(
        receiver_obj->GetAlignedPointerFromInternalField(0));
    return dw->doGetByBinary(keySize);
}
#endif
extern "C" EXTERN uint32_t dbiGetByBinary(double dwPointer, uint32_t keySize) {
    DbiWrap* dw = (DbiWrap*) (size_t) dwPointer;
    return dw->doGetByBinary(keySize);
}
extern "C" EXTERN int64_t openCursor(double dwPointer) {
    DbiWrap* dw = (DbiWrap*) (size_t) dwPointer;
    MDB_cursor *cursor;
    MDB_txn *txn = dw->ew->getReadTxn();
    int rc = mdb_cursor_open(txn, dw->dbi, &cursor);
    if (rc)
        return rc;
    CursorWrap* cw = new CursorWrap(cursor);
    cw->keyType = dw->keyType;
    cw->dw = dw;
    cw->txn = txn;
    return (int64_t) cw;
}


uint32_t DbiWrap::doGetByBinary(uint32_t keySize) {
    char* keyBuffer = ew->keyBuffer;
    MDB_txn* txn = ew->getReadTxn();
    MDB_val key, data;
    key.mv_size = keySize;
    key.mv_data = (void*) keyBuffer;

    int result = mdb_get(txn, dbi, &key, &data);
    if (result) {
        if (result == MDB_NOTFOUND)
            return 0xffffffff;
        // let the slow handler handle throwing errors
        //options.fallback = true;
        return result;
    }
    getFast = true;
    result = getVersionAndUncompress(data, this);
    if (result)
        result = valToBinaryFast(data, this);
/*    if (!result) {
        // this means an allocation or error needs to be thrown, so we fallback to the slow handler
        // or since we are using signed int32 (so we can return error codes), need special handling for above 2GB entries
        options.fallback = true;
    }*/
    getFast = false;
    /*
    alternately, if we want to send over the address, which can be used for direct access to the LMDB shared memory, but all benchmarking shows it is slower
    *((size_t*) keyBuffer) = data.mv_size;
    *((uint64_t*) (keyBuffer + 8)) = (uint64_t) data.mv_data;
    return 0;*/
    return data.mv_size;
}

void DbiWrap::getByBinary(
  const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Local<v8::Object> instance =
      v8::Local<v8::Object>::Cast(info.Holder());
    DbiWrap* dw = Nan::ObjectWrap::Unwrap<DbiWrap>(instance);
    char* keyBuffer = dw->ew->keyBuffer;
    MDB_txn* txn = dw->ew->getReadTxn();
    MDB_val key;
    MDB_val data;
    key.mv_size = info[0]->Uint32Value(Nan::GetCurrentContext()).FromJust();
    key.mv_data = (void*) keyBuffer;
    int rc = mdb_get(txn, dw->dbi, &key, &data);
    if (rc) {
        if (rc == MDB_NOTFOUND)
            return info.GetReturnValue().Set(Nan::New<Number>(0xffffffff));
        else
            return throwLmdbError(rc);
    }   
    rc = getVersionAndUncompress(data, dw);
    return info.GetReturnValue().Set(valToBinaryUnsafe(data, dw));
}

NAN_METHOD(DbiWrap::getStringByBinary) {
    v8::Local<v8::Object> instance =
      v8::Local<v8::Object>::Cast(info.Holder());
    DbiWrap* dw = Nan::ObjectWrap::Unwrap<DbiWrap>(instance);
    char* keyBuffer = dw->ew->keyBuffer;
    MDB_txn* txn = dw->ew->getReadTxn();
    MDB_val key;
    MDB_val data;
    key.mv_size = info[0]->Uint32Value(Nan::GetCurrentContext()).FromJust();
    key.mv_data = (void*) keyBuffer;
    int rc = mdb_get(txn, dw->dbi, &key, &data);
    if (rc) {
        if (rc == MDB_NOTFOUND)
            return info.GetReturnValue().Set(Nan::Undefined());
        else
            return throwLmdbError(rc);
    }
    rc = getVersionAndUncompress(data, dw);
    if (rc)
        return info.GetReturnValue().Set(valToUtf8(data));
    else
        return info.GetReturnValue().Set(Nan::New<Number>(data.mv_size));
}

extern "C" EXTERN int prefetch(double dwPointer, double keysPointer) {
	DbiWrap* dw = (DbiWrap*) (size_t) dwPointer;
    return dw->prefetch((uint32_t*)(size_t)keysPointer);
}

int DbiWrap::prefetch(uint32_t* keys) {
    MDB_txn* txn;
    mdb_txn_begin(ew->env, nullptr, MDB_RDONLY, &txn);
    MDB_val key;
    MDB_val data;
    unsigned int flags;
    mdb_dbi_flags(txn, dbi, &flags);
    bool dupSort = flags & MDB_DUPSORT;
    int effected = 0;
    MDB_cursor *cursor;
    int rc = mdb_cursor_open(txn, dbi, &cursor);
    if (rc)
        return rc;
    while((key.mv_size = *keys++) > 0) {
        if (key.mv_size == 0xffffffff) {
            // it is a pointer to a new buffer
            keys = (uint32_t*) (size_t) *((double*) keys); // read as a double pointer
            key.mv_size = *keys++;
            if (key.mv_size == 0)
                break;
        }
        key.mv_data = (void*) keys;
        keys += (key.mv_size + 12) >> 2;
        int rc = mdb_cursor_get(cursor, &key, &data, MDB_SET_KEY);
        while (!rc) {
            // access one byte from each of the pages to ensure they are in the OS cache,
            // potentially triggering the hard page fault in this thread
            int pages = (data.mv_size + 0xfff) >> 12;
            // TODO: Adjust this for the page headers, I believe that makes the first page slightly less 4KB.
            for (int i = 0; i < pages; i++) {
                effected += *(((uint8_t*)data.mv_data) + (i << 12));
            }
            if (dupSort) // in dupsort databases, access the rest of the values
                rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT_DUP);
            else
                rc = 1; // done
        }
    }
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    return effected;
}

class PrefetchWorker : public Nan::AsyncWorker {
  public:
    PrefetchWorker(DbiWrap* dw, uint32_t* keys, Nan::Callback *callback)
      : Nan::AsyncWorker(callback), dw(dw), keys(keys) {}

    void Execute() {
        dw->prefetch(keys);
    }

    void HandleOKCallback() {
        Nan::HandleScope scope;
        Local<v8::Value> argv[] = {
            Nan::Null()
        };

        callback->Call(1, argv, async_resource);
    }

  private:
    DbiWrap* dw;
    uint32_t* keys;
};

NAN_METHOD(DbiWrap::prefetch) {
    v8::Local<v8::Object> instance =
      v8::Local<v8::Object>::Cast(info.Holder());
    DbiWrap* dw = Nan::ObjectWrap::Unwrap<DbiWrap>(instance);
    size_t keysAddress = Local<Number>::Cast(info[0])->Value();
    Nan::Callback* callback = new Nan::Callback(Local<v8::Function>::Cast(info[1]));

    PrefetchWorker* worker = new PrefetchWorker(dw, (uint32_t*) keysAddress, callback);
    Nan::AsyncQueueWorker(worker);
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

