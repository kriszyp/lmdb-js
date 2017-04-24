
// This file is part of node-lmdb, the Node.js binding for lmdb
// Copyright (c) 2013 Timur Kristóf
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

#include "node-lmdb.h"
#include <string.h>

using namespace v8;
using namespace node;

CursorWrap::CursorWrap(MDB_cursor *cursor) {
    this->cursor = cursor;
}

CursorWrap::~CursorWrap() {
    if (this->cursor) {
        this->dw->Unref();
        this->tw->Unref();
        mdb_cursor_close(this->cursor);
    }
}

NAN_METHOD(CursorWrap::ctor) {
    Nan::HandleScope scope;

    if (info.Length() < 2) {
      Nan::ThrowTypeError("Wrong number of arguments");
      return;
    }

    // Extra pessimism...
    Nan::MaybeLocal<v8::Object> arg0 = Nan::To<v8::Object>(info[0]);
    Nan::MaybeLocal<v8::Object> arg1 = Nan::To<v8::Object>(info[1]);
    if (arg0.IsEmpty() || arg1.IsEmpty()) {
      Nan::ThrowTypeError("Invalid argument");
      return;
    }
    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(arg0.ToLocalChecked());
    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(arg1.ToLocalChecked());

    // Support 4 cursor modes
    //   binaryKey parameter missing - legacy behaviour. Might get fixed later...
    //   binaryKey === true - keys are buffers - always
    //   binaryKey === false - keys MUST be utf16le zero terminated on disk. If not, throws.
    node_lmdb::KeyType kt = dw->keyIsUint32 ? node_lmdb::uint32Key : node_lmdb::legacyStringKey; 
    if ((info.Length() > 2) && (kt != node_lmdb::uint32Key)) {
      bool arg2 = Nan::To<bool>(info[2]).FromMaybe(false);
      kt = arg2 ? node_lmdb::binaryKey : node_lmdb::stringKey;
    }
    
    // Open the cursor
    MDB_cursor *cursor;
    int rc = mdb_cursor_open(tw->txn, dw->dbi, &cursor);
    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    // Create wrapper
    CursorWrap* cw = new CursorWrap(cursor);
    cw->dw = dw;
    cw->dw->Ref();
    cw->tw = tw;
    cw->tw->Ref();
    cw->kt = kt;
    cw->Wrap(info.This());

    return info.GetReturnValue().Set(info.This());
}

NAN_METHOD(CursorWrap::close) {
    Nan::HandleScope scope;

    CursorWrap *cw = Nan::ObjectWrap::Unwrap<CursorWrap>(info.This());
    mdb_cursor_close(cw->cursor);
    cw->dw->Unref();
    cw->tw->Unref();
    cw->cursor = nullptr;
    return;
}

NAN_METHOD(CursorWrap::del) {
    Nan::HandleScope scope;

    CursorWrap *cw = Nan::ObjectWrap::Unwrap<CursorWrap>(info.This());
    // TODO: wrap MDB_NODUPDATA flag

    int rc = mdb_cursor_del(cw->cursor, 0);
    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    return;
}

Nan::NAN_METHOD_RETURN_TYPE CursorWrap::getCommon(
    Nan::NAN_METHOD_ARGS_TYPE info,
    MDB_cursor_op op,
    argtokey_callback_t (*setKey)(CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val&),
    void (*setData)(CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val&),
    void (*freeData)(CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val&),
    Local<Value> (*convertFunc)(MDB_val &data)
) {
    Nan::HandleScope scope;

    int al = info.Length();
    CursorWrap *cw = Nan::ObjectWrap::Unwrap<CursorWrap>(info.This());
    
    argtokey_callback_t freeKey = nullptr;

    // When a new key is manually set
    if (setKey) {
        // Set new key and assign the deleter function
        freeKey = setKey(cw, info, cw->key);
    }
    
    // When data is manually set
    if (setData) {
        setData(cw, info, cw->data);
    }

    // Temporary thing, so that we can free up the data if we want to
    MDB_val tempdata;
    tempdata.mv_size = cw->data.mv_size;
    tempdata.mv_data = cw->data.mv_data;
    
    // Temporary bookkeeping for the current key
    MDB_val tempKey;
    tempKey.mv_size = cw->key.mv_size;
    tempKey.mv_data = cw->key.mv_data;

    // Call LMDB
    int rc = mdb_cursor_get(cw->cursor, &(cw->key), &(cw->data), op);
    
    // cw->key points inside the database now,
    // so we should free the old key now.
    if (freeKey) {
        freeKey(tempKey);
        freeKey = nullptr;
    }

    if (rc == MDB_NOTFOUND) {
        return info.GetReturnValue().Set(Nan::Null());
    }
    else if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    Local<Value> keyHandle = Nan::Undefined();
    if (cw->key.mv_size) {
        keyHandle = keyToHandle(cw->key, cw->kt);
    }

    Local<Value> dataHandle = Nan::Undefined();
    if (convertFunc) {
        dataHandle = convertFunc(cw->data);
        if (al > 0 && info[al - 1]->IsFunction()) {
            // In this case, we expect the key/data pair to be correctly filled
            const unsigned argc = 2;
            Local<Value> argv[argc] = { keyHandle, dataHandle };
            Nan::Callback *callback = new Nan::Callback(Local<Function>::Cast(info[info.Length() - 1]));
            callback->Call(argc, argv);
            delete callback;
        }
    }

    if (freeData) {
        freeData(cw, info, tempdata);
    }

    if (convertFunc) {
        return info.GetReturnValue().Set(dataHandle);
    }
    else if (cw->key.mv_size) {
        return info.GetReturnValue().Set(keyHandle);
    }

    return info.GetReturnValue().Set(Nan::True());
}

Nan::NAN_METHOD_RETURN_TYPE CursorWrap::getCommon(Nan::NAN_METHOD_ARGS_TYPE info, MDB_cursor_op op) {
    return getCommon(info, op, nullptr, nullptr, nullptr, nullptr);
}

NAN_METHOD(CursorWrap::getCurrentString) {
    return getCommon(info, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToString);
}

NAN_METHOD(CursorWrap::getCurrentStringUnsafe) {
    return getCommon(info, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToStringUnsafe);
}

NAN_METHOD(CursorWrap::getCurrentBinary) {
    return getCommon(info, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToBinary);
}

NAN_METHOD(CursorWrap::getCurrentBinaryUnsafe) {
    return getCommon(info, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToBinaryUnsafe);
}

NAN_METHOD(CursorWrap::getCurrentNumber) {
    return getCommon(info, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToNumber);
}

NAN_METHOD(CursorWrap::getCurrentBoolean) {
    return getCommon(info, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToBoolean);
}

#define MAKE_GET_FUNC(name, op) NAN_METHOD(CursorWrap::name) { return getCommon(info, op); }

MAKE_GET_FUNC(goToFirst, MDB_FIRST);

MAKE_GET_FUNC(goToLast, MDB_LAST);

MAKE_GET_FUNC(goToNext, MDB_NEXT);

MAKE_GET_FUNC(goToPrev, MDB_PREV);

MAKE_GET_FUNC(goToFirstDup, MDB_FIRST_DUP);

MAKE_GET_FUNC(goToLastDup, MDB_LAST_DUP);

MAKE_GET_FUNC(goToNextDup, MDB_NEXT_DUP);

MAKE_GET_FUNC(goToPrevDup, MDB_PREV_DUP);

NAN_METHOD(CursorWrap::goToKey) {
    return getCommon(info, MDB_SET, [](CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &key) -> argtokey_callback_t {
        return argToKey(info[0], key, cw->kt);
    }, nullptr, nullptr, nullptr);
}

NAN_METHOD(CursorWrap::goToRange) {
    return getCommon(info, MDB_SET_RANGE, [](CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &key) -> argtokey_callback_t {
        return argToKey(info[0], key, cw->kt);
    }, nullptr, nullptr, nullptr);
}

static void fillDataFromArg1(CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &data) {
    if (info[1]->IsString()) {
        CustomExternalStringResource::writeTo(info[1]->ToString(), &data);
    }
    else if (node::Buffer::HasInstance(info[1])) {
        data.mv_size = node::Buffer::Length(info[1]);
        data.mv_data = node::Buffer::Data(info[1]);
    }
    else if (info[1]->IsNumber()) {
        data.mv_size = sizeof(double);
        data.mv_data = new double;
        *((double*)data.mv_data) = info[1]->ToNumber(Nan::GetCurrentContext()).ToLocalChecked()->Value();
    }
    else if (info[1]->IsBoolean()) {
        data.mv_size = sizeof(double);
        data.mv_data = new bool;
        *((bool*)data.mv_data) = info[1]->ToBoolean()->Value();
    }
    else {
        Nan::ThrowError("Invalid data type.");
    }
}

static void freeDataFromArg1(CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &data) {
    if (info[1]->IsString()) {
        delete[] (uint16_t*)data.mv_data;
    }
    else if (node::Buffer::HasInstance(info[1])) {
        // I think the data is owned by the node::Buffer so we don't need to free it - need to clarify
    }
    else if (info[1]->IsNumber()) {
        delete (double*)data.mv_data;
    }
    else if (info[1]->IsBoolean()) {
        delete (bool*)data.mv_data;
    }
    else {
        Nan::ThrowError("Invalid data type.");
    }
}

NAN_METHOD(CursorWrap::goToDup) {
    return getCommon(info, MDB_GET_BOTH, [](CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &key) -> argtokey_callback_t {
        return argToKey(info[0], key, cw->kt);
    }, fillDataFromArg1, freeDataFromArg1, nullptr);
}

NAN_METHOD(CursorWrap::goToDupRange) {
    return getCommon(info, MDB_GET_BOTH_RANGE, [](CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &key) -> argtokey_callback_t {
        return argToKey(info[0], key, cw->kt);
    }, fillDataFromArg1, freeDataFromArg1, nullptr);
}

void CursorWrap::setupExports(Handle<Object> exports) {
    // CursorWrap: Prepare constructor template
    Local<FunctionTemplate> cursorTpl = Nan::New<FunctionTemplate>(CursorWrap::ctor);
    cursorTpl->SetClassName(Nan::New<String>("Cursor").ToLocalChecked());
    cursorTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // CursorWrap: Add functions to the prototype
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("close").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::close));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("getCurrentString").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::getCurrentString));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("getCurrentStringUnsafe").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::getCurrentStringUnsafe));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("getCurrentBinary").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::getCurrentBinary));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("getCurrentBinaryUnsafe").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::getCurrentBinaryUnsafe));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("getCurrentNumber").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::getCurrentNumber));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("getCurrentBoolean").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::getCurrentBoolean));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToFirst").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToFirst));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToLast").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToLast));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToNext").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToNext));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToPrev").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToPrev));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToKey").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToKey));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToRange").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToRange));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToFirstDup").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToFirstDup));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToLastDup").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToLastDup));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToNextDup").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToNextDup));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToPrevDup").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToPrevDup));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToDup").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToDup));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("goToDupRange").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::goToDupRange));
    cursorTpl->PrototypeTemplate()->Set(Nan::New<String>("del").ToLocalChecked(), Nan::New<FunctionTemplate>(CursorWrap::del));

    // Set exports
    exports->Set(Nan::New<String>("Cursor").ToLocalChecked(), cursorTpl->GetFunction());
}
