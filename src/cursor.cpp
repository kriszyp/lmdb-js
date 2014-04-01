
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

Handle<Value> CursorWrap::ctor(const Arguments &args) {
    // Get arguments
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args[0]->ToObject());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[1]->ToObject());

    // Open the cursor
    MDB_cursor *cursor;
    int rc = mdb_cursor_open(tw->txn, dw->dbi, &cursor);
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }

    // Create wrapper
    CursorWrap* cw = new CursorWrap(cursor);
    cw->dw = dw;
    cw->dw->Ref();
    cw->tw = tw;
    cw->tw->Ref();
    cw->keyIsUint32 = dw->keyIsUint32;
    cw->Wrap(args.This());

    return args.This();
}

Handle<Value> CursorWrap::close(const Arguments &args) {
    CursorWrap *cw = ObjectWrap::Unwrap<CursorWrap>(args.This());
    mdb_cursor_close(cw->cursor);
    cw->dw->Unref();
    cw->tw->Unref();
    cw->cursor = nullptr;
    return Undefined();
}

Handle<Value> CursorWrap::del(const Arguments &args) {
    CursorWrap *cw = ObjectWrap::Unwrap<CursorWrap>(args.This());
    // TODO: wrap MDB_NODUPDATA flag

    int rc = mdb_cursor_del(cw->cursor, 0);
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }

    return Undefined();
}

Handle<Value> CursorWrap::getCommon(
    const Arguments& args,
    MDB_cursor_op op,
    void (*setKey)(CursorWrap* cw, const Arguments& args, MDB_val&),
    void (*setData)(CursorWrap* cw, const Arguments& args, MDB_val&),
    void (*freeData)(CursorWrap* cw, const Arguments& args, MDB_val&),
    Handle<Value> (*convertFunc)(MDB_val &data)
) {
    int al = args.Length();
    CursorWrap *cw = ObjectWrap::Unwrap<CursorWrap>(args.This());

    if (setKey) {
        setKey(cw, args, cw->key);
    }
    if (setData) {
        setData(cw, args, cw->data);
    }

    // Temporary thing, so that we can free up the data if we want to
    MDB_val tempdata;
    tempdata.mv_size = cw->data.mv_size;
    tempdata.mv_data = cw->data.mv_data;

    int rc = mdb_cursor_get(cw->cursor, &(cw->key), &(cw->data), op);

    if (rc == MDB_NOTFOUND) {
        return Null();
    }
    else if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }

    Handle<Value> keyHandle = Undefined();
    if (cw->key.mv_size) {
        keyHandle = keyToHandle(cw->key, cw->keyIsUint32);
    }

    if (convertFunc && al > 0 && args[al - 1]->IsFunction()) {
        // In this case, we expect the key/data pair to be correctly filled
        const unsigned argc = 2;
        Handle<Value> argv[argc] = { keyHandle, convertFunc(cw->data) };
        Handle<Function> callback = Handle<Function>::Cast(args[args.Length() - 1]);
        callback->Call(Context::GetCurrent()->Global(), argc, argv);
    }

    if (freeData) {
        freeData(cw, args, tempdata);
    }

    if (cw->key.mv_size) {
        return keyHandle;
    }

    return Boolean::New(true);
}

Handle<Value> CursorWrap::getCommon(const Arguments& args, MDB_cursor_op op) {
    return getCommon(args, op, nullptr, nullptr, nullptr, nullptr);
}

Handle<Value> CursorWrap::getCurrentString(const Arguments& args) {
    return getCommon(args, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToString);
}

Handle<Value> CursorWrap::getCurrentBinary(const Arguments& args) {
    return getCommon(args, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToBinary);
}

Handle<Value> CursorWrap::getCurrentNumber(const Arguments& args) {
    return getCommon(args, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToNumber);
}

Handle<Value> CursorWrap::getCurrentBoolean(const Arguments& args) {
    return getCommon(args, MDB_GET_CURRENT, nullptr, nullptr, nullptr, valToBoolean);
}

#define MAKE_GET_FUNC(name, op) Handle<Value> CursorWrap::name(const Arguments& args) { return getCommon(args, op); }

MAKE_GET_FUNC(goToFirst, MDB_FIRST);

MAKE_GET_FUNC(goToLast, MDB_LAST);

MAKE_GET_FUNC(goToNext, MDB_NEXT);

MAKE_GET_FUNC(goToPrev, MDB_PREV);

MAKE_GET_FUNC(goToFirstDup, MDB_FIRST_DUP);

MAKE_GET_FUNC(goToLastDup, MDB_LAST_DUP);

MAKE_GET_FUNC(goToNextDup, MDB_NEXT_DUP);

MAKE_GET_FUNC(goToPrevDup, MDB_PREV_DUP);

Handle<Value> CursorWrap::goToKey(const Arguments &args) {
    return getCommon(args, MDB_SET, [](CursorWrap* cw, const Arguments& args, MDB_val &key) -> void {
        argToKey(args[0], key, cw->keyIsUint32);
    }, nullptr, nullptr, nullptr);
}

Handle<Value> CursorWrap::goToRange(const Arguments &args) {
    return getCommon(args, MDB_SET_RANGE, [](CursorWrap* cw, const Arguments& args, MDB_val &key) -> void {
        argToKey(args[0], key, cw->keyIsUint32);
    }, nullptr, nullptr, nullptr);
}

static void fillDataFromArg1(CursorWrap* cw, const Arguments& args, MDB_val &data) {
    if (args[1]->IsString()) {
        CustomExternalStringResource::writeTo(args[2]->ToString(), &data);
    }
    else if (node::Buffer::HasInstance(args[1])) {
        data.mv_size = node::Buffer::Length(args[2]);
        data.mv_data = node::Buffer::Data(args[2]);
    }
    else if (args[1]->IsNumber()) {
        data.mv_size = sizeof(double);
        data.mv_data = new double;
        *((double*)data.mv_data) = args[1]->ToNumber()->Value();
    }
    else if (args[1]->IsBoolean()) {
        data.mv_size = sizeof(double);
        data.mv_data = new bool;
        *((bool*)data.mv_data) = args[1]->ToBoolean()->Value();
    }
    else {
        ThrowException(Exception::Error(String::New("Invalid data type.")));
    }
}

static void freeDataFromArg1(CursorWrap* cw, const Arguments& args, MDB_val &data) {
    if (args[1]->IsString()) {
        delete (uint16_t*)data.mv_data;
    }
    else if (node::Buffer::HasInstance(args[1])) {
        // I think the data is owned by the node::Buffer so we don't need to free it - need to clarify
    }
    else if (args[1]->IsNumber()) {
        delete (double*)data.mv_data;
    }
    else if (args[1]->IsBoolean()) {
        delete (bool*)data.mv_data;
    }
    else {
        ThrowException(Exception::Error(String::New("Invalid data type.")));
    }
}

Handle<Value> CursorWrap::goToDup(const Arguments &args) {
    return getCommon(args, MDB_GET_BOTH, [](CursorWrap* cw, const Arguments& args, MDB_val &key) -> void {
        argToKey(args[0], key, cw->keyIsUint32);
    }, fillDataFromArg1, freeDataFromArg1, nullptr);
}

Handle<Value> CursorWrap::goToDupRange(const Arguments &args) {
    return getCommon(args, MDB_GET_BOTH_RANGE, [](CursorWrap* cw, const Arguments& args, MDB_val &key) -> void {
        argToKey(args[0], key, cw->keyIsUint32);
    }, fillDataFromArg1, freeDataFromArg1, nullptr);
}

void CursorWrap::setupExports(Handle<Object> exports) {
    // CursorWrap: Prepare constructor template
    Local<FunctionTemplate> cursorTpl = FunctionTemplate::New(CursorWrap::ctor);
    cursorTpl->SetClassName(String::NewSymbol("Cursor"));
    cursorTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // CursorWrap: Add functions to the prototype
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("close"), FunctionTemplate::New(CursorWrap::close)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("getCurrentString"), FunctionTemplate::New(CursorWrap::getCurrentString)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("getCurrentBinary"), FunctionTemplate::New(CursorWrap::getCurrentBinary)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("getCurrentNumber"), FunctionTemplate::New(CursorWrap::getCurrentNumber)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("getCurrentBoolean"), FunctionTemplate::New(CursorWrap::getCurrentBoolean)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToFirst"), FunctionTemplate::New(CursorWrap::goToFirst)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToLast"), FunctionTemplate::New(CursorWrap::goToLast)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToNext"), FunctionTemplate::New(CursorWrap::goToNext)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToPrev"), FunctionTemplate::New(CursorWrap::goToPrev)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToKey"), FunctionTemplate::New(CursorWrap::goToKey)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToRange"), FunctionTemplate::New(CursorWrap::goToRange)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToFirstDup"), FunctionTemplate::New(CursorWrap::goToFirstDup)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToLastDup"), FunctionTemplate::New(CursorWrap::goToLastDup)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToNextDup"), FunctionTemplate::New(CursorWrap::goToNextDup)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToPrevDup"), FunctionTemplate::New(CursorWrap::goToPrevDup)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToDup"), FunctionTemplate::New(CursorWrap::goToDup)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("goToDupRange"), FunctionTemplate::New(CursorWrap::goToDupRange)->GetFunction());
    cursorTpl->PrototypeTemplate()->Set(String::NewSymbol("del"), FunctionTemplate::New(CursorWrap::del)->GetFunction());

    // CursorWrap: Get constructor
    Persistent<Function> cursorCtor = Persistent<Function>::New(cursorTpl->GetFunction());

    // Set exports
    exports->Set(String::NewSymbol("Cursor"), cursorCtor);
}
