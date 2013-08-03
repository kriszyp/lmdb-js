
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
    cw->Wrap(args.This());

    return args.This();
}

Handle<Value> CursorWrap::close(const Arguments &args) {
    CursorWrap *cw = ObjectWrap::Unwrap<CursorWrap>(args.This());
    mdb_cursor_close(cw->cursor);
    cw->cursor = NULL;
    return Undefined();
}

Handle<Value> CursorWrap::getCommon(const Arguments& args, MDB_cursor_op op, void (*setKey)(const Arguments& args, MDB_val&), Handle<Value> (*convertFunc)(MDB_val &data)) {
    CursorWrap *cw = ObjectWrap::Unwrap<CursorWrap>(args.This());
    
    MDB_val key, data;
    
    if (setKey) {
        setKey(args, key);
    }
    
    int rc = mdb_cursor_get(cw->cursor, &key, &data, op);
    int al = args.Length();
    
    if (rc == MDB_NOTFOUND) {
        return Null();
    }
    else if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }
    
    Handle<Value> keyHandle = keyToHandle(key);
    
    if (convertFunc && al > 0 && args[al - 1]->IsFunction()) {    
        const unsigned argc = 2;
        Handle<Value> argv[argc] = { keyHandle, convertFunc(data) };
        Handle<Function> callback = Handle<Function>::Cast(args[args.Length() - 1]);
        callback->Call(Context::GetCurrent()->Global(), argc, argv);
    }
    
    return keyHandle;
}

Handle<Value> CursorWrap::getCommon(const Arguments& args, MDB_cursor_op op) {
    return getCommon(args, op, NULL, NULL);
}

Handle<Value> CursorWrap::getCurrentString(const Arguments& args) {
    return getCommon(args, MDB_GET_CURRENT, NULL, valToString);
}

Handle<Value> CursorWrap::getCurrentBinary(const Arguments& args) {
    return getCommon(args, MDB_GET_CURRENT, NULL, valToBinary);
}

Handle<Value> CursorWrap::getCurrentNumber(const Arguments& args) {
    return getCommon(args, MDB_GET_CURRENT, NULL, valToNumber);
}

Handle<Value> CursorWrap::getCurrentBoolean(const Arguments& args) {
    return getCommon(args, MDB_GET_CURRENT, NULL, valToBoolean);
}

#define MAKE_GET_FUNC(name, op) Handle<Value> CursorWrap::name(const Arguments& args) { return getCommon(args, op); }

MAKE_GET_FUNC(goToFirst, MDB_FIRST);

MAKE_GET_FUNC(goToLast, MDB_LAST);

MAKE_GET_FUNC(goToNext, MDB_NEXT);

MAKE_GET_FUNC(goToPrev, MDB_PREV);

Handle<Value> CursorWrap::goToKey(const Arguments &args) {
    return getCommon(args, MDB_SET, [](const Arguments& args, MDB_val &key) -> void {
        argToKey(args[0], key);
    }, NULL);
}

Handle<Value> CursorWrap::goToRange(const Arguments &args) {
    return getCommon(args, MDB_SET_RANGE, [](const Arguments& args, MDB_val &key) -> void {
        argToKey(args[0], key);
    }, NULL);
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
    
    // CursorWrap: Get constructor
    Persistent<Function> cursorCtor = Persistent<Function>::New(cursorTpl->GetFunction());
    
    // Set exports
    exports->Set(String::NewSymbol("Cursor"), cursorCtor);
}



