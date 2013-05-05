
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

using namespace v8;
using namespace node;

TxnWrap::TxnWrap(MDB_env *env, MDB_txn *txn) {
    needsClose = false;
    this->env = env;
    this->txn = txn;
}

TxnWrap::~TxnWrap() {
    // Close if not closed already
    if (needsClose) {
        mdb_txn_abort(txn);
    }
}

Handle<Value> TxnWrap::ctor(const Arguments& args) {
    HandleScope scope;

    EnvWrap *ew = ObjectWrap::Unwrap<EnvWrap>(args[0]->ToObject());
    MDB_txn *txn;
    int rc = mdb_txn_begin(ew->env, NULL, 0, &txn);    
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }
    
    TxnWrap* tw = new TxnWrap(ew->env, txn);
    tw->needsClose = true;
    tw->Wrap(args.This());

    return args.This();
}

Handle<Value> TxnWrap::commit(const Arguments& args) {
    HandleScope scope;
    
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    mdb_txn_commit(tw->txn);
    tw->needsClose = false;
    
    return Undefined();
}

Handle<Value> TxnWrap::abort(const Arguments& args) {
    HandleScope scope;
    
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    mdb_txn_abort(tw->txn);
    tw->needsClose = false;
    
    return Undefined();
}


