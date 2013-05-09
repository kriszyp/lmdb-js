
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

void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Local<Object> options);

DbiWrap::DbiWrap(MDB_env *env, MDB_dbi dbi) {
    this->needsClose = false;
    this->env = env;
    this->dbi = dbi;
}

DbiWrap::~DbiWrap() {
    // Close if not closed already
    if (needsClose) {
        mdb_dbi_close(env, dbi);
    }
}

Handle<Value> DbiWrap::ctor(const Arguments& args) {
    HandleScope scope;
    
    MDB_dbi dbi;
    MDB_txn *txn;
    int flags;
    int rc;
    
    EnvWrap *ew = ObjectWrap::Unwrap<EnvWrap>(args[0]->ToObject());
    Local<Object> options = args[1]->ToObject();
    Local<String> name = options->Get(String::NewSymbol("name"))->ToString();
    
    int l = name->Length();
    char *cname = new char[l + 1];
    name->WriteAscii(cname);
    cname[l] = 0;
    
    // Get flags from options
    setFlagFromValue(&flags, MDB_REVERSEKEY, "reverseKey", false, options);
    setFlagFromValue(&flags, MDB_DUPSORT, "dupSort", false, options);
    setFlagFromValue(&flags, MDB_INTEGERKEY, "integerKey", false, options);
    setFlagFromValue(&flags, MDB_DUPFIXED, "dupFixed", false, options);
    setFlagFromValue(&flags, MDB_INTEGERDUP, "integerDup", false, options);
    setFlagFromValue(&flags, MDB_REVERSEDUP, "reverseDup", false, options);
    setFlagFromValue(&flags, MDB_CREATE, "create", false, options);
    
    // TODO: wrap mdb_set_compare
    // TODO: wrap mdb_set_dupsort
    // NOTE: mdb_set_relfunc is not exposed because MDB_FIXEDMAP is "highly experimental"
    // NOTE: mdb_set_relctx is not exposed because MDB_FIXEDMAP is "highly experimental"
    
    // Open transaction
    rc = mdb_txn_begin(ew->env, NULL, 0, &txn);
    if (rc != 0) {
        // TODO: take care of error
        mdb_txn_abort(txn);
        return Undefined();
    }
    
    // Open database
    rc = mdb_dbi_open(txn, cname, flags, &dbi);
    if (rc != 0) {
        // TODO
        mdb_txn_abort(txn);
        return Undefined();
    }
    
    // Commit transaction
    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        // TODO
        return Undefined();
    }
    
    // Create wrapper    
    DbiWrap* dw = new DbiWrap(ew->env, dbi);
    dw->needsClose = true;
    dw->Wrap(args.This());

    return args.This();
}

Handle<Value> DbiWrap::close(const Arguments& args) {
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args.This());
    mdb_dbi_close(dw->env, dw->dbi);
    dw->needsClose = false;
    
    return Undefined();
}

