
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

#ifndef NODE_LMDB_H
#define NODE_LMDB_H

#include <v8.h>
#include <node.h>
#include <lmdb.h>

using namespace v8;
using namespace node;

// Exports misc stuff to the module
void setupExportMisc(Handle<Object> exports);

// Wraps MDB_env
class EnvWrap : public ObjectWrap {
private:
    // Stores whether or not the MDB_env needs closing
    bool needsClose;
    // The wrapped object
    MDB_env *env;
    // Constructor for TxnWrap
    static Persistent<Function> txnCtor;
    
    friend class TxnWrap;

public:
    EnvWrap();
    ~EnvWrap();

    // Sets up exports for the Env constructor
    static void setupExports(Handle<Object> exports);
    static Handle<Value> ctor(const Arguments& args);
    static Handle<Value> setMaxDbs(const Arguments& args);
    static Handle<Value> open(const Arguments& args);
    static Handle<Value> close(const Arguments& args);
    
    static Handle<Value> beginTxn(const Arguments& args);
};

// Wraps MDB_txn
class TxnWrap : public ObjectWrap {
private:
    // Stores whether or not the MDB_txn needs closing
    bool needsClose;
    // The wrapped object
    MDB_txn *txn;
    // Reference to the MDB_env of the wrapped MDB_txn
    MDB_env *env;
    
    friend class EnvWrap;

public:
    TxnWrap(MDB_env *env, MDB_txn *txn);
    ~TxnWrap();

    static Handle<Value> ctor(const Arguments& args);
    static Handle<Value> commit(const Arguments& args);
    static Handle<Value> abort(const Arguments& args);
};

#endif // NODE_LMDB_H

