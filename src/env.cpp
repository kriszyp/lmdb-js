
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

Persistent<Function> EnvWrap::txnCtor;

EnvWrap::EnvWrap() {
    needsClose = false;
}

EnvWrap::~EnvWrap() {
    // Close if not closed already
    if (needsClose) {
        mdb_env_close(env);
    }
}

Handle<Value> EnvWrap::ctor(const Arguments& args) {
    HandleScope scope;
    int rc;

    EnvWrap* wrapper = new EnvWrap();
    rc = mdb_env_create(&(wrapper->env));
    
    if (rc != 0) {
        mdb_env_close(wrapper->env);
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return scope.Close(Undefined());
    }
    
    wrapper->needsClose = true;
    wrapper->Wrap(args.This());

    return args.This();
}

//Handle<Value> EnvWrap::setMaxDbs(const Arguments& args) {
//    HandleScope scope;
//    int rc;
//    
//    EnvWrap *wrapper = ObjectWrap::Unwrap<EnvWrap>(args.This());
//    int n = args[0]->ToInteger()->Value();
//    rc = mdb_env_set_maxdbs(wrapper->env, n);
//    
//    if (rc != 0) {
//        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
//        return scope.Close(Undefined());
//    }
//    
//    return scope.Close(Undefined());
//}

Handle<Value> EnvWrap::open(const Arguments& args) {
    HandleScope scope;
    int rc;
    
    // Get the wrapper
    EnvWrap *ew = ObjectWrap::Unwrap<EnvWrap>(args.This());
    Local<Object> options = args[0]->ToObject();
    Local<String> path = options->Get(String::NewSymbol("path"))->ToString();
    
    Handle<Value> maxDbs = options->Get(String::NewSymbol("maxDbs"));
    if (maxDbs->IsInt32()) {
        int n = maxDbs->ToInt32()->Value();
        rc = mdb_env_set_maxdbs(ew->env, n);
    }
    
    int l = path->Length();
    char *cpath = new char[l + 1];
    path->WriteAscii(cpath);
    cpath[l] = 0;
    
    // TODO: make 3rd and 4th parameter configurable
    rc = mdb_env_open(ew->env, cpath, 0, 0664);
    
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return scope.Close(Undefined());
    }
    
    return scope.Close(Undefined());
}

Handle<Value> EnvWrap::close(const Arguments& args) {
    HandleScope scope;
    
    EnvWrap *wrapper = ObjectWrap::Unwrap<EnvWrap>(args.This());
    mdb_env_close(wrapper->env);
    wrapper->needsClose = false;
    
    return scope.Close(Undefined());
}

Handle<Value> EnvWrap::beginTxn(const Arguments& args) {
    HandleScope scope;
    
    const unsigned argc = 1;
    Handle<Value> argv[argc] = { args.This() };
    Local<Object> instance = txnCtor->NewInstance(argc, argv);
    
    return scope.Close(instance);
}

void EnvWrap::setupExports(Handle<Object> exports) {
    // EnvWrap: Prepare constructor template
    Local<FunctionTemplate> envTpl = FunctionTemplate::New(EnvWrap::ctor);
    envTpl->SetClassName(String::NewSymbol("Env"));
    envTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // EnvWrap: Add functions to the prototype
    envTpl->PrototypeTemplate()->Set(String::NewSymbol("open"), FunctionTemplate::New(EnvWrap::open)->GetFunction());
    envTpl->PrototypeTemplate()->Set(String::NewSymbol("close"), FunctionTemplate::New(EnvWrap::close)->GetFunction());
    envTpl->PrototypeTemplate()->Set(String::NewSymbol("beginTxn"), FunctionTemplate::New(EnvWrap::beginTxn)->GetFunction());
    // EnvWrap: Get constructor
    Persistent<Function> envCtor = Persistent<Function>::New(envTpl->GetFunction());
    
    // TxnWrap: Prepare constructor template
    Local<FunctionTemplate> txnTpl = FunctionTemplate::New(TxnWrap::ctor);
    txnTpl->SetClassName(String::NewSymbol("Txn"));
    txnTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // TxnWrap: Add functions to the prototype
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("commit"), FunctionTemplate::New(TxnWrap::commit)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("abort"), FunctionTemplate::New(TxnWrap::abort)->GetFunction());
    // TxnWrap: Get constructor
    EnvWrap::txnCtor = Persistent<Function>::New(txnTpl->GetFunction());
    
    // Set exports
    exports->Set(String::NewSymbol("Env"), envCtor);
}



