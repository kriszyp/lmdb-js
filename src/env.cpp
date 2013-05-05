
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

EnvWrap::EnvWrap() {
    needsClose = false;
}

EnvWrap::~EnvWrap() {
    // Close if not closed already
    if (needsClose) {
        mdb_env_close(env);
    }
}

// Constructor
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

// Wrapper for mdb_env_set_maxdbs
Handle<Value> EnvWrap::setMaxDbs(const Arguments& args) {
    HandleScope scope;
    int rc;
    
    EnvWrap *wrapper = ObjectWrap::Unwrap<EnvWrap>(args.This());
    int n = args[0]->ToInteger()->Value();
    rc = mdb_env_set_maxdbs(wrapper->env, n);
    
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return scope.Close(Undefined());
    }
    
    return scope.Close(Undefined());
}

// Wrapper for mdb_env_open
Handle<Value> EnvWrap::open(const Arguments& args) {
    HandleScope scope;
    int rc;
    
    // Get the wrapper
    EnvWrap *wrapper = ObjectWrap::Unwrap<EnvWrap>(args.This());
    // Get the first parameter
    String *pathWrap = *(args[0]->ToString());
    int l = pathWrap->Length();
    char *path = new char[l + 1];
    pathWrap->WriteAscii(path);
    path[l] = 0;
    
    // TODO: make 3rd and 4th parameter configurable
    rc = mdb_env_open(wrapper->env, path, 0, 0664);
    
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return scope.Close(Undefined());
    }
    
    return scope.Close(Undefined());
}

// Wrapper for mdb_env_close
Handle<Value> EnvWrap::close(const Arguments& args) {
    HandleScope scope;
    
    EnvWrap *wrapper = ObjectWrap::Unwrap<EnvWrap>(args.This());
    mdb_env_close(wrapper->env);
    wrapper->needsClose = false;
    
    return scope.Close(Undefined());
}

// Sets up exports for the EnvWrap constructor
void EnvWrap::setupExports(Handle<Object> exports) {
    // Prepare constructor template
    Local<FunctionTemplate> tpl = FunctionTemplate::New(EnvWrap::ctor);
    tpl->SetClassName(String::NewSymbol("Env"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    // Add functions to the prototype
    tpl->PrototypeTemplate()->Set(String::NewSymbol("setMaxDbs"), FunctionTemplate::New(EnvWrap::setMaxDbs)->GetFunction());
    tpl->PrototypeTemplate()->Set(String::NewSymbol("open"), FunctionTemplate::New(EnvWrap::open)->GetFunction());
    tpl->PrototypeTemplate()->Set(String::NewSymbol("close"), FunctionTemplate::New(EnvWrap::close)->GetFunction());

    Persistent<Function> constructor = Persistent<Function>::New(tpl->GetFunction());
    exports->Set(String::NewSymbol("Env"), constructor);
}



