
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
#include <stdio.h>

void setupExportMisc(Handle<Object> exports) {
    Local<Object> versionObj = Object::New();
    
    int major, minor, patch;
    char *str = mdb_version(&major, &minor, &patch);
    versionObj->Set(String::NewSymbol("versionString"), String::New(str));
    versionObj->Set(String::NewSymbol("major"), Integer::New(major));
    versionObj->Set(String::NewSymbol("minor"), Integer::New(minor));
    versionObj->Set(String::NewSymbol("patch"), Integer::New(patch));
    
    Persistent<Object> v = Persistent<Object>::New(versionObj);
    exports->Set(String::NewSymbol("version"), v);
}

void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Local<Object> options) {
    Handle<Value> opt = options->Get(String::NewSymbol(name));
    if (opt->IsBoolean() ? opt->BooleanValue() : defaultValue) {
        *flags |= flag;
    }
}

void consoleLog(const char *msg) {
    Handle<String> str = String::New("console.log('");
    str = String::Concat(str, String::New(msg));
    str = String::Concat(str, String::New("');"));
    
    Local<Script> script = Script::New(str, String::New("node-lmdb-consolelog.js"));
    script->Run();
}

void consoleLogN(int n) {
    char c[20];
    memset(c, 0, 20 * sizeof(char));
    sprintf(c, "%d", n);
    consoleLog(c);
}

void v8ToLmdbVal(Handle<Value> handle, MDB_val *val) {
    // TODO: support other data types, not just string
    // TODO: get rid of this memory leak
    v8::String::Utf8Value *str = new v8::String::Utf8Value(handle->ToString());
    
    val->mv_size = str->length() * sizeof(char);
    val->mv_data = **str;
}

Handle<Value> lmdbValToV8(MDB_val *val) {
    // TODO: support other data types, not just string
    Local<String> var = String::New((char*)val->mv_data);
    return var;
}

