
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

