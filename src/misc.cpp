
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

argtokey_callback_t argToKey(const Handle<Value> &val, MDB_val &key, bool keyIsUint32) {
    // Check key type
    if (keyIsUint32 && !val->IsUint32()) {
        ThrowException(Exception::Error(String::New("Invalid key. keyIsUint32 specified on the database, but the given key was not an unsigned 32-bit integer")));
        return nullptr;
    }
    if (!keyIsUint32 && !val->IsString()) {
        ThrowException(Exception::Error(String::New("Invalid key. String key expected, because keyIsUint32 isn't specified on the database.")));
        return nullptr;
    }

    // Handle uint32_t key
    if (keyIsUint32) {
        uint32_t *v = new uint32_t;
        *v = val->Uint32Value();

        key.mv_size = sizeof(uint32_t);
        key.mv_data = v;

        return ([](MDB_val &key) -> void {
            delete (uint32_t*)key.mv_data;
        });
    }

    // Handle string key
    CustomExternalStringResource::writeTo(val->ToString(), &key);
    return ([](MDB_val &key) -> void {
        delete (uint16_t*)key.mv_data;
    });

    return nullptr;
}

Handle<Value> keyToHandle(MDB_val &key, bool keyIsUint32) {
    if (keyIsUint32) {
        return Integer::NewFromUnsigned(*((uint32_t*)key.mv_data));
    }
    else {
        return valToString(key);
    }
}

Handle<Value> valToString(MDB_val &data) {
    return String::NewExternal(new CustomExternalStringResource(&data));
}

Handle<Value> valToBinary(MDB_val &data) {
    return Buffer::New(
//        NOTE: newer node API will need this parameter
//        v8::Isolate::GetCurrent(),
        (char*)data.mv_data,
        data.mv_size,
        [](char*, void*) -> void {
            /* Don't need to do anything here, because the data belongs to LMDB anyway */
        },
        nullptr
    )->handle_;
}

Handle<Value> valToNumber(MDB_val &data) {
    return Number::New(*((double*)data.mv_data));
}

Handle<Value> valToBoolean(MDB_val &data) {
    return Boolean::New(*((bool*)data.mv_data));
}

void consoleLog(const char *msg) {
    Handle<String> str = String::New("console.log('");
    str = String::Concat(str, String::New(msg));
    str = String::Concat(str, String::New("');"));

    Local<Script> script = Script::New(str, String::New("node-lmdb-consolelog.js"));
    script->Run();
}

void consoleLog(Handle<Value> val) {
    Handle<String> str = String::New("console.log('");
    str = String::Concat(str, val->ToString());
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

void CustomExternalStringResource::writeTo(Handle<String> str, MDB_val *val) {
    unsigned int l = str->Length() + 1;
    uint16_t *d = new uint16_t[l];
    str->Write(d);
    d[l - 1] = 0;

    val->mv_data = d;
    val->mv_size = l * sizeof(uint16_t);
}

CustomExternalStringResource::CustomExternalStringResource(MDB_val *val) {
    // The UTF-16 data
    this->d = (uint16_t*)(val->mv_data);
    // Number of UTF-16 characters in the string
    this->l = (val->mv_size / sizeof(uint16_t) - 1);
}

CustomExternalStringResource::~CustomExternalStringResource() { }

void CustomExternalStringResource::Dispose() {
    // No need to do anything, the data is owned by LMDB, not us
}

const uint16_t *CustomExternalStringResource::data() const {
    return this->d;
}

size_t CustomExternalStringResource::length() const {
    return this->l;
}
