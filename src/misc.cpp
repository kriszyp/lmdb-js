
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

static void DontFree(char* data, void* hint) {}

void setupExportMisc(Handle<Object> exports) {
    Local<Object> versionObj = Nan::New<Object>();

    int major, minor, patch;
    char *str = mdb_version(&major, &minor, &patch);
    versionObj->Set(Nan::New<String>("versionString").ToLocalChecked(), Nan::New<String>(str).ToLocalChecked());
    versionObj->Set(Nan::New<String>("major").ToLocalChecked(), Nan::New<Integer>(major));
    versionObj->Set(Nan::New<String>("minor").ToLocalChecked(), Nan::New<Integer>(minor));
    versionObj->Set(Nan::New<String>("patch").ToLocalChecked(), Nan::New<Integer>(patch));

    exports->Set(Nan::New<String>("version").ToLocalChecked(), versionObj);
}

void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Local<Object> options) {
    Local<Value> opt = options->Get(Nan::New<String>(name).ToLocalChecked());
    if (opt->IsBoolean() ? opt->BooleanValue() : defaultValue) {
        *flags |= flag;
    }
}

argtokey_callback_t argToKey(const Local<Value> &val, MDB_val &key, node_lmdb::KeyType kt) {
    // Check key type
    bool uintKey = (kt == node_lmdb::uint32Key);
    if (uintKey && !val->IsUint32()) {
        Nan::ThrowError("Invalid key. keyIsUint32 specified on the database, but the given key was not an unsigned 32-bit integer");
        return nullptr;
    }

    // Handle buffer
    if (node::Buffer::HasInstance(val)) {
        key.mv_size = node::Buffer::Length(val);
        key.mv_data = node::Buffer::Data(val);

        return ([](MDB_val &key) -> void {
           // We shouldn't need free here - need to clarify
        });

    }

    if (!uintKey && !val->IsString()) {
        Nan::ThrowError("Invalid key. String key expected, because keyIsUint32 isn't specified on the database.");
        return nullptr;
    }

    // Handle uint32_t key
    if (uintKey) {
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
        delete[] (uint16_t*)key.mv_data;
    });

    return nullptr;
}


argtokey_callback_t argToKey(const Local<Value> &val, MDB_val &key, bool keyIsUint32) {
    return argToKey(val,key, keyIsUint32 ? node_lmdb::uint32Key : node_lmdb::stringKey);
}

Local<Value> valToStringChecked(MDB_val &data) {
    char *p = static_cast<char*>(data.mv_data);
    if (data.mv_size & 1 ||
        data.mv_size < sizeof(uint16_t) ||
        p[data.mv_size-2] ||
        p[data.mv_size-1]
       ) {
        Nan::ThrowError("Invalid UTF16 string");
        return Nan::Undefined();
    }
    auto str = Nan::New<v8::String>(
        static_cast<uint16_t*>(data.mv_data),
        data.mv_size/sizeof(uint16_t)-1);
    return str.ToLocalChecked();
}

Local<Value> keyToHandle(MDB_val &key, node_lmdb::KeyType kt) {
    switch (kt) {
      case node_lmdb::uint32Key:
        return Nan::New<Integer>(*((uint32_t*)key.mv_data));
      case node_lmdb::binaryKey:
        return valToBinary(key);
      case node_lmdb::stringKey:
        return valToStringChecked(key);
      case node_lmdb::legacyStringKey:
        return valToString(key);
    }
    assert(("Unhandled KeyType"==0));
}

Local<Value> valToStringUnsafe(MDB_val &data) {
    auto resource = new CustomExternalStringResource(&data);
    auto str = Nan::New<v8::String>(resource);

    return str.ToLocalChecked();
}

Local<Value> valToString(MDB_val &data) {

    if (data.mv_size < sizeof(uint16_t)) {
        Nan::ThrowError("Invalid UTF16 string");
        return Nan::Undefined();
    }
    
    auto buffer = reinterpret_cast<const uint16_t*>(data.mv_data);
    int length = data.mv_size / sizeof(uint16_t) - 1;
    auto str = Nan::New<v8::String>(buffer, length);

    return str.ToLocalChecked();
}

Local<Value> valToBinary(MDB_val &data) {
    return Nan::CopyBuffer(
        (char*)data.mv_data,
        data.mv_size
    ).ToLocalChecked();
}

Local<Value> valToBinaryUnsafe(MDB_val &data) {
    return Nan::NewBuffer(
        (char*)data.mv_data,
        data.mv_size,
        DontFree,
        NULL
    ).ToLocalChecked();
}

Local<Value> valToNumber(MDB_val &data) {
    return Nan::New<Number>(*((double*)data.mv_data));
}

Local<Value> valToBoolean(MDB_val &data) {
    return Nan::New<Boolean>(*((bool*)data.mv_data));
}

void consoleLog(const char *msg) {
    Local<String> str = Nan::New("console.log('").ToLocalChecked();
    str = String::Concat(str, Nan::New<String>(msg).ToLocalChecked());
    str = String::Concat(str, Nan::New("');").ToLocalChecked());

    Local<Script> script = Nan::CompileScript(str).ToLocalChecked();
    Nan::RunScript(script);
}

void consoleLog(Local<Value> val) {
    Local<String> str = Nan::New<String>("console.log('").ToLocalChecked();
    str = String::Concat(str, val->ToString());
    str = String::Concat(str, Nan::New<String>("');").ToLocalChecked());

    Local<Script> script = Nan::CompileScript(str).ToLocalChecked();
    Nan::RunScript(script);
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
    // Silently generate a 0 length if length invalid
    size_t n = val->mv_size / sizeof(uint16_t);
    this->l = n ? n-1 : 0;
}

CustomExternalStringResource::~CustomExternalStringResource() { }

void CustomExternalStringResource::Dispose() {
    // No need to do anything, the data is owned by LMDB, not us
    
    // But actually need to delete the string resource itself:
    // the docs say that "The default implementation will use the delete operator."
    // while initially I thought this means using delete on the string,
    // apparently they meant just calling the destructor of this class.
    delete this;
}

const uint16_t *CustomExternalStringResource::data() const {
    return this->d;
}

size_t CustomExternalStringResource::length() const {
    return this->l;
}
