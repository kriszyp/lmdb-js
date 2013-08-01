
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
#include <node_buffer.h>

using namespace v8;
using namespace node;

void v8ToLmdbVal(Handle<Value> handle, MDB_val *val);
Handle<Value> lmdbValToV8(MDB_val *val);
void consoleLog(const char *msg);

TxnWrap::TxnWrap(MDB_env *env, MDB_txn *txn) {
    this->env = env;
    this->txn = txn;
}

TxnWrap::~TxnWrap() {
    // Close if not closed already
    if (this->txn) {
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
    tw->Wrap(args.This());

    return args.This();
}

Handle<Value> TxnWrap::commit(const Arguments& args) {
    HandleScope scope;
    
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    int rc = mdb_txn_commit(tw->txn);
    tw->txn = NULL;
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }
    
    return Undefined();
}

Handle<Value> TxnWrap::abort(const Arguments& args) {
    HandleScope scope;
    
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    mdb_txn_abort(tw->txn);
    tw->txn = NULL;
    
    return Undefined();
}

static inline void fakeFreeCallback(char *data, void *) {
    // Don't need to do anything here, because the data belongs to LMDB anyway
}

Handle<Value> TxnWrap::getCommon(const Arguments &args, Handle<Value> (*successFunc)(const Arguments&, MDB_val&)) {
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[0]->ToObject());
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    MDB_val key, data;
    CustomExternalStringResource::writeTo(args[1]->ToString(), &key);
    
    int rc = mdb_get(tw->txn, dw->dbi, &key, &data);
    if (rc == MDB_NOTFOUND) {
        return Null();
    }
    else if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }
    
    return successFunc(args, data);
}

Handle<Value> TxnWrap::getString(const Arguments& args) {
    return getCommon(args, [](const Arguments &args, MDB_val &data) -> Handle<Value> {
        return String::NewExternal(new CustomExternalStringResource(&data));
    });
}

Handle<Value> TxnWrap::getBinary(const Arguments& args) {
    return getCommon(args, [](const Arguments& args, MDB_val& data) -> Handle<Value> {
        return Buffer::New((char*)data.mv_data, data.mv_size, fakeFreeCallback, NULL)->handle_;
    });
}

Handle<Value> TxnWrap::getNumber(const Arguments& args) {
    return getCommon(args, [](const Arguments& args, MDB_val& data) -> Handle<Value> {
        return Number::New(*((double*)data.mv_data));
    });
}

Handle<Value> TxnWrap::getBoolean(const Arguments& args) {
    return getCommon(args, [](const Arguments& args, MDB_val& data) -> Handle<Value> {
        return Boolean::New(*((bool*)data.mv_data));
    });
}

Handle<Value> TxnWrap::putCommon(const Arguments &args, void (*fillFunc)(const Arguments&, MDB_val&), void (*freeFunc)(MDB_val&)) {  
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[0]->ToObject());
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    int flags = 0;
    MDB_val key, data;
    
    CustomExternalStringResource::writeTo(args[1]->ToString(), &key);
    fillFunc(args, data);
    
    int rc = mdb_put(tw->txn, dw->dbi, &key, &data, flags);
    freeFunc(data);
    
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }
    
    return Undefined();
}

Handle<Value> TxnWrap::putString(const Arguments& args) {
    return putCommon(args, [](const Arguments &args, MDB_val &data) -> void {
        CustomExternalStringResource::writeTo(args[2]->ToString(), &data);
    }, [](MDB_val &data) -> void {
        delete (uint16_t*)data.mv_data;
    });
}

Handle<Value> TxnWrap::putBinary(const Arguments& args) {
    return putCommon(args, [](const Arguments &args, MDB_val &data) -> void {
        data.mv_size = node::Buffer::Length(args[2]);
        data.mv_data = node::Buffer::Data(args[2]);
    }, [](MDB_val &data) -> void {
        // TODO
    });
}

Handle<Value> TxnWrap::putNumber(const Arguments& args) {
    return putCommon(args, [](const Arguments &args, MDB_val &data) -> void {
        data.mv_size = sizeof(double);
        data.mv_data = new double;
        *((double*)data.mv_data) = args[2]->ToNumber()->Value();
    }, [](MDB_val &data) -> void {
        delete (double*)data.mv_data;
    });
}

Handle<Value> TxnWrap::putBoolean(const Arguments& args) {
    return putCommon(args, [](const Arguments &args, MDB_val &data) -> void {
        data.mv_size = sizeof(double);
        data.mv_data = new bool;
        *((bool*)data.mv_data) = args[2]->ToBoolean()->Value();
    }, [](MDB_val &data) -> void {
        delete (bool*)data.mv_data;
    });
}

Handle<Value> TxnWrap::del(const Arguments& args) {
    HandleScope scope;
    
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[0]->ToObject());
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    MDB_val key;
    CustomExternalStringResource::writeTo(args[1]->ToString(), &key);
    
    int rc = mdb_del(tw->txn, dw->dbi, &key, NULL);
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }
    
    return Undefined();
}


