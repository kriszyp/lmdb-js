
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
void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Local<Object> options);

static inline void fakeFreeCallback(char *data, void *) {
    // Don't need to do anything here, because the data belongs to LMDB anyway
}

argtokey_callback_t argToKey(const Handle<Value> &val, MDB_val &key) {
    if (val->IsUint32()) {
        uint32_t *v = new uint32_t;
        *v = val->Uint32Value();
        
        key.mv_size = sizeof(uint32_t);
        key.mv_data = v;
        
        return ([](MDB_val &key) -> void {
            delete (uint32_t*)key.mv_data;
        });
    }
    else if (val->IsString()) {
        CustomExternalStringResource::writeTo(val->ToString(), &key);
        return ([](MDB_val &key) -> void {
            delete (uint16_t*)key.mv_data;
        });
    }
    else {
        ThrowException(Exception::Error(String::New("The data type of the given key is not supported.")));
    }
    
    return NULL;
}

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
    int flags = 0;
    
    if (args[1]->IsObject()) {
        Local<Object> options = args[1]->ToObject();
        
        // Get flags from options
        
        setFlagFromValue(&flags, MDB_RDONLY, "readOnly", false, options);
    }
    
    
    MDB_txn *txn;
    int rc = mdb_txn_begin(ew->env, NULL, flags, &txn);
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

Handle<Value> TxnWrap::reset(const Arguments& args) {
    HandleScope scope;
    
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    mdb_txn_reset(tw->txn);
    
    return Undefined();
}

Handle<Value> TxnWrap::renew(const Arguments& args) {
    HandleScope scope;
    
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    int rc = mdb_txn_renew(tw->txn);
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }
    
    return Undefined();
}

Handle<Value> TxnWrap::getCommon(const Arguments &args, Handle<Value> (*successFunc)(const Arguments&, MDB_val&)) {
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[0]->ToObject());
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    MDB_val key, data;
    void (*freeKey)(MDB_val&) = argToKey(args[1], key);
    int rc = mdb_get(tw->txn, dw->dbi, &key, &data);
    freeKey(key);
    
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

Handle<Value> TxnWrap::putCommon(const Arguments &args, void (*fillFunc)(const Arguments&, MDB_val&), void (*freeData)(MDB_val&)) {  
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[0]->ToObject());
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    int flags = 0;
    MDB_val key, data;
    
    void (*freeKey)(MDB_val&) = argToKey(args[1], key);
    fillFunc(args, data);
    
    int rc = mdb_put(tw->txn, dw->dbi, &key, &data, flags);
    freeKey(key);
    freeData(data);
    
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
    }, [](MDB_val &) -> void {
        // I think the data is owned by the node::Buffer so we don't need to free it - need to clarify
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
    void (*freeKey)(MDB_val&) = argToKey(args[1], key);
    int rc = mdb_del(tw->txn, dw->dbi, &key, NULL);
    freeKey(key);
    
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }
    
    return Undefined();
}

Handle<Value> TxnWrap::dropDbi(const Arguments& args) {
    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[0]->ToObject());
    int del = 1;
    
    if (args.Length() == 2 && args[1]->IsObject()) {
        Handle<Object> options = args[1]->ToObject();
        Handle<Value> opt = options->Get(String::NewSymbol("justFreePages"));
        del = opt->IsBoolean() ? !(opt->BooleanValue()) : 1;
    }
    
    if (!tw->txn) {
        ThrowException(Exception::Error(String::New("The transaction is already closed.")));
        return Undefined();
    }
    
    int rc = mdb_drop(tw->txn, dw->dbi, del);
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }
    
    return Undefined();
}


