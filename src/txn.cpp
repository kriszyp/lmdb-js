
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

TxnWrap::TxnWrap(MDB_env *env, MDB_txn *txn) {
    this->env = env;
    this->txn = txn;
}

TxnWrap::~TxnWrap() {
    // Close if not closed already
    if (this->txn) {
        mdb_txn_abort(txn);
        this->ew->Unref();
    }
}

NAN_METHOD(TxnWrap::ctor) {
    Nan::HandleScope scope;

    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info[0]->ToObject());
    int flags = 0;

    if (info[1]->IsObject()) {
        Local<Object> options = info[1]->ToObject();

        // Get flags from options

        setFlagFromValue(&flags, MDB_RDONLY, "readOnly", false, options);
    }


    MDB_txn *txn;
    int rc = mdb_txn_begin(ew->env, nullptr, flags, &txn);
    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    TxnWrap* tw = new TxnWrap(ew->env, txn);
    tw->ew = ew;
    tw->ew->Ref();
    tw->Wrap(info.This());

    NanReturnThis();
}

NAN_METHOD(TxnWrap::commit) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }

    int rc = mdb_txn_commit(tw->txn);
    tw->txn = nullptr;
    tw->ew->Unref();

    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    return;
}

NAN_METHOD(TxnWrap::abort) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }

    mdb_txn_abort(tw->txn);
    tw->ew->Unref();
    tw->txn = nullptr;

    return;
}

NAN_METHOD(TxnWrap::reset) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }

    mdb_txn_reset(tw->txn);

    return;
}

NAN_METHOD(TxnWrap::renew) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }

    int rc = mdb_txn_renew(tw->txn);
    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    return;
}

Nan::NAN_METHOD_RETURN_TYPE TxnWrap::getCommon(Nan::NAN_METHOD_ARGS_TYPE info, Local<Value> (*successFunc)(MDB_val&)) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());
    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info[0]->ToObject());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }

    MDB_val key, data;
    void (*freeKey)(MDB_val&) = argToKey(info[1], key, dw->keyIsUint32);
    if (!freeKey) {
        return;
    }

    int rc = mdb_get(tw->txn, dw->dbi, &key, &data);
    freeKey(key);

    if (rc == MDB_NOTFOUND) {
        return info.GetReturnValue().Set(Nan::Null());
    }
    else if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }
    else {
      return info.GetReturnValue().Set(successFunc(data));
    }
}

NAN_METHOD(TxnWrap::getString) {
    return getCommon(info, valToString);
}

NAN_METHOD(TxnWrap::getStringUnsafe) {
    return getCommon(info, valToStringUnsafe);
}

NAN_METHOD(TxnWrap::getBinary) {
    return getCommon(info, valToBinary);
}

NAN_METHOD(TxnWrap::getBinaryUnsafe) {
    return getCommon(info, valToBinaryUnsafe);
}

NAN_METHOD(TxnWrap::getNumber) {
    return getCommon(info, valToNumber);
}

NAN_METHOD(TxnWrap::getBoolean) {
    return getCommon(info, valToBoolean);
}

Nan::NAN_METHOD_RETURN_TYPE TxnWrap::putCommon(Nan::NAN_METHOD_ARGS_TYPE info, void (*fillFunc)(Nan::NAN_METHOD_ARGS_TYPE info, MDB_val&), void (*freeData)(MDB_val&)) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());
    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info[0]->ToObject());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }

    int flags = 0;
    MDB_val key, data;

    void (*freeKey)(MDB_val&) = argToKey(info[1], key, dw->keyIsUint32);
    if (!freeKey) {
        return;
    }

    fillFunc(info, data);

    int rc = mdb_put(tw->txn, dw->dbi, &key, &data, flags);
    freeKey(key);
    freeData(data);

    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    return;
}

NAN_METHOD(TxnWrap::putString) {
    return putCommon(info, [](Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &data) -> void {
        CustomExternalStringResource::writeTo(info[2]->ToString(), &data);
    }, [](MDB_val &data) -> void {
        delete[] (uint16_t*)data.mv_data;
    });
}

NAN_METHOD(TxnWrap::putBinary) {
    return putCommon(info, [](Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &data) -> void {
        data.mv_size = node::Buffer::Length(info[2]);
        data.mv_data = node::Buffer::Data(info[2]);
    }, [](MDB_val &) -> void {
        // I think the data is owned by the node::Buffer so we don't need to free it - need to clarify
    });
}

NAN_METHOD(TxnWrap::putNumber) {
    return putCommon(info, [](Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &data) -> void {
        data.mv_size = sizeof(double);
        data.mv_data = new double;
        *((double*)data.mv_data) = info[2]->ToNumber(Nan::GetCurrentContext()).ToLocalChecked()->Value();
    }, [](MDB_val &data) -> void {
        delete (double*)data.mv_data;
    });
}

NAN_METHOD(TxnWrap::putBoolean) {
    return putCommon(info, [](Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &data) -> void {
        data.mv_size = sizeof(double);
        data.mv_data = new bool;
        *((bool*)data.mv_data) = info[2]->ToBoolean()->Value();
    }, [](MDB_val &data) -> void {
        delete (bool*)data.mv_data;
    });
}

NAN_METHOD(TxnWrap::del) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());
    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info[0]->ToObject());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }

    MDB_val key;
    void (*freeKey)(MDB_val&) = argToKey(info[1], key, dw->keyIsUint32);
    if (!freeKey) {
        return;
    }

    // Set data if dupSort true and data given
    MDB_val data;
    Local<Value> dataHandle = info[2];
    bool freeData = false;
    if ((dw->flags & MDB_DUPSORT) && !(dataHandle->IsUndefined())) {
        if (dataHandle->IsString()) {
            CustomExternalStringResource::writeTo(dataHandle->ToString(), &data);
            freeData = true;
        }
        else if (node::Buffer::HasInstance(dataHandle)) {
            data.mv_size = node::Buffer::Length(dataHandle);
            data.mv_data = node::Buffer::Data(dataHandle);
            freeData = true;
        }
        else if (dataHandle->IsNumber()) {
            data.mv_size = sizeof(double);
            data.mv_data = new double;
            *((double*)data.mv_data) = dataHandle->ToNumber()->Value();
            freeData = true;
        }
        else if (dataHandle->IsBoolean()) {
            data.mv_size = sizeof(double);
            data.mv_data = new bool;
            *((bool*)data.mv_data) = dataHandle->ToBoolean()->Value();
            freeData = true;
        }
        else {
            Nan::ThrowError("Invalid data type.");
        }
    }

    int rc = mdb_del(tw->txn, dw->dbi, &key, freeData ? &data : nullptr);

    freeKey(key);
    if (freeData) {
        if (dataHandle->IsString()) {
            delete[] (uint16_t*)data.mv_data;
        }
        else if (node::Buffer::HasInstance(dataHandle)) {
            // I think the data is owned by the node::Buffer so we don't need to free it - need to clarify
        }
        else if (dataHandle->IsNumber()) {
            delete (double*)data.mv_data;
        }
        else if (dataHandle->IsBoolean()) {
            delete (bool*)data.mv_data;
        }
    }

    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    return;
}
