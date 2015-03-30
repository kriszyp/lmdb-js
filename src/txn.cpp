
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
    NanScope();

    EnvWrap *ew = ObjectWrap::Unwrap<EnvWrap>(args[0]->ToObject());
    int flags = 0;

    if (args[1]->IsObject()) {
        Local<Object> options = args[1]->ToObject();

        // Get flags from options

        setFlagFromValue(&flags, MDB_RDONLY, "readOnly", false, options);
    }


    MDB_txn *txn;
    int rc = mdb_txn_begin(ew->env, nullptr, flags, &txn);
    if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    TxnWrap* tw = new TxnWrap(ew->env, txn);
    tw->ew = ew;
    tw->ew->Ref();
    tw->Wrap(args.This());

    NanReturnThis();
}

NAN_METHOD(TxnWrap::commit) {
    NanScope();

    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());

    if (!tw->txn) {
        return NanThrowError("The transaction is already closed.");
    }

    int rc = mdb_txn_commit(tw->txn);
    tw->txn = nullptr;
    tw->ew->Unref();

    if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    NanReturnUndefined();
}

NAN_METHOD(TxnWrap::abort) {
    NanScope();

    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());

    if (!tw->txn) {
        return NanThrowError("The transaction is already closed.");
    }

    mdb_txn_abort(tw->txn);
    tw->ew->Unref();
    tw->txn = nullptr;

    NanReturnUndefined();
}

NAN_METHOD(TxnWrap::reset) {
    NanScope();

    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());

    if (!tw->txn) {
        return NanThrowError("The transaction is already closed.");
    }

    mdb_txn_reset(tw->txn);

    NanReturnUndefined();
}

NAN_METHOD(TxnWrap::renew) {
    NanScope();

    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());

    if (!tw->txn) {
        return NanThrowError("The transaction is already closed.");
    }

    int rc = mdb_txn_renew(tw->txn);
    if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    NanReturnUndefined();
}

_NAN_METHOD_RETURN_TYPE TxnWrap::getCommon(_NAN_METHOD_ARGS, Handle<Value> (*successFunc)(MDB_val&)) {
    NanScope();

    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[0]->ToObject());

    if (!tw->txn) {
        return NanThrowError("The transaction is already closed.");
    }

    MDB_val key, data;
    void (*freeKey)(MDB_val&) = argToKey(args[1], key, dw->keyIsUint32);
    if (!freeKey) {
        NanReturnUndefined();
    }

    int rc = mdb_get(tw->txn, dw->dbi, &key, &data);
    freeKey(key);

    if (rc == MDB_NOTFOUND) {
        NanReturnNull();
    }
    else if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    NanReturnValue(successFunc(data));
}

NAN_METHOD(TxnWrap::getString) {
    return getCommon(args, valToString);
}

NAN_METHOD(TxnWrap::getBinary) {
    return getCommon(args, valToBinary);
}

NAN_METHOD(TxnWrap::getNumber) {
    return getCommon(args, valToNumber);
}

NAN_METHOD(TxnWrap::getBoolean) {
    return getCommon(args, valToBoolean);
}

_NAN_METHOD_RETURN_TYPE TxnWrap::putCommon(_NAN_METHOD_ARGS, void (*fillFunc)(_NAN_METHOD_ARGS, MDB_val&), void (*freeData)(MDB_val&)) {
    NanScope();

    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[0]->ToObject());

    if (!tw->txn) {
        return NanThrowError("The transaction is already closed.");
    }

    int flags = 0;
    MDB_val key, data;

    void (*freeKey)(MDB_val&) = argToKey(args[1], key, dw->keyIsUint32);
    if (!freeKey) {
        NanReturnUndefined();
    }

    fillFunc(args, data);

    int rc = mdb_put(tw->txn, dw->dbi, &key, &data, flags);
    freeKey(key);
    freeData(data);

    if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    NanReturnUndefined();
}

NAN_METHOD(TxnWrap::putString) {
    return putCommon(args, [](_NAN_METHOD_ARGS, MDB_val &data) -> void {
        CustomExternalStringResource::writeTo(args[2]->ToString(), &data);
    }, [](MDB_val &data) -> void {
        delete (uint16_t*)data.mv_data;
    });
}

NAN_METHOD(TxnWrap::putBinary) {
    return putCommon(args, [](_NAN_METHOD_ARGS, MDB_val &data) -> void {
        data.mv_size = node::Buffer::Length(args[2]);
        data.mv_data = node::Buffer::Data(args[2]);
    }, [](MDB_val &) -> void {
        // I think the data is owned by the node::Buffer so we don't need to free it - need to clarify
    });
}

NAN_METHOD(TxnWrap::putNumber) {
    return putCommon(args, [](_NAN_METHOD_ARGS, MDB_val &data) -> void {
        data.mv_size = sizeof(double);
        data.mv_data = new double;
        *((double*)data.mv_data) = args[2]->ToNumber()->Value();
    }, [](MDB_val &data) -> void {
        delete (double*)data.mv_data;
    });
}

NAN_METHOD(TxnWrap::putBoolean) {
    return putCommon(args, [](_NAN_METHOD_ARGS, MDB_val &data) -> void {
        data.mv_size = sizeof(double);
        data.mv_data = new bool;
        *((bool*)data.mv_data) = args[2]->ToBoolean()->Value();
    }, [](MDB_val &data) -> void {
        delete (bool*)data.mv_data;
    });
}

NAN_METHOD(TxnWrap::del) {
    NanScope();

    TxnWrap *tw = ObjectWrap::Unwrap<TxnWrap>(args.This());
    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args[0]->ToObject());

    if (!tw->txn) {
        return NanThrowError("The transaction is already closed.");
    }

    MDB_val key;
    void (*freeKey)(MDB_val&) = argToKey(args[1], key, dw->keyIsUint32);
    if (!freeKey) {
        NanReturnUndefined();
    }

    int rc = mdb_del(tw->txn, dw->dbi, &key, nullptr);
    freeKey(key);

    if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    NanReturnUndefined();
}
