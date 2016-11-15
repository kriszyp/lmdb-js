
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

void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Local<Object> options);

DbiWrap::DbiWrap(MDB_env *env, MDB_dbi dbi) {
    this->env = env;
    this->dbi = dbi;
}

DbiWrap::~DbiWrap() {
    // Imagine the following JS:
    // ------------------------
    //     var dbi1 = env.openDbi({ name: "hello" });
    //     var dbi2 = env.openDbi({ name: "hello" });
    //     dbi1.close();
    //     txn.putString(dbi2, "world");
    // -----
    // The above DbiWrap objects would both wrap the same MDB_dbi, and if closing the first one called mdb_dbi_close,
    // that'd also render the second DbiWrap instance unusable.
    //
    // For this reason, we will never call mdb_dbi_close
    // NOTE: according to LMDB authors, it is perfectly fine if mdb_dbi_close is never called on an MDB_dbi

    if (this->ew) {
        this->ew->Unref();
    }
}

NAN_METHOD(DbiWrap::ctor) {
    Nan::HandleScope scope;

    MDB_dbi dbi;
    MDB_txn *txn;
    int rc;
    int flags = 0;
    int txnFlags = 0;
    int keyIsUint32 = 0;
    Local<String> name;
    bool nameIsNull = false;

    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info[0]->ToObject());
    if (info[1]->IsObject()) {
        Local<Object> options = info[1]->ToObject();
        nameIsNull = options->Get(Nan::New<String>("name").ToLocalChecked())->IsNull();
        name = options->Get(Nan::New<String>("name").ToLocalChecked())->ToString();

        // Get flags from options

        // NOTE: mdb_set_relfunc is not exposed because MDB_FIXEDMAP is "highly experimental"
        // NOTE: mdb_set_relctx is not exposed because MDB_FIXEDMAP is "highly experimental"
        setFlagFromValue(&flags, MDB_REVERSEKEY, "reverseKey", false, options);
        setFlagFromValue(&flags, MDB_DUPSORT, "dupSort", false, options);
        setFlagFromValue(&flags, MDB_DUPFIXED, "dupFixed", false, options);
        setFlagFromValue(&flags, MDB_INTEGERDUP, "integerDup", false, options);
        setFlagFromValue(&flags, MDB_REVERSEDUP, "reverseDup", false, options);
        setFlagFromValue(&flags, MDB_CREATE, "create", false, options);

        // TODO: wrap mdb_set_compare
        // TODO: wrap mdb_set_dupsort

        // See if key is uint32_t
        setFlagFromValue(&keyIsUint32, 1, "keyIsUint32", false, options);
        if (keyIsUint32) {
            flags |= MDB_INTEGERKEY;
        }

        // Set flags for txn used to open database
        Local<Value> create = options->Get(Nan::New<String>("create").ToLocalChecked());
        if (create->IsBoolean() ? !create->BooleanValue() : false) {
            txnFlags |= MDB_RDONLY;
        }
    }
    else {
        return Nan::ThrowError("Invalid parameters.");
    }

    // Open transaction
    rc = mdb_txn_begin(ew->env, nullptr, txnFlags, &txn);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return Nan::ThrowError(mdb_strerror(rc));
    }

    // Open database
    // NOTE: nullptr in place of the name means using the unnamed database.
    rc = mdb_dbi_open(txn, nameIsNull ? nullptr : *String::Utf8Value(name), flags, &dbi);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return Nan::ThrowError(mdb_strerror(rc));
    }

    // Commit transaction
    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    // Create wrapper
    DbiWrap* dw = new DbiWrap(ew->env, dbi);
    dw->ew = ew;
    dw->ew->Ref();
    dw->keyIsUint32 = keyIsUint32;
    dw->flags = flags;
    dw->Wrap(info.This());

    NanReturnThis();
}

NAN_METHOD(DbiWrap::close) {
    Nan::HandleScope scope;

    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info.This());
    mdb_dbi_close(dw->env, dw->dbi);
    dw->ew->Unref();
    dw->ew = nullptr;

    return;
}

NAN_METHOD(DbiWrap::drop) {
    Nan::HandleScope scope;

    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info.This());
    int del = 1;
    int rc;
    MDB_txn *txn;

    // Check if the database should be deleted
    if (info.Length() == 2 && info[1]->IsObject()) {
        Handle<Object> options = info[1]->ToObject();
        Local<Value> opt = options->Get(Nan::New<String>("justFreePages").ToLocalChecked());
        del = opt->IsBoolean() ? !(opt->BooleanValue()) : 1;
    }

    // Begin transaction
    rc = mdb_txn_begin(dw->env, nullptr, 0, &txn);
    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    // Drop database
    rc = mdb_drop(txn, dw->dbi, del);
    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    // Commit transaction
    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    dw->ew->Unref();
    dw->ew = nullptr;

    return;
}

NAN_METHOD(DbiWrap::stat) {
    Nan::HandleScope scope;

    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info.This());

    if (info.Length() != 1) {
        return Nan::ThrowError("dbi.stat should be called with a single argument which is a txn.");
    }

    TxnWrap *txn = Nan::ObjectWrap::Unwrap<TxnWrap>(info[0]->ToObject());

    MDB_stat stat;
    mdb_stat(txn->txn, dw->dbi, &stat);

    Local<Object> obj = Nan::New<Object>();
    obj->Set(Nan::New<String>("pageSize").ToLocalChecked(), Nan::New<Number>(stat.ms_psize));
    obj->Set(Nan::New<String>("treeDepth").ToLocalChecked(), Nan::New<Number>(stat.ms_depth));
    obj->Set(Nan::New<String>("treeBranchPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_branch_pages));
    obj->Set(Nan::New<String>("treeLeafPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_leaf_pages));
    obj->Set(Nan::New<String>("entryCount").ToLocalChecked(), Nan::New<Number>(stat.ms_entries));

    info.GetReturnValue().Set(obj);
}
