
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
    NanScope();

    MDB_dbi dbi;
    MDB_txn *txn;
    int rc;
    int flags = 0;
    int keyIsUint32 = 0;
    Local<String> name;

    EnvWrap *ew = ObjectWrap::Unwrap<EnvWrap>(args[0]->ToObject());
    if (args[1]->IsObject()) {
        Local<Object> options = args[1]->ToObject();
        name = options->Get(NanNew<String>("name"))->ToString();

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
    }
    else {
        return NanThrowError("Invalid parameters.");
    }

    // Open transaction
    rc = mdb_txn_begin(ew->env, nullptr, 0, &txn);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return NanThrowError(mdb_strerror(rc));
    }

    // Open database
    rc = mdb_dbi_open(txn, *String::Utf8Value(name), flags, &dbi);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return NanThrowError(mdb_strerror(rc));
    }

    // Commit transaction
    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    // Create wrapper
    DbiWrap* dw = new DbiWrap(ew->env, dbi);
    dw->ew = ew;
    dw->ew->Ref();
    dw->keyIsUint32 = keyIsUint32;
    dw->Wrap(args.This());

    NanReturnThis();
}

NAN_METHOD(DbiWrap::close) {
    NanScope();

    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args.This());
    mdb_dbi_close(dw->env, dw->dbi);
    dw->ew->Unref();
    dw->ew = nullptr;

    NanReturnUndefined();
}

NAN_METHOD(DbiWrap::drop) {
    NanScope();

    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args.This());
    int del = 1;
    int rc;
    MDB_txn *txn;

    // Check if the database should be deleted
    if (args.Length() == 2 && args[1]->IsObject()) {
        Handle<Object> options = args[1]->ToObject();
        Handle<Value> opt = options->Get(NanNew<String>("justFreePages"));
        del = opt->IsBoolean() ? !(opt->BooleanValue()) : 1;
    }

    // Begin transaction
    rc = mdb_txn_begin(dw->env, nullptr, 0, &txn);
    if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    // Drop database
    rc = mdb_drop(txn, dw->dbi, del);
    if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    // Commit transaction
    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return NanThrowError(mdb_strerror(rc));
    }

    dw->ew->Unref();
    dw->ew = nullptr;

    NanReturnUndefined();
}

NAN_METHOD(DbiWrap::stat) {
    NanScope();

    DbiWrap *dw = ObjectWrap::Unwrap<DbiWrap>(args.This());

    if (args.Length() != 1) {
        return NanThrowError("dbi.stat should be called with a single argument which is a txn.");
    }

    TxnWrap *txn = ObjectWrap::Unwrap<TxnWrap>(args[0]->ToObject());

    MDB_stat stat;
    mdb_stat(txn->txn, dw->dbi, &stat);

    Local<Object> obj = NanNew<Object>();
    obj->Set(NanNew<String>("pageSize"), NanNew<Number>(stat.ms_psize));
    obj->Set(NanNew<String>("treeDepth"), NanNew<Number>(stat.ms_depth));
    obj->Set(NanNew<String>("treeBranchPageCount"), NanNew<Number>(stat.ms_branch_pages));
    obj->Set(NanNew<String>("treeLeafPageCount"), NanNew<Number>(stat.ms_leaf_pages));
    obj->Set(NanNew<String>("entryCount"), NanNew<Number>(stat.ms_entries));

    NanReturnValue(obj);
}
