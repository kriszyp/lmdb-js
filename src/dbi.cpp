
// This file is part of node-lmdb, the Node.js binding for lmdb
// Copyright (c) 2013-2017 Timur Kristóf
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
#include <cstdio>

using namespace v8;
using namespace node;

void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Local<Object> options);

DbiWrap::DbiWrap(MDB_env *env, MDB_dbi dbi) {
    this->env = env;
    this->dbi = dbi;
    this->keyType = NodeLmdbKeyType::StringKey;
    this->isOpen = false;
    this->ew = nullptr;
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
    Local<String> name;
    bool nameIsNull = false;
    NodeLmdbKeyType keyType = NodeLmdbKeyType::StringKey;
    bool needsTransaction = true;
    bool isOpen = false;

    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(Local<Object>::Cast(info[0]));
    
    if (info[1]->IsObject()) {
        Local<Object> options = Local<Object>::Cast(info[1]);
        nameIsNull = options->Get(Nan::GetCurrentContext(), Nan::New<String>("name").ToLocalChecked()).ToLocalChecked()->IsNull();
        name = Local<String>::Cast(options->Get(Nan::GetCurrentContext(), Nan::New<String>("name").ToLocalChecked()).ToLocalChecked());

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

        keyType = keyTypeFromOptions(options);
        if (keyType == NodeLmdbKeyType::InvalidKey) {
            // NOTE: Error has already been thrown inside keyTypeFromOptions
            return;
        }
        
        if (keyType == NodeLmdbKeyType::Uint32Key) {
            flags |= MDB_INTEGERKEY;
        }

        // Set flags for txn used to open database
        Local<Value> create = options->Get(Nan::GetCurrentContext(), Nan::New<String>("create").ToLocalChecked()).ToLocalChecked();
        #if NODE_VERSION_AT_LEAST(12,0,0)
        if (create->IsBoolean() ? !create->BooleanValue(Isolate::GetCurrent()) : true) {
        #else
        if (create->IsBoolean() ? !create->BooleanValue(Nan::GetCurrentContext()).FromJust() : true) {
        #endif;
            txnFlags |= MDB_RDONLY;
        }
        
        auto txnObj = options->Get(Nan::GetCurrentContext(), Nan::New<String>("txn").ToLocalChecked()).ToLocalChecked();
        if (!txnObj->IsNull() && !txnObj->IsUndefined() && txnObj->IsObject()) {
            TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(Local<Object>::Cast(txnObj));
            needsTransaction = false;
            txn = tw->txn;
        }
    }
    else {
        return Nan::ThrowError("Invalid parameters.");
    }

    if (needsTransaction) {
        // Open transaction
        rc = mdb_txn_begin(ew->env, nullptr, txnFlags, &txn);
        if (rc != 0) {
            // No need to call mdb_txn_abort, because mdb_txn_begin already cleans up after itself
            return throwLmdbError(rc);
        }
    }

    // Open database
    // NOTE: nullptr in place of the name means using the unnamed database.
    #if NODE_VERSION_AT_LEAST(12,0,0)
    rc = mdb_dbi_open(txn, nameIsNull ? nullptr : *String::Utf8Value(Isolate::GetCurrent(), name), flags, &dbi);
    #else
    rc = mdb_dbi_open(txn, nameIsNull ? nullptr : *String::Utf8Value(name), flags, &dbi);
    #endif
    if (rc != 0) {
        if (needsTransaction) {
            mdb_txn_abort(txn);
        }
        return throwLmdbError(rc);
    }
    else {
        isOpen = true;
    }

    if (needsTransaction) {
        // Commit transaction
        rc = mdb_txn_commit(txn);
        if (rc != 0) {
            return throwLmdbError(rc);
        }
    }

    // Create wrapper
    DbiWrap* dw = new DbiWrap(ew->env, dbi);
    if (isOpen) {
        dw->ew = ew;
        dw->ew->Ref();
    }
    dw->keyType = keyType;
    dw->flags = flags;
    dw->isOpen = isOpen;
    dw->Wrap(info.This());

    return info.GetReturnValue().Set(info.This());
}

NAN_METHOD(DbiWrap::close) {
    Nan::HandleScope scope;

    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info.This());
    if (dw->isOpen) {
        mdb_dbi_close(dw->env, dw->dbi);
        dw->isOpen = false;
        dw->ew->Unref();
        dw->ew = nullptr;
    }
    else {
        return Nan::ThrowError("The Dbi is not open, you can't close it.");
    }
}

NAN_METHOD(DbiWrap::drop) {
    Nan::HandleScope scope;

    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info.This());
    int del = 1;
    int rc;
    MDB_txn *txn;
    bool needsTransaction = true;
    
    if (!dw->isOpen) {
        return Nan::ThrowError("The Dbi is not open, you can't drop it.");
    }

    // Check if the database should be deleted
    if (info.Length() == 1 && info[0]->IsObject()) {
        Local<Object> options = Local<Object>::Cast(info[0]);
        
        // Just free pages
        Local<Value> opt = options->Get(Nan::GetCurrentContext(), Nan::New<String>("justFreePages").ToLocalChecked()).ToLocalChecked();
        #if NODE_VERSION_AT_LEAST(12,0,0)
        del = opt->IsBoolean() ? !(opt->BooleanValue(Isolate::GetCurrent())) : 1;
        #else
        del = opt->IsBoolean() ? !(opt->BooleanValue(Nan::GetCurrentContext()).FromJust()) : 1;
        #endif;
        
        // User-supplied txn
        auto txnObj = options->Get(Nan::GetCurrentContext(), Nan::New<String>("txn").ToLocalChecked()).ToLocalChecked();
        if (!txnObj->IsNull() && !txnObj->IsUndefined() && txnObj->IsObject()) {
            TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(Local<Object>::Cast(txnObj));
            needsTransaction = false;
            txn = tw->txn;
        }
    }

    if (needsTransaction) {
        // Begin transaction
        rc = mdb_txn_begin(dw->env, nullptr, 0, &txn);
        if (rc != 0) {
            return throwLmdbError(rc);
        }
    }

    // Drop database
    rc = mdb_drop(txn, dw->dbi, del);
    if (rc != 0) {
        if (needsTransaction) {
            mdb_txn_abort(txn);
        }
        return throwLmdbError(rc);
    }

    if (needsTransaction) {
        // Commit transaction
        rc = mdb_txn_commit(txn);
        if (rc != 0) {
            return throwLmdbError(rc);
        }
    }
    
    // Only close database if del == 1
    if (del == 1) {
        dw->isOpen = false;
        dw->ew->Unref();
        dw->ew = nullptr;
    }
}

NAN_METHOD(DbiWrap::stat) {
    Nan::HandleScope scope;

    DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(info.This());

    if (info.Length() != 1) {
        return Nan::ThrowError("dbi.stat should be called with a single argument which is a txn.");
    }

    TxnWrap *txn = Nan::ObjectWrap::Unwrap<TxnWrap>(Local<Object>::Cast(info[0]));

    MDB_stat stat;
    mdb_stat(txn->txn, dw->dbi, &stat);

    Local<Context> context = Nan::GetCurrentContext();
    Local<Object> obj = Nan::New<Object>();
    obj->Set(context, Nan::New<String>("pageSize").ToLocalChecked(), Nan::New<Number>(stat.ms_psize));
    obj->Set(context, Nan::New<String>("treeDepth").ToLocalChecked(), Nan::New<Number>(stat.ms_depth));
    obj->Set(context, Nan::New<String>("treeBranchPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_branch_pages));
    obj->Set(context, Nan::New<String>("treeLeafPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_leaf_pages));
    obj->Set(context, Nan::New<String>("entryCount").ToLocalChecked(), Nan::New<Number>(stat.ms_entries));
    obj->Set(context, Nan::New<String>("overflowPages").ToLocalChecked(), Nan::New<Number>(stat.ms_overflow_pages));

    info.GetReturnValue().Set(obj);
}
