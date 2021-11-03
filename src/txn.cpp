#include "lmdb-store.h"

using namespace v8;
using namespace node;

TxnTracked::TxnTracked(MDB_txn *txn, unsigned int flags) {
    this->txn = txn;
    this->flags = flags;
    cursorCount = 0;
    onlyCursor = false;
    parent = nullptr;
}

TxnTracked::~TxnTracked() {
}

TxnWrap::TxnWrap(MDB_env *env, MDB_txn *txn) {
    this->env = env;
    this->txn = txn;
    this->flags = 0;
    this->ew = nullptr;
}

TxnWrap::~TxnWrap() {
    // Close if not closed already
    if (this->txn) {
        mdb_txn_abort(txn);
        this->removeFromEnvWrap();
    }
}

void TxnWrap::removeFromEnvWrap() {
    if (this->ew) {
        if (this->ew->currentWriteTxn == this) {
            this->ew->currentWriteTxn = this->parentTw;
        }
        else {
            auto it = std::find(ew->readTxns.begin(), ew->readTxns.end(), this);
            if (it != ew->readTxns.end()) {
                ew->readTxns.erase(it);
            }
        }
        
        this->ew->Unref();
        this->ew = nullptr;
    }
    this->txn = nullptr;
}

NAN_METHOD(TxnWrap::ctor) {
    Nan::HandleScope scope;

    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(Local<Object>::Cast(info[0]));
    int flags = 0;
    MDB_txn *txn;
    TxnWrap *parentTw;
    if (info[1]->IsTrue() && ew->writeWorker) { // this is from a transaction callback
        txn = ew->writeWorker->AcquireTxn(&flags);
        parentTw = nullptr;
    } else {
        if (info[1]->IsObject()) {
            Local<Object> options = Local<Object>::Cast(info[1]);

            // Get flags from options

            setFlagFromValue(&flags, MDB_RDONLY, "readOnly", false, options);
        } else if (info[1]->IsNumber()) {
            flags = info[1]->IntegerValue(Nan::GetCurrentContext()).FromJust();
        }
        MDB_txn *parentTxn;
        if (info[2]->IsObject()) {
            parentTw = Nan::ObjectWrap::Unwrap<TxnWrap>(Local<Object>::Cast(info[2]));
            parentTxn = parentTw->txn;
        } else {
            parentTxn = nullptr;
            parentTw = nullptr;
            // Check existence of current write transaction
            if (0 == (flags & MDB_RDONLY)) {
                if (ew->currentWriteTxn != nullptr)
                    return Nan::ThrowError("You have already opened a write transaction in the current process, can't open a second one.");
                //fprintf(stderr, "begin sync txn");
                auto writeWorker = ew->writeWorker;
                if (writeWorker) {
                    parentTxn = writeWorker->AcquireTxn(&flags); // see if we have a paused transaction
                    // else we create a child transaction from the current batch transaction. TODO: Except in WRITEMAP mode, where we need to indicate that the transaction should not be committed
                }
            }
        }
        //fprintf(stderr, "txn_begin from txn.cpp %u %p\n", flags, parentTxn);
        int rc = mdb_txn_begin(ew->env, parentTxn, flags, &txn);
        if (rc != 0) {
            if (rc == EINVAL) {
                return Nan::ThrowError("Invalid parameter, which on MacOS is often due to more transactions than available robust locked semaphors (see docs for more info)");
            }
            return throwLmdbError(rc);
        }
    }
    TxnWrap* tw = new TxnWrap(ew->env, txn);

    // Set the current write transaction
    if (0 == (flags & MDB_RDONLY)) {
        ew->currentWriteTxn = tw;
    }
    else {
        ew->readTxns.push_back(tw);
        ew->currentReadTxn = txn;
    }
    tw->parentTw = parentTw;
    tw->flags = flags;
    tw->ew = ew;
    tw->ew->Ref();
    tw->Wrap(info.This());

    return info.GetReturnValue().Set(info.This());
}

NAN_METHOD(TxnWrap::commit) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }
    int rc;
    WriteWorker* writeWorker = tw->ew->writeWorker;
    if (writeWorker) {
        // if (writeWorker->txn && env->writeMap)
        // rc = 0
        // else
        rc = mdb_txn_commit(tw->txn);
        
        pthread_mutex_unlock(tw->ew->writingLock);
    }
    else
        rc = mdb_txn_commit(tw->txn);
    //fprintf(stdout, "commit done\n");
    tw->removeFromEnvWrap();

    if (rc != 0) {
        return throwLmdbError(rc);
    }
}

NAN_METHOD(TxnWrap::abort) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }

    mdb_txn_abort(tw->txn);
    tw->removeFromEnvWrap();
}

NAN_METHOD(TxnWrap::reset) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }
    tw->ew->readTxnRenewed = false;
    mdb_txn_reset(tw->txn);
}

NAN_METHOD(TxnWrap::renew) {
    Nan::HandleScope scope;

    TxnWrap *tw = Nan::ObjectWrap::Unwrap<TxnWrap>(info.This());

    if (!tw->txn) {
        return Nan::ThrowError("The transaction is already closed.");
    }

    int rc = mdb_txn_renew(tw->txn);
    if (rc != 0) {
        return throwLmdbError(rc);
    }
}

// This file contains code from the node-lmdb project
// Copyright (c) 2013-2017 Timur Kristóf
// Copyright (c) 2021 Kristopher Tate
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
