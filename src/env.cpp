
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

using namespace v8;
using namespace node;

Nan::Persistent<Function> EnvWrap::txnCtor;

Nan::Persistent<Function> EnvWrap::dbiCtor;

typedef struct EnvSyncData {
    uv_work_t request;
    Nan::Callback *callback;
    EnvWrap *ew;
    MDB_env *env;
    int rc;
} EnvSyncData;

EnvWrap::EnvWrap() {
    this->env = nullptr;
    this->currentWriteTxn = nullptr;
}

EnvWrap::~EnvWrap() {
    // Close if not closed already
    if (this->env) {
        this->cleanupStrayTxns();
        mdb_env_close(env);
    }
}

void EnvWrap::cleanupStrayTxns() {
    if (this->currentWriteTxn) {
        mdb_txn_abort(this->currentWriteTxn->txn);
        this->currentWriteTxn->txn = nullptr;
        this->currentWriteTxn->removeFromEnvWrap();
    }
    while (this->readTxns.size()) {
        TxnWrap *tw = *this->readTxns.begin();
        mdb_txn_abort(tw->txn);
        tw->removeFromEnvWrap();
        tw->txn = nullptr;
    }
}

NAN_METHOD(EnvWrap::ctor) {
    Nan::HandleScope scope;

    int rc;

    EnvWrap* ew = new EnvWrap();
    rc = mdb_env_create(&(ew->env));

    if (rc != 0) {
        mdb_env_close(ew->env);
        return throwLmdbError(rc);
    }

    ew->Wrap(info.This());
    ew->Ref();

    return info.GetReturnValue().Set(info.This());
}

template<class T>
int applyUint32Setting(int (*f)(MDB_env *, T), MDB_env* e, Local<Object> options, T dflt, const char* keyName) {
    int rc;
    const Local<Value> value = options->Get(Nan::New<String>(keyName).ToLocalChecked());
    if (value->IsUint32()) {
        rc = f(e, value->Uint32Value());
    }
    else {
        rc = f(e, dflt);
    }

    return rc;
}

NAN_METHOD(EnvWrap::open) {
    Nan::HandleScope scope;

    int rc;
    int flags = 0;

    // Get the wrapper
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());

    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }

    Local<Object> options = info[0]->ToObject();
    Local<String> path = options->Get(Nan::New<String>("path").ToLocalChecked())->ToString();

    // Parse the maxDbs option
    rc = applyUint32Setting<unsigned>(&mdb_env_set_maxdbs, ew->env, options, 1, "maxDbs");
    if (rc != 0) {
        return throwLmdbError(rc);
    }

    // Parse the mapSize option
    Local<Value> mapSizeOption = options->Get(Nan::New<String>("mapSize").ToLocalChecked());
    if (mapSizeOption->IsNumber()) {
        double mapSizeDouble = mapSizeOption->NumberValue();
        size_t mapSizeSizeT = (size_t) mapSizeDouble;
        rc = mdb_env_set_mapsize(ew->env, mapSizeSizeT);
        if (rc != 0) {
            return throwLmdbError(rc);
        }
    }

    // Parse the maxDbs option
    // NOTE: mdb.c defines DEFAULT_READERS as 126
    rc = applyUint32Setting<unsigned>(&mdb_env_set_maxreaders, ew->env, options, 126, "maxReaders");
    if (rc != 0) {
        return throwLmdbError(rc);
    }

    // NOTE: MDB_FIXEDMAP is not exposed here since it is "highly experimental" + it is irrelevant for this use case
    // NOTE: MDB_NOTLS is not exposed here because it is irrelevant for this use case, as node will run all this on a single thread anyway
    setFlagFromValue(&flags, MDB_NOSUBDIR, "noSubdir", false, options);
    setFlagFromValue(&flags, MDB_RDONLY, "readOnly", false, options);
    setFlagFromValue(&flags, MDB_WRITEMAP, "useWritemap", false, options);
    setFlagFromValue(&flags, MDB_NOMETASYNC, "noMetaSync", false, options);
    setFlagFromValue(&flags, MDB_NOSYNC, "noSync", false, options);
    setFlagFromValue(&flags, MDB_MAPASYNC, "mapAsync", false, options);
    
    // Set MDB_NOTLS to enable multiple read-only transactions on the same thread (in this case, the nodejs main thread)
    flags |= MDB_NOTLS;

    // TODO: make file attributes configurable
    rc = mdb_env_open(ew->env, *String::Utf8Value(path), flags, 0664);

    if (rc != 0) {
        mdb_env_close(ew->env);
        ew->env = nullptr;
        return throwLmdbError(rc);
    }
}

NAN_METHOD(EnvWrap::resize) {
    Nan::HandleScope scope;

    // Get the wrapper
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());

    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }

    // Check that the correct number/type of arguments was given.
    if (info.Length() != 1 || !info[0]->IsNumber()) {
        return Nan::ThrowError("Call env.resize() with exactly one argument which is a number.");
    }

    // Since this function may only be called if no transactions are active in this process, check this condition.
    if (ew->currentWriteTxn || ew->readTxns.size()) {
        return Nan::ThrowError("Only call env.resize() when there are no active transactions. Please close all transactions before calling env.resize().");
    }

    double mapSizeDouble = info[0]->NumberValue();
    size_t mapSizeSizeT = (size_t) mapSizeDouble;
    int rc = mdb_env_set_mapsize(ew->env, mapSizeSizeT);
    if (rc != 0) {
        return throwLmdbError(rc);
    }
}

NAN_METHOD(EnvWrap::close) {
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());
    ew->Unref();

    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }

    ew->cleanupStrayTxns();
    mdb_env_close(ew->env);
    ew->env = nullptr;
}

NAN_METHOD(EnvWrap::stat) {
    Nan::HandleScope scope;
    
    // Get the wrapper
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());
    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }
    
    int rc;
    MDB_stat stat;
    
    rc = mdb_env_stat(ew->env, &stat);
    if (rc != 0) {
        return throwLmdbError(rc);
    }
    
    Local<Object> obj = Nan::New<Object>();
    obj->Set(Nan::New<String>("pageSize").ToLocalChecked(), Nan::New<Number>(stat.ms_psize));
    obj->Set(Nan::New<String>("treeDepth").ToLocalChecked(), Nan::New<Number>(stat.ms_depth));
    obj->Set(Nan::New<String>("treeBranchPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_branch_pages));
    obj->Set(Nan::New<String>("treeLeafPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_leaf_pages));
    obj->Set(Nan::New<String>("entryCount").ToLocalChecked(), Nan::New<Number>(stat.ms_entries));

    info.GetReturnValue().Set(obj);
}

NAN_METHOD(EnvWrap::info) {
    Nan::HandleScope scope;
    
    // Get the wrapper
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());
    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }
    
    int rc;
    MDB_envinfo envinfo;
    
    rc = mdb_env_info(ew->env, &envinfo);
    if (rc != 0) {
        return throwLmdbError(rc);
    }
    
    Local<Object> obj = Nan::New<Object>();
    obj->Set(Nan::New<String>("mapAddress").ToLocalChecked(), Nan::New<Number>((uint64_t) envinfo.me_mapaddr));
    obj->Set(Nan::New<String>("mapSize").ToLocalChecked(), Nan::New<Number>(envinfo.me_mapsize));
    obj->Set(Nan::New<String>("lastPageNumber").ToLocalChecked(), Nan::New<Number>(envinfo.me_last_pgno));
    obj->Set(Nan::New<String>("lastTxnId").ToLocalChecked(), Nan::New<Number>(envinfo.me_last_txnid));
    obj->Set(Nan::New<String>("maxReaders").ToLocalChecked(), Nan::New<Number>(envinfo.me_maxreaders));
    obj->Set(Nan::New<String>("numReaders").ToLocalChecked(), Nan::New<Number>(envinfo.me_numreaders));

    info.GetReturnValue().Set(obj);
}

NAN_METHOD(EnvWrap::beginTxn) {
    Nan::HandleScope scope;

    const int argc = 2;

    Local<Value> argv[argc] = { info.This(), info[0] };
    Nan::MaybeLocal<Object> maybeInstance = Nan::NewInstance(Nan::New(txnCtor), argc, argv);

    // Check if txn could be created
    if ((maybeInstance.IsEmpty())) {
        // The maybeInstance is empty because the txnCtor called Nan::ThrowError.
        // No need to call that here again, the user will get the error thrown there.
        return;
    }

    Local<Object> instance = maybeInstance.ToLocalChecked();
    info.GetReturnValue().Set(instance);
}

NAN_METHOD(EnvWrap::openDbi) {
    Nan::HandleScope scope;

    const unsigned argc = 2;
    Local<Value> argv[argc] = { info.This(), info[0] };
    Nan::MaybeLocal<Object> maybeInstance = Nan::NewInstance(Nan::New(dbiCtor), argc, argv);

    // Check if database could be opened
    if ((maybeInstance.IsEmpty())) {
        // The maybeInstance is empty because the dbiCtor called Nan::ThrowError.
        // No need to call that here again, the user will get the error thrown there.
        return;
    }

    Local<Object> instance = maybeInstance.ToLocalChecked();
    info.GetReturnValue().Set(instance);
}

NAN_METHOD(EnvWrap::sync) {
    Nan::HandleScope scope;

    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());

    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }

    Local<Function> callback = info[0].As<Function>();

    EnvSyncData *d = new EnvSyncData;
    d->request.data = d;
    d->ew = ew;
    d->env = ew->env;
    d->callback = new Nan::Callback(callback);

    uv_queue_work(uv_default_loop(), &(d->request), [](uv_work_t *request) -> void {
        // Performing the sync (this will be called on a separate thread)
        EnvSyncData *d = static_cast<EnvSyncData*>(request->data);
        d->rc = mdb_env_sync(d->env, 1);
    }, [](uv_work_t *request, int) -> void {
        Nan::HandleScope scope;

        // Executed after the sync is finished
        EnvSyncData *d = static_cast<EnvSyncData*>(request->data);
        const unsigned argc = 1;
        Local<Value> argv[argc];

        if (d->rc == 0) {
            argv[0] = Nan::Null();
        }
        else {
            argv[0] = Nan::Error(mdb_strerror(d->rc));
        }
        
        Nan::Call(*(d->callback), argc, argv);
        delete d->callback;
        delete d;
    });
}

void EnvWrap::setupExports(Handle<Object> exports) {
    // EnvWrap: Prepare constructor template
    Local<FunctionTemplate> envTpl = Nan::New<FunctionTemplate>(EnvWrap::ctor);
    envTpl->SetClassName(Nan::New<String>("Env").ToLocalChecked());
    envTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // EnvWrap: Add functions to the prototype
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("open").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::open));
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("close").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::close));
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("beginTxn").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::beginTxn));
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("openDbi").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::openDbi));
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("sync").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::sync));
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("stat").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::stat));
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("info").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::info));
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("resize").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::resize));
    // TODO: wrap mdb_env_copy too

    // TxnWrap: Prepare constructor template
    Local<FunctionTemplate> txnTpl = Nan::New<FunctionTemplate>(TxnWrap::ctor);
    txnTpl->SetClassName(Nan::New<String>("Txn").ToLocalChecked());
    txnTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // TxnWrap: Add functions to the prototype
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("commit").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::commit));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("abort").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::abort));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getString").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getString));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getStringUnsafe").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getStringUnsafe));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getBinary").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getBinary));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getBinaryUnsafe").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getBinaryUnsafe));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getNumber").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getNumber));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getBoolean").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getBoolean));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("putString").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::putString));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("putBinary").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::putBinary));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("putNumber").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::putNumber));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("putBoolean").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::putBoolean));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("del").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::del));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("reset").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::reset));
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("renew").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::renew));
    // TODO: wrap mdb_cmp too
    // TODO: wrap mdb_dcmp too
    // TxnWrap: Get constructor
    EnvWrap::txnCtor.Reset( txnTpl->GetFunction());

    // DbiWrap: Prepare constructor template
    Local<FunctionTemplate> dbiTpl = Nan::New<FunctionTemplate>(DbiWrap::ctor);
    dbiTpl->SetClassName(Nan::New<String>("Dbi").ToLocalChecked());
    dbiTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // DbiWrap: Add functions to the prototype
    dbiTpl->PrototypeTemplate()->Set(Nan::New<String>("close").ToLocalChecked(), Nan::New<FunctionTemplate>(DbiWrap::close));
    dbiTpl->PrototypeTemplate()->Set(Nan::New<String>("drop").ToLocalChecked(), Nan::New<FunctionTemplate>(DbiWrap::drop));
    dbiTpl->PrototypeTemplate()->Set(Nan::New<String>("stat").ToLocalChecked(), Nan::New<FunctionTemplate>(DbiWrap::stat));
    // TODO: wrap mdb_stat too
    // DbiWrap: Get constructor
    EnvWrap::dbiCtor.Reset( dbiTpl->GetFunction());

    // Set exports
    exports->Set(Nan::New<String>("Env").ToLocalChecked(), envTpl->GetFunction());
}
