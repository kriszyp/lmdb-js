
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
}

EnvWrap::~EnvWrap() {
    // Close if not closed already
    if (this->env) {
        mdb_env_close(env);
    }
}

NAN_METHOD(EnvWrap::ctor) {
    Nan::HandleScope scope;

    int rc;

    EnvWrap* ew = new EnvWrap();
    rc = mdb_env_create(&(ew->env));

    if (rc != 0) {
        mdb_env_close(ew->env);
        return Nan::ThrowError(mdb_strerror(rc));
    }

    ew->Wrap(info.This());
    ew->Ref();

    NanReturnThis();
}

template<class T>
int applyUint32Setting(int (*f)(MDB_env *, T), MDB_env* e, Local<Object> options, T dflt, const char* keyName) {
    int rc;
    const Handle<Value> value = options->Get(Nan::New<String>(keyName).ToLocalChecked());
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
        return Nan::ThrowError(mdb_strerror(rc));
    }

    // Parse the mapSize option
    Handle<Value> mapSizeOption = options->Get(Nan::New<String>("mapSize").ToLocalChecked());
    if (mapSizeOption->IsNumber()) {
        double mapSizeDouble = mapSizeOption->NumberValue();
        size_t mapSizeSizeT = (size_t) mapSizeDouble;
        rc = mdb_env_set_mapsize(ew->env, mapSizeSizeT);
        if (rc != 0) {
            return Nan::ThrowError(mdb_strerror(rc));
        }
    }

    // Parse the maxDbs option
    rc = applyUint32Setting<unsigned>(&mdb_env_set_maxreaders, ew->env, options, 1, "maxReaders");
    if (rc != 0) {
        return Nan::ThrowError(mdb_strerror(rc));
    }

    // NOTE: MDB_FIXEDMAP is not exposed here since it is "highly experimental" + it is irrelevant for this use case
    // NOTE: MDB_NOTLS is not exposed here because it is irrelevant for this use case, as node will run all this on a single thread anyway
    setFlagFromValue(&flags, MDB_NOSUBDIR, "noSubdir", false, options);
    setFlagFromValue(&flags, MDB_RDONLY, "readOnly", false, options);
    setFlagFromValue(&flags, MDB_WRITEMAP, "useWritemap", false, options);
    setFlagFromValue(&flags, MDB_NOMETASYNC, "noMetaSync", false, options);
    setFlagFromValue(&flags, MDB_NOSYNC, "noSync", false, options);
    setFlagFromValue(&flags, MDB_MAPASYNC, "mapAsync", false, options);

    // TODO: make file attributes configurable
    rc = mdb_env_open(ew->env, *String::Utf8Value(path), flags, 0664);

    if (rc != 0) {
        mdb_env_close(ew->env);
        ew->env = nullptr;
        return Nan::ThrowError(mdb_strerror(rc));
    }

    return;
}

NAN_METHOD(EnvWrap::close) {
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());
    ew->Unref();

    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }

    mdb_env_close(ew->env);
    ew->env = nullptr;

    return;
}

NAN_METHOD(EnvWrap::beginTxn) {
    Nan::HandleScope scope;

    const unsigned argc = 2;

    Handle<Value> argv[argc] = { info.This(), info[0] };
    Local<Object> instance = Nan::New(txnCtor)->NewInstance(argc, argv);

    info.GetReturnValue().Set(instance);
}

NAN_METHOD(EnvWrap::openDbi) {
    Nan::HandleScope scope;

    const unsigned argc = 2;
    Handle<Value> argv[argc] = { info.This(), info[0] };
    Local<Object> instance = Nan::New(dbiCtor)->NewInstance(argc, argv);

    info.GetReturnValue().Set(instance);
}

NAN_METHOD(EnvWrap::sync) {
    Nan::HandleScope scope;

    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());

    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }

    Handle<Function> callback = Handle<Function>::Cast(info[0]);

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
        // Executed after the sync is finished
        EnvSyncData *d = static_cast<EnvSyncData*>(request->data);
        const unsigned argc = 1;
        Handle<Value> argv[argc];

        if (d->rc == 0) {
            argv[0] = Nan::Null();
        }
        else {
            argv[0] = Nan::Error(mdb_strerror(d->rc));
        }

        d->callback->Call(argc, argv);
        delete d->callback;
        delete d;
    });

    return;
}

void EnvWrap::setupExports(Handle<Object> exports) {
    // EnvWrap: Prepare constructor template
    Local<FunctionTemplate> envTpl = Nan::New<FunctionTemplate>(EnvWrap::ctor);
    envTpl->SetClassName(Nan::New<String>("Env").ToLocalChecked());
    envTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // EnvWrap: Add functions to the prototype
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("open").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::open)->GetFunction());
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("close").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::close)->GetFunction());
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("beginTxn").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::beginTxn)->GetFunction());
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("openDbi").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::openDbi)->GetFunction());
    envTpl->PrototypeTemplate()->Set(Nan::New<String>("sync").ToLocalChecked(), Nan::New<FunctionTemplate>(EnvWrap::sync)->GetFunction());
    // TODO: wrap mdb_env_copy too
    // TODO: wrap mdb_env_stat too
    // TODO: wrap mdb_env_info too

    // TxnWrap: Prepare constructor template
    Local<FunctionTemplate> txnTpl = Nan::New<FunctionTemplate>(TxnWrap::ctor);
    txnTpl->SetClassName(Nan::New<String>("Txn").ToLocalChecked());
    txnTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // TxnWrap: Add functions to the prototype
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("commit").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::commit)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("abort").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::abort)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getString").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getString)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getBinary").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getBinary)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getNumber").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getNumber)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("getBoolean").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::getBoolean)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("putString").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::putString)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("putBinary").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::putBinary)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("putNumber").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::putNumber)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("putBoolean").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::putBoolean)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("del").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::del)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("reset").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::reset)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(Nan::New<String>("renew").ToLocalChecked(), Nan::New<FunctionTemplate>(TxnWrap::renew)->GetFunction());
    // TODO: wrap mdb_cmp too
    // TODO: wrap mdb_dcmp too
    // TxnWrap: Get constructor
    EnvWrap::txnCtor.Reset( txnTpl->GetFunction());

    // DbiWrap: Prepare constructor template
    Local<FunctionTemplate> dbiTpl = Nan::New<FunctionTemplate>(DbiWrap::ctor);
    dbiTpl->SetClassName(Nan::New<String>("Dbi").ToLocalChecked());
    dbiTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // DbiWrap: Add functions to the prototype
    dbiTpl->PrototypeTemplate()->Set(Nan::New<String>("close").ToLocalChecked(), Nan::New<FunctionTemplate>(DbiWrap::close)->GetFunction());
    dbiTpl->PrototypeTemplate()->Set(Nan::New<String>("drop").ToLocalChecked(), Nan::New<FunctionTemplate>(DbiWrap::drop)->GetFunction());
    dbiTpl->PrototypeTemplate()->Set(Nan::New<String>("stat").ToLocalChecked(), Nan::New<FunctionTemplate>(DbiWrap::stat)->GetFunction());
    // TODO: wrap mdb_stat too
    // DbiWrap: Get constructor
    EnvWrap::dbiCtor.Reset( dbiTpl->GetFunction());

    // Set exports
    exports->Set(Nan::New<String>("Env").ToLocalChecked(), envTpl->GetFunction());
}
