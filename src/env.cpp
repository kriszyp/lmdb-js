
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

Persistent<Function> EnvWrap::txnCtor;

Persistent<Function> EnvWrap::dbiCtor;

typedef struct EnvSyncData {
    uv_work_t request;
    Persistent<Function> callback;
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

Handle<Value> EnvWrap::ctor(const Arguments& args) {
    HandleScope scope;
    int rc;

    EnvWrap* ew = new EnvWrap();
    rc = mdb_env_create(&(ew->env));

    if (rc != 0) {
        mdb_env_close(ew->env);
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return scope.Close(Undefined());
    }

    ew->Wrap(args.This());
    ew->Ref();
    return args.This();
}

template<class T>
int applyUint32Setting(int (*f)(MDB_env *, T), MDB_env* e, Local<Object> options, T dflt, const char* keyName) {
    int rc;
    const Handle<Value> value = options->Get(String::NewSymbol(keyName));
    if (value->IsUint32()) {
        rc = f(e, value->Uint32Value());
    }
    else {
        rc = f(e, dflt);
    }

    return rc;

}

Handle<Value> EnvWrap::open(const Arguments& args) {
    HandleScope scope;
    int rc;
    int flags = 0;

    // Get the wrapper
    EnvWrap *ew = ObjectWrap::Unwrap<EnvWrap>(args.This());

    if (!ew->env) {
        ThrowException(Exception::Error(String::New("The environment is already closed.")));
        return Undefined();
    }

    Local<Object> options = args[0]->ToObject();
    Local<String> path = options->Get(String::NewSymbol("path"))->ToString();

    // Parse the maxDbs option
    rc = applyUint32Setting<unsigned>(&mdb_env_set_maxdbs, ew->env, options, 1, "maxDbs");
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }

    // Parse the mapSize option
    Handle<Value> mapSizeOption = options->Get(String::NewSymbol("mapSize"));
    if (mapSizeOption->IsNumber()) {
        double mapSizeDouble = mapSizeOption->NumberValue();
        size_t mapSizeSizeT = (size_t) mapSizeDouble;
        rc = mdb_env_set_mapsize(ew->env, mapSizeSizeT);
        if (rc != 0) {
            ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
            return Undefined();
        }
    }

    // Parse the maxDbs option
    rc = applyUint32Setting<unsigned>(&mdb_env_set_maxreaders, ew->env, options, 1, "maxReaders");
    if (rc != 0) {
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }

    // NOTE: MDB_FIXEDMAP is not exposed here since it is "highly experimental" + it is irrelevant for this use case
    // NOTE: MDB_NOTLS is not exposed here because it is irrelevant for this use case, as node will run all this on a single thread anyway
    setFlagFromValue(&flags, MDB_NOSUBDIR, "noSubdir", false, options);
    setFlagFromValue(&flags, MDB_RDONLY, "readOnly", false, options);
    setFlagFromValue(&flags, MDB_WRITEMAP, "useWritemap", false, options);
    setFlagFromValue(&flags, MDB_NOMETASYNC, "noMetaSync", false, options);
    setFlagFromValue(&flags, MDB_NOSYNC, "noSync", false, options);
    setFlagFromValue(&flags, MDB_MAPASYNC, "mapAsync", false, options);

    int l = path->Length();
    char *cpath = new char[l + 1];
    path->WriteAscii(cpath);
    cpath[l] = 0;

    // TODO: make file attributes configurable
    rc = mdb_env_open(ew->env, cpath, flags, 0664);

    if (rc != 0) {
        mdb_env_close(ew->env);
        ew->env = nullptr;
        ThrowException(Exception::Error(String::New(mdb_strerror(rc))));
        return Undefined();
    }

    return Undefined();
}

Handle<Value> EnvWrap::close(const Arguments& args) {
    HandleScope scope;

    EnvWrap *ew = ObjectWrap::Unwrap<EnvWrap>(args.This());
    ew->Unref();

    if (!ew->env) {
        ThrowException(Exception::Error(String::New("The environment is already closed.")));
        return Undefined();
    }

    mdb_env_close(ew->env);
    ew->env = nullptr;

    return scope.Close(Undefined());
}

Handle<Value> EnvWrap::beginTxn(const Arguments& args) {
    HandleScope scope;

    const unsigned argc = 2;
    Handle<Value> argv[argc] = { args.This(), args[0] };
    Local<Object> instance = txnCtor->NewInstance(argc, argv);

    return scope.Close(instance);
}

Handle<Value> EnvWrap::openDbi(const Arguments& args) {
    HandleScope scope;

    const unsigned argc = 2;
    Handle<Value> argv[argc] = { args.This(), args[0] };
    Local<Object> instance = dbiCtor->NewInstance(argc, argv);

    return scope.Close(instance);
}

Handle<Value> EnvWrap::sync(const Arguments &args) {
    HandleScope scope;

    EnvWrap *ew = ObjectWrap::Unwrap<EnvWrap>(args.This());

    if (!ew->env) {
        ThrowException(Exception::Error(String::New("The environment is already closed.")));
        return Undefined();
    }

    Handle<Function> callback = Handle<Function>::Cast(args[0]);

    EnvSyncData *d = new EnvSyncData;
    d->request.data = d;
    d->ew = ew;
    d->env = ew->env;
    d->callback = Persistent<Function>::New(callback);

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
            argv[0] = Null();
        }
        else {
            argv[0] = Exception::Error(String::New(mdb_strerror(d->rc)));
        }

        d->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        d->callback.Dispose();
        delete d;
    });

    return Undefined();
}

void EnvWrap::setupExports(Handle<Object> exports) {
    // EnvWrap: Prepare constructor template
    Local<FunctionTemplate> envTpl = FunctionTemplate::New(EnvWrap::ctor);
    envTpl->SetClassName(String::NewSymbol("Env"));
    envTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // EnvWrap: Add functions to the prototype
    envTpl->PrototypeTemplate()->Set(String::NewSymbol("open"), FunctionTemplate::New(EnvWrap::open)->GetFunction());
    envTpl->PrototypeTemplate()->Set(String::NewSymbol("close"), FunctionTemplate::New(EnvWrap::close)->GetFunction());
    envTpl->PrototypeTemplate()->Set(String::NewSymbol("beginTxn"), FunctionTemplate::New(EnvWrap::beginTxn)->GetFunction());
    envTpl->PrototypeTemplate()->Set(String::NewSymbol("openDbi"), FunctionTemplate::New(EnvWrap::openDbi)->GetFunction());
    envTpl->PrototypeTemplate()->Set(String::NewSymbol("sync"), FunctionTemplate::New(EnvWrap::sync)->GetFunction());
    // TODO: wrap mdb_env_copy too
    // TODO: wrap mdb_env_stat too
    // TODO: wrap mdb_env_info too
    // EnvWrap: Get constructor
    Persistent<Function> envCtor = Persistent<Function>::New(envTpl->GetFunction());

    // TxnWrap: Prepare constructor template
    Local<FunctionTemplate> txnTpl = FunctionTemplate::New(TxnWrap::ctor);
    txnTpl->SetClassName(String::NewSymbol("Txn"));
    txnTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // TxnWrap: Add functions to the prototype
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("commit"), FunctionTemplate::New(TxnWrap::commit)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("abort"), FunctionTemplate::New(TxnWrap::abort)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("getString"), FunctionTemplate::New(TxnWrap::getString)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("getBinary"), FunctionTemplate::New(TxnWrap::getBinary)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("getNumber"), FunctionTemplate::New(TxnWrap::getNumber)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("getBoolean"), FunctionTemplate::New(TxnWrap::getBoolean)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("putString"), FunctionTemplate::New(TxnWrap::putString)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("putBinary"), FunctionTemplate::New(TxnWrap::putBinary)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("putNumber"), FunctionTemplate::New(TxnWrap::putNumber)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("putBoolean"), FunctionTemplate::New(TxnWrap::putBoolean)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("del"), FunctionTemplate::New(TxnWrap::del)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("reset"), FunctionTemplate::New(TxnWrap::reset)->GetFunction());
    txnTpl->PrototypeTemplate()->Set(String::NewSymbol("renew"), FunctionTemplate::New(TxnWrap::renew)->GetFunction());
    // TODO: wrap mdb_cmp too
    // TODO: wrap mdb_dcmp too
    // TxnWrap: Get constructor
    EnvWrap::txnCtor = Persistent<Function>::New(txnTpl->GetFunction());

    // DbiWrap: Prepare constructor template
    Local<FunctionTemplate> dbiTpl = FunctionTemplate::New(DbiWrap::ctor);
    dbiTpl->SetClassName(String::NewSymbol("Dbi"));
    dbiTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // DbiWrap: Add functions to the prototype
    dbiTpl->PrototypeTemplate()->Set(String::NewSymbol("close"), FunctionTemplate::New(DbiWrap::close)->GetFunction());
    dbiTpl->PrototypeTemplate()->Set(String::NewSymbol("drop"), FunctionTemplate::New(DbiWrap::drop)->GetFunction());
    dbiTpl->PrototypeTemplate()->Set(String::NewSymbol("stat"), FunctionTemplate::New(DbiWrap::stat)->GetFunction());
    // TODO: wrap mdb_stat too
    // DbiWrap: Get constructor
    EnvWrap::dbiCtor = Persistent<Function>::New(dbiTpl->GetFunction());

    // Set exports
    exports->Set(String::NewSymbol("Env"), envCtor);
}
