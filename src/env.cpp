
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

#define IGNORE_NOTFOUND    (1)
thread_local Nan::Persistent<Function>* EnvWrap::txnCtor;
thread_local Nan::Persistent<Function>* EnvWrap::dbiCtor;
//Nan::Persistent<Function> EnvWrap::txnCtor;
//Nan::Persistent<Function> EnvWrap::dbiCtor;
uv_mutex_t* EnvWrap::envsLock = EnvWrap::initMutex();
std::vector<env_path_t> EnvWrap::envs;

uv_mutex_t* EnvWrap::initMutex() {
    uv_mutex_t* mutex = new uv_mutex_t;
    uv_mutex_init(mutex);
    return mutex;
}

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
    const Local<Value> value = options->Get(Nan::GetCurrentContext(), Nan::New<String>(keyName).ToLocalChecked()).ToLocalChecked();
    if (value->IsUint32()) {
        rc = f(e, value->Uint32Value(Nan::GetCurrentContext()).FromJust());
    }
    else {
        rc = f(e, dflt);
    }

    return rc;
}

class SyncWorker : public Nan::AsyncWorker {
  public:
    SyncWorker(MDB_env* env, Nan::Callback *callback)
      : Nan::AsyncWorker(callback), env(env) {}

    void Execute() {
        int rc = mdb_env_sync(env, 1);
        if (rc != 0) {
            SetErrorMessage(mdb_strerror(rc));
        }
    }

    void HandleOKCallback() {
        Nan::HandleScope scope;
        v8::Local<v8::Value> argv[] = {
            Nan::Null()
        };

        callback->Call(1, argv, async_resource);
    }

  private:
    MDB_env* env;
};

class CopyWorker : public Nan::AsyncWorker {
  public:
    CopyWorker(MDB_env* env, char* inPath, int flags, Nan::Callback *callback)
      : Nan::AsyncWorker(callback), env(env), flags(flags), path(strdup(inPath)) {
      }
    ~CopyWorker() {
        free(path);
    }

    void Execute() {
        int rc = mdb_env_copy2(env, path, flags);
        if (rc != 0) {
            fprintf(stderr, "Error on copy code: %u\n", rc);
            SetErrorMessage("Error on copy");
        }
    }

    void HandleOKCallback() {
        Nan::HandleScope scope;
        v8::Local<v8::Value> argv[] = {
            Nan::Null()
        };

        callback->Call(1, argv, async_resource);
    }

  private:
    MDB_env* env;
    char* path;
    int flags;
};

struct condition_t {
    MDB_val key;
    MDB_val data;
    MDB_dbi dbi;
    bool matchSize;
    argtokey_callback_t freeKey;
};

struct action_t {
    MDB_val key;
    MDB_val data;
    MDB_dbi dbi;
    condition_t *condition;
    argtokey_callback_t freeKey;
};

int deleteValue; // pointer to this as the value represents a delete

class BatchWorker : public Nan::AsyncProgressWorker {
  public:
    BatchWorker(MDB_env* env, action_t *actions, int actionCount, int putFlags, Nan::Callback *callback, Nan::Callback *progress)
      : Nan::AsyncProgressWorker(callback, "node-lmdb:Batch"),
      actions(actions),
      actionCount(actionCount),
      putFlags(putFlags),
      env(env),
      progress(progress) {
        results = new int[actionCount];
    }

    ~BatchWorker() {
        for (int i = 0; i < actionCount; i++) {
            action_t* action = &actions[i];
            condition_t* condition = action->condition;
            if (condition) {
                delete condition;
            }
        }
        delete[] actions;
        delete[] results;
        delete progress;
    }

    void Execute(const ExecutionProgress& executionProgress) {
        MDB_txn *txn;
        int rc = mdb_txn_begin(env, nullptr, 0, &txn);
        if (rc != 0) {
            return SetErrorMessage(mdb_strerror(rc));
        }
        int getCount = 0;

        for (int i = 0; i < actionCount;) {
            action_t* action = &actions[i];
            condition_t* condition = action->condition;
            if (condition) {
                MDB_val value;
                rc = mdb_get(txn, condition->dbi, &condition->key, &value);
                bool different;
                if (condition->data.mv_data == &deleteValue) {
                    different = !rc;
                } else {
                    if (rc) {
                        different = rc == MDB_NOTFOUND;
                    } else {
                        different = (condition->matchSize ? value.mv_size != condition->data.mv_size : value.mv_size < condition->data.mv_size) ||
                        memcmp(value.mv_data, condition->data.mv_data, condition->data.mv_size);
                    }
                }
                if (different) {
                    results[i] = 1;
                } else {
                    // condition matches, remove condition, same as having no condition
                    condition = nullptr;
                    results[i] = 0;
                }
                rc = 0;
            } else {
                results[i] = 0;
            }
            if (condition) {
                rc = 0; // make sure this gets set back to zero, failed conditions shouldn't trigger error
            } else {
                if (action->data.mv_data == &deleteValue) {
                    rc = mdb_del(txn, action->dbi, &action->key, nullptr);
                    if (rc == MDB_NOTFOUND) {
                        rc = 0; // ignore not_found errors
                        results[i] = 2;
                    }
                } else {
                    rc = mdb_put(txn, action->dbi, &action->key, &action->data, putFlags);
                }
            }

            if (action->freeKey) { // if we created a key and needs to be cleaned up, do it now
                action->freeKey(action->key);
            }
            if (rc != 0) {
                if (rc == MDB_BAD_VALSIZE)
                    results[i] = 3;
                else {
                    mdb_txn_abort(txn);
                    return SetErrorMessage(mdb_strerror(rc));
                }
            }
            i++;
            if (progress) { // let node know that progress updates are available
                executionProgress.Send(reinterpret_cast<const char*>(&i), sizeof(int));
            }
        }

        rc = mdb_txn_commit(txn);
        if (rc != 0) {
            return SetErrorMessage(mdb_strerror(rc));
        }
    }

    v8::Local<v8::Array> updatedResultsArray(int currentIndex) {
        v8::Local<v8::Array> resultsArray;
        if (hasResultsArray) {
            resultsArray = v8::Local<v8::Array>::Cast(GetFromPersistent("results"));
        } else {
            resultsArray = Nan::New<v8::Array>(actionCount);
            SaveToPersistent("results", resultsArray);
            hasResultsArray = true;
        }
        Local<Context> context = Nan::GetCurrentContext();
        for (; resultIndex < currentIndex; resultIndex++) {
            resultsArray->Set(context, resultIndex, Nan::New<Number>(results[resultIndex]));
        }
        return resultsArray;
    }

    void HandleProgressCallback(const char *data, size_t count) {
        Nan::HandleScope scope;
        v8::Local<v8::Value> argv[] = {
            updatedResultsArray(*reinterpret_cast<int*>(const_cast<char*>(data)))
        };

        progress->Call(1, argv, async_resource);
    }

    void HandleOKCallback() {
        Nan::HandleScope scope;
        v8::Local<v8::Value> argv[] = {
            Nan::Null(),
            updatedResultsArray(actionCount)
        };

        callback->Call(2, argv, async_resource);
    }

  private:
    MDB_env* env;
    int actionCount;
    int* results;
    int resultIndex = 0;
    bool hasResultsArray = false;
    action_t* actions;
    int putFlags;
    Nan::Callback* progress;
};



NAN_METHOD(EnvWrap::open) {
    Nan::HandleScope scope;

    int rc;
    int flags = 0;

    // Get the wrapper
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());

    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }

    Local<Object> options = Local<Object>::Cast(info[0]);
    Local<String> path = Local<String>::Cast(options->Get(Nan::GetCurrentContext(), Nan::New<String>("path").ToLocalChecked()).ToLocalChecked());
    Nan::Utf8String charPath(path);
    uv_mutex_lock(envsLock);
    for (env_path_t envPath : envs) {
        char* existingPath = envPath.path;
        if (!strcmp(existingPath, *charPath)) {
            envPath.count++;
            mdb_env_close(ew->env);
            ew->env = envPath.env;
            uv_mutex_unlock(envsLock);
            return;
        }
    }

    // Parse the maxDbs option
    rc = applyUint32Setting<unsigned>(&mdb_env_set_maxdbs, ew->env, options, 1, "maxDbs");
    if (rc != 0) {
        uv_mutex_unlock(envsLock);
        return throwLmdbError(rc);
    }

    // Parse the mapSize option
    Local<Value> mapSizeOption = options->Get(Nan::GetCurrentContext(), Nan::New<String>("mapSize").ToLocalChecked()).ToLocalChecked();
    if (mapSizeOption->IsNumber()) {
        mdb_size_t mapSizeSizeT = mapSizeOption->IntegerValue(Nan::GetCurrentContext()).FromJust();
        rc = mdb_env_set_mapsize(ew->env, mapSizeSizeT);
        if (rc != 0) {
            uv_mutex_unlock(envsLock);
            return throwLmdbError(rc);
        }
    }

    // Parse the maxReaders option
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
    setFlagFromValue(&flags, MDB_PREVSNAPSHOT, "usePreviousSnapshot", false, options);
    setFlagFromValue(&flags, MDB_NOMEMINIT , "noMemInit", false, options);
    setFlagFromValue(&flags, MDB_NORDAHEAD , "noReadAhead", false, options);
    setFlagFromValue(&flags, MDB_NOMETASYNC, "noMetaSync", false, options);
    setFlagFromValue(&flags, MDB_NOSYNC, "noSync", false, options);
    setFlagFromValue(&flags, MDB_MAPASYNC, "mapAsync", false, options);
    setFlagFromValue(&flags, MDB_NOLOCK, "unsafeNoLock", false, options);

    if (flags & MDB_NOLOCK) {
        fprintf(stderr, "You chose to use MDB_NOLOCK which is not officially supported by node-lmdb. You have been warned!\n");
    }

    // Set MDB_NOTLS to enable multiple read-only transactions on the same thread (in this case, the nodejs main thread)
    flags |= MDB_NOTLS;

    // TODO: make file attributes configurable
    #if NODE_VERSION_AT_LEAST(12,0,0)
    rc = mdb_env_open(ew->env, *String::Utf8Value(Isolate::GetCurrent(), path), flags, 0664);
    #else
    rc = mdb_env_open(ew->env, *String::Utf8Value(path), flags, 0664);
    #endif;

    if (rc != 0) {
        mdb_env_close(ew->env);
        uv_mutex_unlock(envsLock);
        ew->env = nullptr;
        return throwLmdbError(rc);
    }
    env_path_t envPath;
    envPath.path = strdup(*charPath);
    envPath.env = ew->env;
    envPath.count = 1;
    envs.push_back(envPath);
    uv_mutex_unlock(envsLock);
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

    mdb_size_t mapSizeSizeT = info[0]->IntegerValue(Nan::GetCurrentContext()).FromJust();
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

    uv_mutex_lock(envsLock);
    for (auto envPath = envs.begin(); envPath != envs.end(); ) {
        if (envPath->env == ew->env) {
            envPath->count--;
            if (envPath->count <= 0) {
                // last thread using it, we can really close it now
                envs.erase(envPath);
                mdb_env_close(ew->env);
            }
            break;
        }
        ++envPath;
    }
    uv_mutex_unlock(envsLock);

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

    Local<Context> context = Nan::GetCurrentContext();
    Local<Object> obj = Nan::New<Object>();
    obj->Set(context, Nan::New<String>("pageSize").ToLocalChecked(), Nan::New<Number>(stat.ms_psize));
    obj->Set(context, Nan::New<String>("treeDepth").ToLocalChecked(), Nan::New<Number>(stat.ms_depth));
    obj->Set(context, Nan::New<String>("treeBranchPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_branch_pages));
    obj->Set(context, Nan::New<String>("treeLeafPageCount").ToLocalChecked(), Nan::New<Number>(stat.ms_leaf_pages));
    obj->Set(context, Nan::New<String>("entryCount").ToLocalChecked(), Nan::New<Number>(stat.ms_entries));

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

    Local<Context> context = Nan::GetCurrentContext();
    Local<Object> obj = Nan::New<Object>();
    obj->Set(context, Nan::New<String>("mapAddress").ToLocalChecked(), Nan::New<Number>((uint64_t) envinfo.me_mapaddr));
    obj->Set(context, Nan::New<String>("mapSize").ToLocalChecked(), Nan::New<Number>(envinfo.me_mapsize));
    obj->Set(context, Nan::New<String>("lastPageNumber").ToLocalChecked(), Nan::New<Number>(envinfo.me_last_pgno));
    obj->Set(context, Nan::New<String>("lastTxnId").ToLocalChecked(), Nan::New<Number>(envinfo.me_last_txnid));
    obj->Set(context, Nan::New<String>("maxReaders").ToLocalChecked(), Nan::New<Number>(envinfo.me_maxreaders));
    obj->Set(context, Nan::New<String>("numReaders").ToLocalChecked(), Nan::New<Number>(envinfo.me_numreaders));

    info.GetReturnValue().Set(obj);
}

NAN_METHOD(EnvWrap::copy) {
    Nan::HandleScope scope;

    // Get the wrapper
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());

    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }

    // Check that the correct number/type of arguments was given.
    if (!info[0]->IsString()) {
        return Nan::ThrowError("Call env.copy(path, compact?, callback) with a file path.");
    }
    if (!info[info.Length() - 1]->IsFunction()) {
        return Nan::ThrowError("Call env.copy(path, compact?, callback) with a file path.");
    }
    Nan::Utf8String path(info[0].As<String>());

    int flags = 0;
    if (info.Length() > 1 && info[1]->IsTrue()) {
        flags = MDB_CP_COMPACT;
    }

    Nan::Callback* callback = new Nan::Callback(
      v8::Local<v8::Function>::Cast(info[info.Length()  > 2 ? 2 : 1])
    );

    CopyWorker* worker = new CopyWorker(
      ew->env, *path, flags, callback
    );

    Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(EnvWrap::detachBuffer) {
    Nan::HandleScope scope;
    #if NODE_VERSION_AT_LEAST(12,0,0)
    Local<v8::ArrayBuffer>::Cast(info[0])->Detach();
    #endif
}

NAN_METHOD(EnvWrap::beginTxn) {
    Nan::HandleScope scope;

    const int argc = 2;

    Local<Value> argv[argc] = { info.This(), info[0] };
    Nan::MaybeLocal<Object> maybeInstance = Nan::NewInstance(Nan::New(*txnCtor), argc, argv);

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
    Nan::MaybeLocal<Object> maybeInstance = Nan::NewInstance(Nan::New(*dbiCtor), argc, argv);

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

    Nan::Callback* callback = new Nan::Callback(
      v8::Local<v8::Function>::Cast(info[0])
    );

    SyncWorker* worker = new SyncWorker(
      ew->env, callback
    );

    Nan::AsyncQueueWorker(worker);
    return;
}


NAN_METHOD(EnvWrap::batchWrite) {
    Nan::HandleScope scope;

    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());
    Local<Context> context = Nan::GetCurrentContext();

    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }
    v8::Local<v8::Array> array = v8::Local<v8::Array>::Cast(info[0]);

    int length = array->Length();
    action_t* actions = new action_t[length];

    int putFlags = 0;
    Nan::Callback* callback;
    Nan::Callback* progress = nullptr;
    Local<Value> options = info[1];

    if (!info[1]->IsNull() && !info[1]->IsUndefined() && info[1]->IsObject() && !info[1]->IsFunction()) {
        Local<Object> optionsObject = Local<Object>::Cast(options);
        setFlagFromValue(&putFlags, MDB_NODUPDATA, "noDupData", false, optionsObject);
        setFlagFromValue(&putFlags, MDB_NOOVERWRITE, "noOverwrite", false, optionsObject);
        setFlagFromValue(&putFlags, MDB_APPEND, "append", false, optionsObject);
        setFlagFromValue(&putFlags, MDB_APPENDDUP, "appendDup", false, optionsObject);

        Local<Value> progressValue = optionsObject->Get(context, Nan::New<String>("progress").ToLocalChecked()).ToLocalChecked();
        if (progressValue->IsFunction()) {
            progress = new Nan::Callback(v8::Local<v8::Function>::Cast(progressValue));
        }
        callback = new Nan::Callback(
            v8::Local<v8::Function>::Cast(info[2])
        );
    } else {
        callback = new Nan::Callback(
            v8::Local<v8::Function>::Cast(info[1])
        );
    }

    BatchWorker* worker = new BatchWorker(
        ew->env, actions, length, putFlags, callback, progress
    );
    int persistedIndex = 0;
    bool keyIsValid = false;
    NodeLmdbKeyType keyType;

    for (unsigned int i = 0; i < array->Length(); i++) {
        if (!array->Get(context, i).ToLocalChecked()->IsObject())
            continue;
        action_t* action = &actions[i];
        v8::Local<v8::Object> operation = v8::Local<v8::Object>::Cast(array->Get(context, i).ToLocalChecked());

        bool isArray = operation->IsArray();
        DbiWrap *dw = Nan::ObjectWrap::Unwrap<DbiWrap>(v8::Local<v8::Object>::Cast((isArray ? operation->Get(context, 0) : operation->Get(context, Nan::New<String>("db").ToLocalChecked())).ToLocalChecked()));
        action->dbi = dw->dbi;
        v8::Local<v8::Value> key = (isArray ? operation->Get(context, 1) : operation->Get(context, Nan::New<String>("key").ToLocalChecked())).ToLocalChecked();
        
        if (!keyIsValid) {
            // just execute this the first time so we didn't need to re-execute for each iteration
            keyType = inferAndValidateKeyType(key, options, dw->keyType, keyIsValid);
            if (!keyIsValid) {
                // inferAndValidateKeyType already threw an error
                return;
            }
        }
        action->freeKey = argToKey(key, action->key, keyType, keyIsValid);
        if (!keyIsValid) {
            // argToKey already threw an error
            return;
        }
        // persist the reference until we are done with the operation
        worker->SaveToPersistent(persistedIndex++, key);
        v8::Local<v8::Value> value = (isArray ? operation->Get(context, 2) : operation->Get(context, Nan::New<String>("value").ToLocalChecked())).ToLocalChecked();

        // check if this is a conditional save
        v8::Local<v8::Value> ifValue = (isArray ? operation->Get(context, 3) : operation->Get(context, Nan::New<String>("ifValue").ToLocalChecked())).ToLocalChecked();
        if (!ifValue->IsUndefined()) {
            condition_t *condition = action->condition = new condition_t();

            if (ifValue->IsNull()) {
                condition->data.mv_data = &deleteValue;
            } else if (ifValue->IsArrayBufferView()) {
                condition->data.mv_size = node::Buffer::Length(ifValue);
                condition->data.mv_data = node::Buffer::Data(ifValue);
                if (!isArray) {
                    v8::Local<v8::Value> ifExactMatch = operation->Get(context, Nan::New<String>("ifExactMatch").ToLocalChecked()).ToLocalChecked();
                    if (ifExactMatch->IsTrue()) {
                        condition->matchSize = true;
                    }
                }
            } else {
                return Nan::ThrowError("The ifValue must be a buffer or null/undefined.");
            }
            if (isArray) {
                condition->dbi = action->dbi;
                condition->key = action->key;
            } else {
                v8::Local<v8::Value> ifDB = operation->Get(context, Nan::New<String>("ifDB").ToLocalChecked()).ToLocalChecked();
                if (ifDB->IsNull() || ifDB->IsUndefined()) {
                    condition->dbi = action->dbi;
                } else if (ifDB->IsObject()) {
                    dw = Nan::ObjectWrap::Unwrap<DbiWrap>(v8::Local<v8::Object>::Cast((isArray ? operation->Get(context, 0) : operation->Get(Nan::GetCurrentContext(), Nan::New<String>("ifDB").ToLocalChecked())).ToLocalChecked()));
                    condition->dbi = dw->dbi;
                } else {
                    return Nan::ThrowError("The ifDB must be a database object or null/undefined.");
                }
                v8::Local<v8::Value> ifKey = operation->Get(context, Nan::New<String>("ifKey").ToLocalChecked()).ToLocalChecked();
                if (ifKey->IsNull() || ifKey->IsUndefined()) {
                    condition->key = action->key;
                } else {
                    condition->freeKey = argToKey(ifKey, condition->key, keyType, keyIsValid);
                    if (!keyIsValid) {
                        // argToKey already threw an error
                        return;
                    }
                    worker->SaveToPersistent(persistedIndex++, ifKey);
                }
            }
            worker->SaveToPersistent(persistedIndex++, ifValue);
        } else {
            action->condition = nullptr;
        }

        if (value->IsNull() || value->IsUndefined()) {
            action->data.mv_data = &deleteValue;
        } else if (value->IsArrayBufferView()) {
            action->data.mv_size = node::Buffer::Length(value);
            action->data.mv_data = node::Buffer::Data(value);
            // likewise persist value if needed too
            worker->SaveToPersistent(persistedIndex++, value);
        } else {
            return Nan::ThrowError("The value must be a buffer or null/undefined.");
        }
    }

    worker->SaveToPersistent("env", info.This());

    Nan::AsyncQueueWorker(worker);
    return;
}



void EnvWrap::setupExports(Local<Object> exports) {
    // EnvWrap: Prepare constructor template
    Local<FunctionTemplate> envTpl = Nan::New<FunctionTemplate>(EnvWrap::ctor);
    envTpl->SetClassName(Nan::New<String>("Env").ToLocalChecked());
    envTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // EnvWrap: Add functions to the prototype
    Isolate *isolate = Isolate::GetCurrent();
    envTpl->PrototypeTemplate()->Set(isolate, "open", Nan::New<FunctionTemplate>(EnvWrap::open));
    envTpl->PrototypeTemplate()->Set(isolate, "close", Nan::New<FunctionTemplate>(EnvWrap::close));
    envTpl->PrototypeTemplate()->Set(isolate, "beginTxn", Nan::New<FunctionTemplate>(EnvWrap::beginTxn));
    envTpl->PrototypeTemplate()->Set(isolate, "openDbi", Nan::New<FunctionTemplate>(EnvWrap::openDbi));
    envTpl->PrototypeTemplate()->Set(isolate, "sync", Nan::New<FunctionTemplate>(EnvWrap::sync));
    envTpl->PrototypeTemplate()->Set(isolate, "batchWrite", Nan::New<FunctionTemplate>(EnvWrap::batchWrite));
    envTpl->PrototypeTemplate()->Set(isolate, "stat", Nan::New<FunctionTemplate>(EnvWrap::stat));
    envTpl->PrototypeTemplate()->Set(isolate, "info", Nan::New<FunctionTemplate>(EnvWrap::info));
    envTpl->PrototypeTemplate()->Set(isolate, "resize", Nan::New<FunctionTemplate>(EnvWrap::resize));
    envTpl->PrototypeTemplate()->Set(isolate, "copy", Nan::New<FunctionTemplate>(EnvWrap::copy));
    envTpl->PrototypeTemplate()->Set(isolate, "detachBuffer", Nan::New<FunctionTemplate>(EnvWrap::detachBuffer));

    // TxnWrap: Prepare constructor template
    Local<FunctionTemplate> txnTpl = Nan::New<FunctionTemplate>(TxnWrap::ctor);
    txnTpl->SetClassName(Nan::New<String>("Txn").ToLocalChecked());
    txnTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // TxnWrap: Add functions to the prototype
    txnTpl->PrototypeTemplate()->Set(isolate, "commit", Nan::New<FunctionTemplate>(TxnWrap::commit));
    txnTpl->PrototypeTemplate()->Set(isolate, "abort", Nan::New<FunctionTemplate>(TxnWrap::abort));
    txnTpl->PrototypeTemplate()->Set(isolate, "getString", Nan::New<FunctionTemplate>(TxnWrap::getString));
    txnTpl->PrototypeTemplate()->Set(isolate, "getStringUnsafe", Nan::New<FunctionTemplate>(TxnWrap::getStringUnsafe));
    txnTpl->PrototypeTemplate()->Set(isolate, "getBinary", Nan::New<FunctionTemplate>(TxnWrap::getBinary));
    txnTpl->PrototypeTemplate()->Set(isolate, "getBinaryUnsafe", Nan::New<FunctionTemplate>(TxnWrap::getBinaryUnsafe));
    txnTpl->PrototypeTemplate()->Set(isolate, "getNumber", Nan::New<FunctionTemplate>(TxnWrap::getNumber));
    txnTpl->PrototypeTemplate()->Set(isolate, "getBoolean", Nan::New<FunctionTemplate>(TxnWrap::getBoolean));
    txnTpl->PrototypeTemplate()->Set(isolate, "putString", Nan::New<FunctionTemplate>(TxnWrap::putString));
    txnTpl->PrototypeTemplate()->Set(isolate, "putBinary", Nan::New<FunctionTemplate>(TxnWrap::putBinary));
    txnTpl->PrototypeTemplate()->Set(isolate, "putNumber", Nan::New<FunctionTemplate>(TxnWrap::putNumber));
    txnTpl->PrototypeTemplate()->Set(isolate, "putBoolean", Nan::New<FunctionTemplate>(TxnWrap::putBoolean));
    txnTpl->PrototypeTemplate()->Set(isolate, "del", Nan::New<FunctionTemplate>(TxnWrap::del));
    txnTpl->PrototypeTemplate()->Set(isolate, "reset", Nan::New<FunctionTemplate>(TxnWrap::reset));
    txnTpl->PrototypeTemplate()->Set(isolate, "renew", Nan::New<FunctionTemplate>(TxnWrap::renew));
    // TODO: wrap mdb_cmp too
    // TODO: wrap mdb_dcmp too
    // TxnWrap: Get constructor
    EnvWrap::txnCtor = new Nan::Persistent<Function>();
    EnvWrap::txnCtor->Reset( txnTpl->GetFunction(Nan::GetCurrentContext()).ToLocalChecked());

    // DbiWrap: Prepare constructor template
    Local<FunctionTemplate> dbiTpl = Nan::New<FunctionTemplate>(DbiWrap::ctor);
    dbiTpl->SetClassName(Nan::New<String>("Dbi").ToLocalChecked());
    dbiTpl->InstanceTemplate()->SetInternalFieldCount(1);
    // DbiWrap: Add functions to the prototype
    dbiTpl->PrototypeTemplate()->Set(isolate, "close", Nan::New<FunctionTemplate>(DbiWrap::close));
    dbiTpl->PrototypeTemplate()->Set(isolate, "drop", Nan::New<FunctionTemplate>(DbiWrap::drop));
    dbiTpl->PrototypeTemplate()->Set(isolate, "stat", Nan::New<FunctionTemplate>(DbiWrap::stat));
    // TODO: wrap mdb_stat too
    // DbiWrap: Get constructor
    EnvWrap::dbiCtor = new Nan::Persistent<Function>();
    EnvWrap::dbiCtor->Reset( dbiTpl->GetFunction(Nan::GetCurrentContext()).ToLocalChecked());

    // Set exports
    exports->Set(Nan::GetCurrentContext(), Nan::New<String>("Env").ToLocalChecked(), envTpl->GetFunction(Nan::GetCurrentContext()).ToLocalChecked());
}
