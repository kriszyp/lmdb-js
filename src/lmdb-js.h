
// This file is part of lmdb-js
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

#ifndef NODE_LMDB_H
#define NODE_LMDB_H

#include <vector>
#include <algorithm>
#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include <nan.h>
#include "lmdb.h"
#include "lz4.h"
#ifdef MDB_RPAGE_CACHE
#include "chacha8.h"
#endif
#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
#if NODE_VERSION_AT_LEAST(17,0,0)
#include "../dependencies/v8/v8-fast-api-calls.h"
#else
#include "../dependencies/v8/v8-fast-api-calls-v16.h"
#endif
#endif

using namespace v8;
using namespace node;



#ifndef __CPTHREAD_H__
#define __CPTHREAD_H__

#ifdef _WIN32
#define EXTERN __declspec(dllexport)
# else
#define EXTERN __attribute__((visibility("default")))
#endif

#ifdef _WIN32
# include <windows.h>
#else
# include <pthread.h>
#endif

#ifdef _WIN32
typedef CRITICAL_SECTION pthread_mutex_t;
typedef void pthread_mutexattr_t;
typedef void pthread_condattr_t;
typedef HANDLE pthread_t;
typedef CONDITION_VARIABLE pthread_cond_t;

#endif

#ifdef _WIN32

int pthread_mutex_init(pthread_mutex_t *mutex, pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);

int pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);

#endif

int cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, uint64_t ns);

#endif /* __CPTHREAD_H__ */

class Logging {
  public:
    static int debugLogging;
    static int initLogging();
};

enum class LmdbKeyType {

    // Invalid key (used internally by lmdb-js)
    InvalidKey = -1,
    
    // Default key (used internally by lmdb-js)
    DefaultKey = 0,

    // UCS-2/UTF-16 with zero terminator - Appears to V8 as string
    StringKey = 1,
    
    // LMDB fixed size integer key with 32 bit keys - Appearts to V8 as an Uint32
    Uint32Key = 2,
    
    // LMDB default key format - Appears to V8 as node::Buffer
    BinaryKey = 3,

};
enum class KeyCreation {
    Reset = 0,
    Continue = 1,
    InArray = 2,
};
const int THEAD_MEMORY_THRESHOLD = 4000;

class TxnWrap;
class DbiWrap;
class EnvWrap;
class CursorWrap;
class Compression;

// Exports misc stuff to the module
void setupExportMisc(Local<Object> exports);

// Helper callback
typedef void (*argtokey_callback_t)(MDB_val &key);

void consoleLog(Local<Value> val);
void consoleLog(const char *msg);
void consoleLogN(int n);
void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Local<Object> options);
void writeValueToEntry(const Local<Value> &str, MDB_val *val);
LmdbKeyType keyTypeFromOptions(const Local<Value> &val, LmdbKeyType defaultKeyType = LmdbKeyType::DefaultKey);
bool getVersionAndUncompress(MDB_val &data, DbiWrap* dw);
int compareFast(const MDB_val *a, const MDB_val *b);
NAN_METHOD(setGlobalBuffer);
NAN_METHOD(lmdbError);
//NAN_METHOD(getBufferForAddress);
NAN_METHOD(getViewAddress);
NAN_METHOD(getAddress);
NAN_METHOD(clearKeptObjects);
NAN_METHOD(lmdbNativeFunctions);

#ifndef thread_local
#ifdef __GNUC__
# define thread_local __thread
#elif __STDC_VERSION__ >= 201112L
# define thread_local _Thread_local
#elif defined(_MSC_VER)
# define thread_local __declspec(thread)
#else
# define thread_local
#endif
#endif

bool valToBinaryFast(MDB_val &data, DbiWrap* dw);
Local<Value> valToUtf8(MDB_val &data);
Local<Value> valToString(MDB_val &data);
Local<Value> valToStringUnsafe(MDB_val &data);
Local<Value> valToBinary(MDB_val &data);
Local<Value> valToBinaryUnsafe(MDB_val &data, DbiWrap* dw);

int putWithVersion(MDB_txn *   txn,
        MDB_dbi     dbi,
        MDB_val *   key,
        MDB_val *   data,
        unsigned int    flags, double version);

void throwLmdbError(int rc);

class TxnWrap;
class DbiWrap;
class EnvWrap;
class CursorWrap;
struct env_path_t {
    MDB_env* env;
    char* path;
    int count;
};

const int INTERRUPT_BATCH = 9998;
const int ALLOW_COMMIT = 9997;
const int RESTART_WORKER_TXN = 9999;
const int RESUME_BATCH = 9996;
const int USER_HAS_LOCK = 9995;
const int SEPARATE_FLUSHED = 1;
const int DELETE_ON_CLOSE = 2;

class WriteWorker {
  public:
    WriteWorker(MDB_env* env, EnvWrap* envForTxn, uint32_t* instructions);
    void Write();
    MDB_txn* txn;
    MDB_txn* AcquireTxn(int* flags);
    void UnlockTxn();
    int WaitForCallbacks(MDB_txn** txn, bool allowCommit, uint32_t* target);
    virtual void ReportError(const char* error);
    virtual void SendUpdate();
    int interruptionStatus;
    bool finishedProgress;
    bool hasError;
    EnvWrap* envForTxn;
    virtual ~WriteWorker();
    uint32_t* instructions;
    int progressStatus;
    MDB_env* env;
};
class NanWriteWorker : public WriteWorker, public Nan::AsyncProgressWorker {
  public:
    NanWriteWorker(MDB_env* env, EnvWrap* envForTxn, uint32_t* instructions, Nan::Callback *callback);
    void Execute(const ExecutionProgress& executionProgress);
    void HandleProgressCallback(const char* data, size_t count);
    void HandleOKCallback();
    void ReportError(const char* error);
    void SendUpdate();
  private:
    ExecutionProgress* executionProgress;
};
class TxnTracked {
  public:
    TxnTracked(MDB_txn *txn, unsigned int flags);
    ~TxnTracked();
    unsigned int flags;
    MDB_txn *txn;
    TxnTracked *parent;
};

/*
    `Env`
    Represents a database environment.
    (Wrapper for `MDB_env`)
*/
class EnvWrap : public Nan::ObjectWrap {
private:
    // List of open read transactions
    std::vector<TxnWrap*> readTxns;
    // Constructor for TxnWrap
    static thread_local Nan::Persistent<Function>* txnCtor;
    // Constructor for DbiWrap
    static thread_local Nan::Persistent<Function>* dbiCtor;
    static pthread_mutex_t* envsLock;
    static std::vector<env_path_t> envs;
    static pthread_mutex_t* initMutex();
    // compression settings and space
    Compression *compression;

    // Cleans up stray transactions
    void cleanupStrayTxns();

    friend class TxnWrap;
    friend class DbiWrap;

public:
    EnvWrap();
    ~EnvWrap();
    // The wrapped object
    MDB_env *env;
    // Current write transaction
    TxnWrap *currentWriteTxn;
    TxnTracked *writeTxn;
    pthread_mutex_t* writingLock;
    pthread_cond_t* writingCond;

    MDB_txn* currentReadTxn;
    WriteWorker* writeWorker;
    bool readTxnRenewed;
    unsigned int jsFlags;
    char* keyBuffer;
    int pageSize;
    MDB_txn* getReadTxn();

    // Sets up exports for the Env constructor
    static void setupExports(Local<Object> exports);
    void closeEnv();
    int openEnv(int flags, int jsFlags, const char* path, char* keyBuffer, Compression* compression, int maxDbs,
        int maxReaders, mdb_size_t mapSize, int pageSize, char* encryptionKey);
    
    /*
        Constructor of the database environment. You need to `open()` it before you can use it.
        (Wrapper for `mdb_env_create`)
    */
    static NAN_METHOD(ctor);
    
    /*
        Gets statistics about the database environment.
    */
    static NAN_METHOD(stat);

    /*
        Gets statistics about the free space database
    */
    static NAN_METHOD(freeStat);
    
    /*
        Detaches a buffer from the backing store
    */
    static NAN_METHOD(detachBuffer);

    /*
        Gets information about the database environment.
    */
    static NAN_METHOD(info);
    /*
        Check for stale readers
    */
    static NAN_METHOD(readerCheck);
    /*
        Print a list of readers
    */
    static NAN_METHOD(readerList);

    /*
        Opens the database environment with the specified options. The options will be used to configure the environment before opening it.
        (Wrapper for `mdb_env_open`)

        Parameters:

        * Options object that contains possible configuration options.

        Possible options are:

        * maxDbs: the maximum number of named databases you can have in the environment (default is 1)
        * maxReaders: the maximum number of concurrent readers of the environment (default is 126)
        * mapSize: maximal size of the memory map (the full environment) in bytes (default is 10485760 bytes)
        * path: path to the database environment
    */
    static NAN_METHOD(open);
    static NAN_METHOD(getMaxKeySize);

    /*
        Resizes the maximal size of the memory map. It may be called if no transactions are active in this process.
        (Wrapper for `mdb_env_set_mapsize`)

        Parameters:

        * maximal size of the memory map (the full environment) in bytes (default is 10485760 bytes)
    */
    static NAN_METHOD(resize);

    /*
        Copies the database environment to a file.
        (Wrapper for `mdb_env_copy2`)

        Parameters:

        * path - Path to the target file
        * compact (optional) - Copy using compact setting
        * callback - Callback when finished (this is performed asynchronously)
    */
    static NAN_METHOD(copy);    

    /*
        Closes the database environment.
        (Wrapper for `mdb_env_close`)
    */
    static NAN_METHOD(close);

    /*
        Starts a new transaction in the environment.
        (Wrapper for `mdb_txn_begin`)

        Parameters:

        * Options object that contains possible configuration options.

        Possible options are:

        * readOnly: if true, the transaction is read-only
    */
    static NAN_METHOD(beginTxn);
    static NAN_METHOD(commitTxn);
    static NAN_METHOD(abortTxn);

    /*
        Opens a database in the environment.
        (Wrapper for `mdb_dbi_open`)

        Parameters:

        * Options object that contains possible configuration options.

        Possible options are:

        * name: the name of the database (or null to use the unnamed database)
        * create: if true, the database will be created if it doesn't exist
        * keyIsUint32: if true, keys are treated as 32-bit unsigned integers
        * dupSort: if true, the database can hold multiple items with the same key
        * reverseKey: keys are strings to be compared in reverse order
        * dupFixed: if dupSort is true, indicates that the data items are all the same size
        * integerDup: duplicate data items are also integers, and should be sorted as such
        * reverseDup: duplicate data items should be compared as strings in reverse order
    */
    static NAN_METHOD(openDbi);

    /*
        Flushes all data to the disk asynchronously.
        (Asynchronous wrapper for `mdb_env_sync`)

        Parameters:

        * Callback to be executed after the sync is complete.
    */
    static NAN_METHOD(sync);

    /*
        Performs a set of operations asynchronously, automatically wrapping it in its own transaction

        Parameters:

        * Callback to be executed after the sync is complete.
    */
    static NAN_METHOD(startWriting);
    static NAN_METHOD(compress);
#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
    static void writeFast(Local<Object> receiver_obj, uint64_t instructionAddress, FastApiCallbackOptions& options);
#endif
    static void write(const v8::FunctionCallbackInfo<v8::Value>& info);

    static NAN_METHOD(resetCurrentReadTxn);
};

const int TXN_ABORTABLE = 1;
const int TXN_SYNCHRONOUS_COMMIT = 2;
const int TXN_FROM_WORKER = 4;

/*
    `Txn`
    Represents a transaction running on a database environment.
    (Wrapper for `MDB_txn`)
*/
class TxnWrap : public Nan::ObjectWrap {
private:

    // Reference to the MDB_env of the wrapped MDB_txn
    MDB_env *env;

    // Environment wrapper of the current transaction
    EnvWrap *ew;
    // parent TW, if it is exists
    TxnWrap *parentTw;
    
    // Flags used with mdb_txn_begin
    unsigned int flags;

    friend class CursorWrap;
    friend class DbiWrap;
    friend class EnvWrap;

public:
    TxnWrap(MDB_env *env, MDB_txn *txn);
    ~TxnWrap();

    // The wrapped object
    MDB_txn *txn;

    // Remove the current TxnWrap from its EnvWrap
    void removeFromEnvWrap();
    int begin(EnvWrap *ew, unsigned int flags);

    // Constructor (not exposed)
    static NAN_METHOD(ctor);

    /*
        Commits the transaction.
        (Wrapper for `mdb_txn_commit`)
    */
    static NAN_METHOD(commit);

    /*
        Aborts the transaction.
        (Wrapper for `mdb_txn_abort`)
    */
    static NAN_METHOD(abort);

    /*
        Aborts a read-only transaction but makes it renewable with `renew`.
        (Wrapper for `mdb_txn_reset`)
    */
    static NAN_METHOD(reset);
    void reset();
    /*
        Renews a read-only transaction after it has been reset.
        (Wrapper for `mdb_txn_renew`)
    */
    static NAN_METHOD(renew);

};

const int HAS_VERSIONS = 0x1000;
/*
    `Dbi`
    Represents a database instance in an environment.
    (Wrapper for `MDB_dbi`)
*/
class DbiWrap : public Nan::ObjectWrap {
public:
    // Tells how keys should be treated
    LmdbKeyType keyType;
    // Stores flags set when opened
    int flags;
    // The wrapped object
    MDB_dbi dbi;
    // Reference to the MDB_env of the wrapped MDB_dbi
    MDB_env *env;
    // The EnvWrap object of the current Dbi
    EnvWrap *ew;
    // Whether the Dbi was opened successfully
    bool isOpen;
    // compression settings and space
    Compression* compression;
    // versions stored in data
    bool hasVersions;
    // current unsafe buffer for this db
    bool getFast;

    friend class TxnWrap;
    friend class CursorWrap;
    friend class EnvWrap;

    DbiWrap(MDB_env *env, MDB_dbi dbi);
    ~DbiWrap();

    // Constructor (not exposed)
    static NAN_METHOD(ctor);

    /*
        Closes the database instance.
        Wrapper for `mdb_dbi_close`)
    */
    static NAN_METHOD(close);

    /*
        Drops the database instance, either deleting it completely (default) or just freeing its pages.

        Parameters:

        * Options object that contains possible configuration options.

        Possible options are:

        * justFreePages - indicates that the database pages need to be freed but the database shouldn't be deleted

    */
    static NAN_METHOD(drop);

    static NAN_METHOD(stat);
    static NAN_METHOD(prefetch);
    int prefetch(uint32_t* keys);
    int open(int flags, char* name, bool hasVersions, LmdbKeyType keyType, Compression* compression);
#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
    static uint32_t getByBinaryFast(Local<Object> receiver_obj, uint32_t keySize);
#endif
    uint32_t doGetByBinary(uint32_t keySize);
    static void getByBinary(const v8::FunctionCallbackInfo<v8::Value>& info);
    static NAN_METHOD(getStringByBinary);
    static NAN_METHOD(getSharedByBinary);
};

class Compression : public Nan::ObjectWrap {
public:
    char* dictionary; // dictionary to use to decompress
    char* compressDictionary; // separate dictionary to use to compress since the decompression dictionary can move around in the main thread
    unsigned int dictionarySize;
    char* decompressTarget;
    unsigned int decompressSize;
    unsigned int compressionThreshold;
    // compression acceleration (defaults to 1)
    int acceleration;
    static thread_local LZ4_stream_t* stream;
    void decompress(MDB_val& data, bool &isValid, bool canAllocate);
    argtokey_callback_t compress(MDB_val* value, argtokey_callback_t freeValue);
    int compressInstruction(EnvWrap* env, double* compressionAddress);
    static NAN_METHOD(ctor);
    static NAN_METHOD(setBuffer);
    Compression();
    ~Compression();
    friend class EnvWrap;
    friend class DbiWrap;
    //NAN_METHOD(Compression::startCompressing);
};

/*
    `Cursor`
    Represents a cursor instance that is assigned to a transaction and a database instance
    (Wrapper for `MDB_cursor`)
*/
class CursorWrap : public Nan::ObjectWrap {

private:

    // Key/data pair where the cursor is at, and ending key
    MDB_val key, data, endKey;
    // Free function for the current key
    argtokey_callback_t freeKey;
    template<size_t keyIndex, size_t optionsIndex>
    friend argtokey_callback_t cursorArgToKey(CursorWrap* cw, Nan::NAN_METHOD_ARGS_TYPE info, MDB_val &key, bool &keyIsValid);

public:
    MDB_cursor_op iteratingOp;    
    MDB_cursor *cursor;
    // Stores how key is represented
    LmdbKeyType keyType;
    int flags;
    DbiWrap *dw;
    MDB_txn *txn;

    // The wrapped object
    CursorWrap(MDB_cursor *cursor);
    ~CursorWrap();

    // Sets up exports for the Cursor constructor
    static void setupExports(Local<Object> exports);

    /*
        Opens a new cursor for the specified transaction and database instance.
        (Wrapper for `mdb_cursor_open`)

        Parameters:

        * Transaction object
        * Database instance object
    */
    static NAN_METHOD(ctor);

    /*
        Closes the cursor.
        (Wrapper for `mdb_cursor_close`)

        Parameters:

        * Transaction object
        * Database instance object
    */
    static NAN_METHOD(close);
    /*
        Deletes the key/data pair to which the cursor refers.
        (Wrapper for `mdb_cursor_del`)
    */
    static NAN_METHOD(del);

    static NAN_METHOD(getCurrentValue);
    int returnEntry(int lastRC, MDB_val &key, MDB_val &data);
#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
    static uint32_t positionFast(Local<Object> receiver_obj, uint32_t flags, uint32_t offset, uint32_t keySize, uint64_t endKeyAddress, FastApiCallbackOptions& options);
    static int32_t iterateFast(Local<Object> receiver_obj, FastApiCallbackOptions& options);
#endif
    static void position(const v8::FunctionCallbackInfo<v8::Value>& info);    
    uint32_t doPosition(uint32_t offset, uint32_t keySize, uint64_t endKeyAddress);
    static void iterate(const v8::FunctionCallbackInfo<v8::Value>& info);    
    static NAN_METHOD(renew);
    //static NAN_METHOD(getStringByBinary);
};

// External string resource that glues MDB_val and v8::String
class CustomExternalStringResource : public String::ExternalStringResource {
private:
    const uint16_t *d;
    size_t l;

public:
    CustomExternalStringResource(MDB_val *val);
    ~CustomExternalStringResource();

    void Dispose();
    const uint16_t *data() const;
    size_t length() const;

    static void writeTo(Local<String> str, MDB_val *val);
};

class CustomExternalOneByteStringResource : public String::ExternalOneByteStringResource {
private:
    const char *d;
    size_t l;

public:
    CustomExternalOneByteStringResource(MDB_val *val);
    ~CustomExternalOneByteStringResource();

    void Dispose();
    const char *data() const;
    size_t length() const;

};


#endif // NODE_LMDB_H
