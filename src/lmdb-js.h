
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
#define NAPI_VERSION 4
#include <napi.h>
#include <node_api.h>

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

using namespace Napi;

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
void setupExportMisc(Env env, Object exports);

// Helper callback
typedef void (*argtokey_callback_t)(MDB_val &key);

void consoleLog(Value val);
void consoleLog(const char *msg);
void consoleLogN(int n);
void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Object options);
void writeValueToEntry(const Value &str, MDB_val *val);
LmdbKeyType keyTypeFromOptions(const Value &val, LmdbKeyType defaultKeyType = LmdbKeyType::DefaultKey);
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
Value valToUtf8(MDB_val &data);
Value valToString(MDB_val &data);
Value valToStringUnsafe(MDB_val &data);
Value valToBinary(MDB_val &data);
Value valToBinaryUnsafe(MDB_val &data, DbiWrap* dw);

int putWithVersion(MDB_txn *   txn,
        MDB_dbi     dbi,
        MDB_val *   key,
        MDB_val *   data,
        unsigned int    flags, double version);

void throwLmdbError(Env env, int rc);

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
/*class NanWriteWorker : public WriteWorker, public AsyncProgressWorker<NanWriteWorker> {
  public:
    NanWriteWorker(MDB_env* env, EnvWrap* envForTxn, uint32_t* instructions, Function *callback);
    void Execute(ExecutionProgress executionProgress);
    void HandleProgressCallback(const char* data, size_t count);
    void OnOK();
    void ReportError(const char* error);
    void SendUpdate();
  private:
    ExecutionProgress* executionProgress;
};*/
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
class EnvWrap : public ObjectWrap<EnvWrap> {
private:
    // List of open read transactions
    std::vector<TxnWrap*> readTxns;
    // Constructor for TxnWrap
    static thread_local napi_ref* txnCtor;
    // Constructor for DbiWrap
    static thread_local napi_ref* dbiCtor;
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
    EnvWrap(const CallbackInfo&);
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
    static void setupExports(Napi::Env env, Object exports);
    void closeEnv();
    int openEnv(int flags, int jsFlags, const char* path, char* keyBuffer, Compression* compression, int maxDbs,
        int maxReaders, mdb_size_t mapSize, int pageSize, char* encryptionKey);
    
    /*
        Constructor of the database environment. You need to `open()` it before you can use it.
        (Wrapper for `mdb_env_create`)
    */
    napi_value ctor(const CallbackInfo& info);
    
    /*
        Gets statistics about the database environment.
    */
    napi_value stat(const CallbackInfo& info);

    /*
        Gets statistics about the free space database
    */
    napi_value freeStat(const CallbackInfo& info);
    
    /*
        Detaches a buffer from the backing store
    */
    napi_value detachBuffer(const CallbackInfo& info);

    /*
        Gets information about the database environment.
    */
    napi_value info(const CallbackInfo& info);
    /*
        Check for stale readers
    */
    napi_value readerCheck(const CallbackInfo& info);
    /*
        Print a list of readers
    */
    napi_value readerList(const CallbackInfo& info);

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
    napi_value open(const CallbackInfo& info);
    napi_value getMaxKeySize(const CallbackInfo& info);

    /*
        Resizes the maximal size of the memory map. It may be called if no transactions are active in this process.
        (Wrapper for `mdb_env_set_mapsize`)

        Parameters:

        * maximal size of the memory map (the full environment) in bytes (default is 10485760 bytes)
    */
    napi_value resize(const CallbackInfo& info);

    /*
        Copies the database environment to a file.
        (Wrapper for `mdb_env_copy2`)

        Parameters:

        * path - Path to the target file
        * compact (optional) - Copy using compact setting
        * callback - Callback when finished (this is performed asynchronously)
    */
    napi_value copy(const CallbackInfo& info);    

    /*
        Closes the database environment.
        (Wrapper for `mdb_env_close`)
    */
    napi_value close(const CallbackInfo& info);

    /*
        Starts a new transaction in the environment.
        (Wrapper for `mdb_txn_begin`)

        Parameters:

        * Options object that contains possible configuration options.

        Possible options are:

        * readOnly: if true, the transaction is read-only
    */
    napi_value beginTxn(const CallbackInfo& info);
    napi_value commitTxn(const CallbackInfo& info);
    napi_value abortTxn(const CallbackInfo& info);

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
    napi_value openDbi(const CallbackInfo& info);

    /*
        Flushes all data to the disk asynchronously.
        (Asynchronous wrapper for `mdb_env_sync`)

        Parameters:

        * Callback to be executed after the sync is complete.
    */
    napi_value sync(const CallbackInfo& info);

    /*
        Performs a set of operations asynchronously, automatically wrapping it in its own transaction

        Parameters:

        * Callback to be executed after the sync is complete.
    */
    napi_value startWriting(const CallbackInfo& info);
    napi_value compress(const CallbackInfo& info);
#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
    static void writeFast(Object receiver_obj, uint64_t instructionAddress, FastApiCallbackOptions& options);
#endif
    static void write(const CallbackInfo& info);

    napi_value resetCurrentReadTxn(const CallbackInfo& info);
};

const int TXN_ABORTABLE = 1;
const int TXN_SYNCHRONOUS_COMMIT = 2;
const int TXN_FROM_WORKER = 4;

/*
    `Txn`
    Represents a transaction running on a database environment.
    (Wrapper for `MDB_txn`)
*/
class TxnWrap : public ObjectWrap<TxnWrap> {
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
    napi_value ctor(const CallbackInfo& info);

    /*
        Commits the transaction.
        (Wrapper for `mdb_txn_commit`)
    */
    napi_value commit(const CallbackInfo& info);

    /*
        Aborts the transaction.
        (Wrapper for `mdb_txn_abort`)
    */
    napi_value abort(const CallbackInfo& info);

    /*
        Aborts a read-only transaction but makes it renewable with `renew`.
        (Wrapper for `mdb_txn_reset`)
    */
    napi_value reset(const CallbackInfo& info);
    void reset();
    /*
        Renews a read-only transaction after it has been reset.
        (Wrapper for `mdb_txn_renew`)
    */
    napi_value renew(const CallbackInfo& info);

};

const int HAS_VERSIONS = 0x1000;
/*
    `Dbi`
    Represents a database instance in an environment.
    (Wrapper for `MDB_dbi`)
*/
class DbiWrap : public ObjectWrap<DbiWrap> {
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
    napi_value ctor(const CallbackInfo& info);

    /*
        Closes the database instance.
        Wrapper for `mdb_dbi_close`)
    */
    napi_value close(const CallbackInfo& info);

    /*
        Drops the database instance, either deleting it completely (default) or just freeing its pages.

        Parameters:

        * Options object that contains possible configuration options.

        Possible options are:

        * justFreePages - indicates that the database pages need to be freed but the database shouldn't be deleted

    */
    napi_value drop(const CallbackInfo& info);

    napi_value stat(const CallbackInfo& info);
    napi_value prefetch(const CallbackInfo& info);
    int prefetch(uint32_t* keys);
    int open(int flags, char* name, bool hasVersions, LmdbKeyType keyType, Compression* compression);
#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
    static uint32_t getByBinaryFast(Object receiver_obj, uint32_t keySize);
#endif
    uint32_t doGetByBinary(uint32_t keySize);
    static void getByBinary(const CallbackInfo& info);
    napi_value getStringByBinary(const CallbackInfo& info);
    napi_value getSharedByBinary(const CallbackInfo& info);
};

class Compression : public ObjectWrap<Compression> {
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
    napi_value ctor(const CallbackInfo& info);
    napi_value setBuffer(const CallbackInfo& info);
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
class CursorWrap : public ObjectWrap<CursorWrap> {

private:

    // Key/data pair where the cursor is at, and ending key
    MDB_val key, data, endKey;
    // Free function for the current key
    argtokey_callback_t freeKey;

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
    static void setupExports(Napi::Env env, Object exports);

    /*
        Opens a new cursor for the specified transaction and database instance.
        (Wrapper for `mdb_cursor_open`)

        Parameters:

        * Transaction object
        * Database instance object
    */
    napi_value ctor(const CallbackInfo& info);

    /*
        Closes the cursor.
        (Wrapper for `mdb_cursor_close`)

        Parameters:

        * Transaction object
        * Database instance object
    */
    napi_value close(const CallbackInfo& info);
    /*
        Deletes the key/data pair to which the cursor refers.
        (Wrapper for `mdb_cursor_del`)
    */
    napi_value del(const CallbackInfo& info);

    napi_value getCurrentValue(const CallbackInfo& info);
    int returnEntry(int lastRC, MDB_val &key, MDB_val &data);
#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
    static uint32_t positionFast(Object receiver_obj, uint32_t flags, uint32_t offset, uint32_t keySize, uint64_t endKeyAddress, FastApiCallbackOptions& options);
    static int32_t iterateFast(Object receiver_obj, FastApiCallbackOptions& options);
#endif
    Napi::Value position(const CallbackInfo& info);    
    uint32_t doPosition(uint32_t offset, uint32_t keySize, uint64_t endKeyAddress);
    Napi::Value iterate(const CallbackInfo& info);    
    Napi::Value renew(const CallbackInfo& info);
    //napi_value getStringByBinary(const CallbackInfo& info);
};

#endif // NODE_LMDB_H