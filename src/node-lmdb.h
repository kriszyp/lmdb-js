
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

#ifndef NODE_LMDB_H
#define NODE_LMDB_H

#include <v8.h>
#include <node.h>
#include <lmdb.h>
#include <uv.h>

using namespace v8;
using namespace node;

// Exports misc stuff to the module
void setupExportMisc(Handle<Object> exports);

/*
    `Env`
    Represents a database environment.
    (Wrapper for `MDB_env`)
*/
class EnvWrap : public ObjectWrap {
private:
    // The wrapped object
    MDB_env *env;
    // Constructor for TxnWrap
    static Persistent<Function> txnCtor;
    // Constructor for DbiWrap
    static Persistent<Function> dbiCtor;
    
    friend class TxnWrap;
    friend class DbiWrap;

public:
    EnvWrap();
    ~EnvWrap();

    // Sets up exports for the Env constructor
    static void setupExports(Handle<Object> exports);
    
    /*
        Constructor of the database environment. You need to `open()` it before you can use it.
        (Wrapper for `mdb_env_create`)
    */
    static Handle<Value> ctor(const Arguments& args);
    
    /*
        Opens the database environment with the specified options. The options will be used to configure the environment before opening it.
        (Wrapper for `mdb_env_open`)
        
        Parameters:
        
        * Options object that contains possible configuration options.
        
        Possible options are:
        
        * maxDbs: the maximum number of named databases you can have in the environment
        * path: path to the database environment
    */
    static Handle<Value> open(const Arguments& args);
    
    /*
        Closes the database environment.
        (Wrapper for `mdb_env_close`)
    */
    static Handle<Value> close(const Arguments& args);
    
    /*
        Starts a new transaction in the environment.
        (Wrapper for `mdb_txn_begin`)
        
        Parameters:
        
        * Options object that contains possible configuration options.
        
        Possible options are:
        
        * TODO
    */
    static Handle<Value> beginTxn(const Arguments& args);
    
    /*
        Opens a database in the environment.
        (Wrapper for `mdb_dbi_open`)
        
        Parameters:
        
        * Options object that contains possible configuration options.
        
        Possible options are:
        
        * create: if true, the database will be created if it doesn't exist
    */
    static Handle<Value> openDbi(const Arguments& args);
    
    /*
        Flushes all data to the disk asynchronously.
        (Asynchronous wrapper for `mdb_env_sync`)
        
        Parameters:
        
        * Callback to be executed after the sync is complete.
    */
    static Handle<Value> sync(const Arguments &args);
};

/*
    `Txn`
    Represents a transaction running on a database environment.
    (Wrapper for `MDB_txn`)
*/
class TxnWrap : public ObjectWrap {
private:
    // The wrapped object
    MDB_txn *txn;
    // Reference to the MDB_env of the wrapped MDB_txn
    MDB_env *env;

public:
    TxnWrap(MDB_env *env, MDB_txn *txn);
    ~TxnWrap();

    // Constructor (not exposed)
    static Handle<Value> ctor(const Arguments& args);
    
    // Helper for all the get methods (not exposed)
    static Handle<Value> getCommon(const Arguments &args, Handle<Value> (*successFunc)(const Arguments&, MDB_val&));
    
    // Helper for all the put methods (not exposed)
    static Handle<Value> putCommon(const Arguments &args, void (*fillFunc)(const Arguments&, MDB_val&), void (*freeFunc)(MDB_val&));
    
    /*
        Commits the transaction.
        (Wrapper for `mdb_txn_commit`)
    */
    static Handle<Value> commit(const Arguments& args);
    
    /*
        Aborts the transaction.
        (Wrapper for `mdb_txn_abort`)
    */
    static Handle<Value> abort(const Arguments& args);
    
    /*
        Aborts a read-only transaction but makes it renewable with `renew`.
        (Wrapper for `mdb_txn_reset`)
    */
    static Handle<Value> reset(const Arguments& args);
    
    /*
        Renews a read-only transaction after it has been reset.
        (Wrapper for `mdb_txn_renew`)
    */
    static Handle<Value> renew(const Arguments& args);
    
    /*
        Gets string data (JavaScript string type) associated with the given key from a database. You need to open a database in the environment to use this.
        This method is zero-copy and the return value can only be used until the next put operation or until the transaction is committed or aborted.
        (Wrapper for `mdb_get`)
        
        Parameters:
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * key for which the value is retrieved
    */
    static Handle<Value> getString(const Arguments& args);
    
    /*
        Gets binary data (Node.js Buffer) associated with the given key from a database. You need to open a database in the environment to use this.
        This method is zero-copy and the return value can only be used until the next put operation or until the transaction is committed or aborted.
        (Wrapper for `mdb_get`)
        
        Parameters:
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * key for which the value is retrieved
    */
    static Handle<Value> getBinary(const Arguments& args);
    
    /*
        Gets number data (JavaScript number type) associated with the given key from a database. You need to open a database in the environment to use this.
        This method will copy the value out of the database.
        (Wrapper for `mdb_get`)
        
        Parameters:
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * key for which the value is retrieved
    */
    static Handle<Value> getNumber(const Arguments& args);
    
    /*
        Gets boolean data (JavaScript boolean type) associated with the given key from a database. You need to open a database in the environment to use this.
        This method will copy the value out of the database.
        (Wrapper for `mdb_get`)
        
        Parameters:
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * key for which the value is retrieved
    */
    static Handle<Value> getBoolean(const Arguments& args);
    
    /*
        Puts string data (JavaScript string type) into a database.
        (Wrapper for `mdb_put`)
        
        Parameters:
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * key for which the value is stored
        * data to store for the given key
    */
    static Handle<Value> putString(const Arguments& args);
    
    /*
        Puts binary data (Node.js Buffer) into a database.
        (Wrapper for `mdb_put`)
        
        Parameters:
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * key for which the value is stored
        * data to store for the given key
    */
    static Handle<Value> putBinary(const Arguments& args);
    
    /*
        Puts number data (JavaScript number type) into a database.
        (Wrapper for `mdb_put`)
        
        Parameters:
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * key for which the value is stored
        * data to store for the given key
    */
    static Handle<Value> putNumber(const Arguments& args);
    
    /*
        Puts boolean data (JavaScript boolean type) into a database.
        (Wrapper for `mdb_put`)
        
        Parameters:
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * key for which the value is stored
        * data to store for the given key
    */
    static Handle<Value> putBoolean(const Arguments& args);
    
    /*
        Deletes data with the given key from the database.
        (Wrapper for `mdb_del`)
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * key for which the value is stored
    */
    static Handle<Value> del(const Arguments& args);
    
    /*
        Drops a database instance, either deleting it completely (default) or just freeing its pages.
        
        Parameters:
        
        * database instance created with calling `openDbi()` on an `Env` instance
        * Options object that contains possible configuration options.
        
        Possible options are:
        
        * justFreePages - indicates that the database pages need to be freed but the database shouldn't be deleted
        
    */
    static Handle<Value> dropDbi(const Arguments& args);
};

/*
    `Dbi`
    Represents a database instance in an environment.
    (Wrapper for `MDB_dbi`)
*/
class DbiWrap : public ObjectWrap {
private:
    // Stores whether or not the MDB_dbi needs closing
    bool needsClose;
    // The wrapped object
    MDB_dbi dbi;
    // Reference to the MDB_env of the wrapped MDB_dbi
    MDB_env *env;
    
    friend class TxnWrap;

public:
    DbiWrap(MDB_env *env, MDB_dbi dbi);
    ~DbiWrap();

    // Constructor (not exposed)
    static Handle<Value> ctor(const Arguments& args);
    
    /*
        Closes the database instance.
        Wrapper for `mdb_dbi_close`)
    */
    static Handle<Value> close(const Arguments& args);
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
    
    static void writeTo(Handle<String> str, MDB_val *val);
};

#endif // NODE_LMDB_H

