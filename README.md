node-lmdb
=========

This is a node.js binding for LMDB, an extremely fast and lightweight transactional key-value store database.

About
-----

### About this module

The aim of this node module is to provide bindings so that people can use LMDB from their node applications, aiming for a simple and clean API which is on par with the LMDB API but tries to apply javascript patterns and naming conventions as much as possible to make users feel familiar about it.

We support **zero-copy** retrieval of **string** and **binary** values. Binary values are operated on via the Node.js `Buffer` API.

### About LMDB

Here are the main highlights of LMDB, for more, visit http://symas.com/mdb :)

* Key-value store, NoSQL
* In-process, no need to squeeze your data through a socket
* Support for transactions and multiple databases in the same environment
* Support for multi-threaded and multi-process use
* Zero-copy lookup (memory map)

Usage
-----

### Introduction

#### Step 0: require the module

Just like with any other node module, the first step is to `require()` the module.

```javascript
var lmdb = require('node-lmdb');
```

#### Step 1: create an environment

`Env` represents a database environment. You can create one with the `new` operator and after that, you must open it before you can use it.
`open()` accepts an object literal in which you can specify the configuration options for the environment.

```javascript
var env = new lmdb.Env();
env.open({
    path: __dirname + "/mydata",
    maxDbs: 3
});
```

Close the environment when you no longer need it.

```javascript
env.close();
```

#### Step 2: open one or more databases

An environment (`Env`) can contain one or more databases. Open a database with `env.openDbi()` which takes an object literal with which you can configure your database.

```javascript
var dbi = env.openDbi({
    name: "myPrettyDatabase"
})
```

Close the database when you no longer need it.

```javascript
dbi.close();
```

#### Step 3: use transactions

The basic unit of work in LMDB is a transaction, which is called `Txn` for short. Here is how you operate with your data.  
Every piece of data in LMDB is referred to by a **key**.  
You can use the methods `getString()`, `getBinary()`, `getNumber()` and `getBoolean()` to retrieve something,
`putString()`, `putBinary()`, `putNumber()` and `putBoolean()` to store something and `del()` to delete something.

Currently **only string, binary, number and boolean values are supported**, use `JSON.stringify` and `JSON.parse` for complex data structures.  
Because of the nature of LMDB, the data returned by `txn.getString()` and `txn.getBinary()` is only valid until the next `put` operation or the end of the transaction.
If you need to use the data *later*, you will have to copy it for yourself.

**IMPORTANT:** always close your transactions with `abort()` or `commit()` when you are done with them.

```javascript
var txn = env.beginTxn();
var value = txn.getString(dbi, 1);

console.log(value);

if (value === null) {
    txn.putString(dbi, 1, "Hello world!");
}
else {
    txn.del(dbi, 1);
}

txn.putString(dbi, 2, "Yes, it's this simple!");
txn.commit();
```

### Basic concepts

LMDB has four different entities:

* `Env` represents a full database environment. The same environment can be used by multiple processes, but a particular `Env` object **must** be used by one process only. You can operate with the same environment from multiple threads.
* `Dbi` represents a sub-database which belongs to a database environment. The same environment can contain either multiple named databases or an unnamed database.
* `Txn` represents a transaction. Multiple threads can open transactions for the same `Env`, but a particular `Txn` object **must** only be accessed by one thread, and only one `Txn` object can be used on a thread at a time. (NOTE: The `noTls` option in the environment will change this behaviour for *read-only* transactions, so that a thread can then create any number of *read-only* transactions and any number of threads can access the same *read-only* transaction.) Note that **only one** *write* transaction can be open in an environment in any given time. `env.beginTxn()` will simply block until the previous one is either `commit()`ted or `abort()`ed.
* `Cursor` objects can be used to iterate through multiple keys in the same database.

Here is how you use LMDB in a typical scenario:

* You create an `Env` and `open()` it with the desired configuration options.
* You open a `Dbi` by calling `env.openDbi()` and passing the database configuration options.
* Now you can create `Txn`s with `env.beginTxn()` and operate on the database through a transaction by calling `txn.getString()`, `txn.putString()` etc.
* When you are done, you should either `abort()` or `commit()` your transactions and `close()` your databases and environment.

### Examples

You can find some in the source tree. More will be added later.

### Limitations of node-lmdb

* **Only string, binary, number and boolean values are supported.** If you want to store complex data structures, use `JSON.stringify` before putting it into the database and `JSON.parse` when you retrieve the data.
* Because of the nature of LMDB, the data returned by `txn.getString()` and `txn.getBinary()` is **only valid until the next `put` operation or the end of the transaction**. If you need to use the data *later*, you will have to copy it for yourself.
* Fixed address map (called `MDB_FIXEDMAP` in C) features are **not exposed** by this binding because they are highly experimental
* `Cursor`s are not yet exposed but are planned soon.
* Not all functions are wrapped by the binding yet. If there's one that you would like to see, drop me a line.

Contributing
------------

Feel free to send me pull requests on GitHub. Contributions are more than welcome! :)
