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

### Supported platforms

* Tested and works on Linux (author uses Fedora 20)
* Tested and works on Mac OS X - see https://github.com/Venemo/node-lmdb/issues/3
* **Not yet tested** on Windows - see https://github.com/Venemo/node-lmdb/issues/2

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
    mapSize: 2*1024*1024*1024, // maximum database size
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
    name: "myPrettyDatabase",
    create: true // will create if database did not exist
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

You can find some in the source tree. There are some basic examples and I intend to create some advanced ones too.

The basic examples we currently have:

* `example1-env.js` - shows basic usage of `Env`, `Dbi` and `Txn` operating on string values
* `example2-datatypes.js` - shows how to use various data types for your data
* `example3-multiple-transactions.js` - shows how LMDB will behave if you operate with multiple transactions
* `example4-cursors.js` - shows how to work with cursors on a basic database
* `example5-dupsort.js` - shows how to use a `dupSort` database with cursors
* `example6-asyncio.js` - shows how to use the fastest (but also most dangerous) way for async IO
* `example7-largedb.js` - shows how to work with an insanely large database

Advanced examples:

* `example-advanced1-indexing.js` - this is a module pattern example which demonstrates the implementation of a search engine prototype
* *More will come later, so don't forget to check back!*

### Limitations of node-lmdb

* **Only string, binary, number and boolean values are supported.** If you want to store complex data structures, use `JSON.stringify` before putting it into the database and `JSON.parse` when you retrieve the data.
* **Only string and unsigned integer keys are supported.** Default is string, specify `keyIsUint32: true` to `openDbi` for unsigned integer. It would make the API too complicated to support more data types for keys.
* Because of the nature of LMDB, the data returned by `txn.getString()` and `txn.getBinary()` is **only valid until the next `put` operation or the end of the transaction**. If you need to use the data *later*, you will have to copy it for yourself.
* Fixed address map (called `MDB_FIXEDMAP` in C) features are **not exposed** by this binding because they are highly experimental
* Not all functions are wrapped by the binding yet. If there's one that you would like to see, drop me a line.

Contributing
------------

If you find problems with this module, open an issue on GitHub.
Also feel free to send me pull requests. Contributions are more than welcome! :)

### Building the module

LMDB is bundled in `node-lmdb` so you can simply build this module using `node-gyp`.

```bash
# Install node-gyp globally (needs admin permissions)
npm -g install node-gyp

# Clone node-lmdb
git clone git@github.com:Venemo/node-lmdb.git

# Build
cd node-lmdb
node-gyp configure
node-gyp build
```

### Managing the LMDB dependency

```bash
# Adding upstream LMDB as remote
git remote add lmdb git@gitorious.org:mdb/mdb.git
# Fetch new remote
git fetch lmdb
# Adding the subtree (when it's not there yet)
git subtree add  --prefix=dependencies/lmdb lmdb HEAD --squash
# Updating the subtree (when already added)
git subtree pull --prefix=dependencies/lmdb lmdb HEAD --squash
```

### Developer FAQ

#### How fast is this stuff?

LMDB is one of the fastest databases on the planet, because it's **in-process** and **zero-copy**, which means it runs within your app, and not somewhere else,
so it doesn't push your data through sockets and can retrieve your data without copying it in memory.

We don't have any benchmarks for node-lmdb but you can enjoy a detailed benchmark of LMDB here: http://symas.com/mdb/microbench/
obviously, the V8 wrapper will have some negative impact on performance, but I wouldn't expect a significant difference.

#### Why is the code so ugly?

Unfortunately, writing C++ addons to Node.js (and V8) requires a special pattern (as described in their docs) which most developers might find ugly.
Fortunately, we've done this work for you so you can enjoy LMDB without the need to code C++.

#### How does this module work?

It glues together LMDB and Node.js with a native Node.js addon that wraps the LMDB C API.

Zero-copy is implemented for string and binary values via a V8 custom external string resource and the Node.js Buffer class.

#### How did you do it?

These are the places I got my knowledge when developing node-lmdb:

* V8 reference documentation: http://bespin.cz/~ondras/html/
* Node.js C++ addons documentation: http://nodejs.org/api/addons.html
* LMDB documentation: http://symas.com/mdb/doc/
