node-lmdb
=========

This is a node.js binding for LMDB, an extremely fast and lightweight transactional key-value store database.

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=venemo%40msn%2ecom&lc=US&item_name=to%20Timur%20Kristof%2c%20for%20node%2dlmdb%20development&item_number=node%2dlmdb&no_note=0&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donate_SM%2egif%3aNonHostedGuest)

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
* Crash-proof design

### Supported platforms

* Tested and works on Linux (author uses Fedora)
* Tested and works on Mac OS X
* Tested and works on Windows

### License info

The `node-lmdb` code is licensed to you under the terms of the MIT license. LMDB itself is licensed under its own OpenLDAP public license (which is similarly permissive).

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

#### Asynchronous batched operations

You can batch together a set of operations to be processed asynchronously with `node-lmdb`. Committing multiple operations at once can improve performance, and performing a batch of operations and using sync transactions (slower, but maintains crash-proof integrity) can be efficiently delegated to an asynchronous thread. In addition, writes can be defined as conditional by specifying the required value to match in order for the operation to be performed, to allow for deterministic atomic writes based on prior state. The `batchWrite` method accepts an array of write operation requests, where each operation is an object or array. If it is an object, the supported properties are:
* `db` (required) - The database to write to
* `key` (required) - The key to write
* `value` (optional) - If specified, this is the value to `put` into the entry. If absent or undefined, this write operation will be a delete, and delete this key. This should be a binary/buffer value.
* `ifValue` (optional) - If specified, the write operation (put or delete) will only be performed if the provided `ifValue` matches the existing value for this entry. This should be a binary/buffer value.
* `ifExactMatch` (optional) - If set to true, the conditional write requires that `ifValue` exactly match the existing value, byte for byte and length. By default `ifValue` can be a prefix and only needs to match the number of bytes in `ifValue` (for example if `ifValue` is `Buffer.from([5, 2])`, the conditional write will be performed if the `value` starts with 5, 2).
* `ifKey` (optional) - If specified, indicates the key to use for for matching the conditional value. By default, the key use to match `ifValue` is the same key as the write operation.
* `ifDB` (optional) - If specified, indicates the db to use for for matching the conditional value. By default, the key use to match `ifValue` is the same db as the write operation.

If the write operation is a specified with an array, the supported elements are:
* A three element array for `put`ing data: `[db, key, value]` (where `value` is a binary/buffer)
* A two element array for `del`eting data: `[db, key]`
* A four element array for conditionally `put`ing or `del`eting data: `[db, key, value, ifValue]` (where `value` and `ifValue` are as specificied in the object definition)

When `batchWrite` is called, `node-ldmb` will asynchronously create a new write transaction, execute all the operations in the provided array, except for any conditional writes where the condition failed, and commit the transaction, if there were no errors. For conditional writes, if the condition did not match, the write will be skipped, but the transaction will still be committed. However, if any errors occur, the transaction will be aborted. This entire transaction will be created by `node-lmdb` and executed in a separate thread. The callback function will be called once the transaction is finished. It is possible for an explicit write transaction in the main JS thread to block or be blocked by the asynchronous transaction.
For example:
```javascript
env.batchWrite([
    [dbi, key1, Buffer.from("Hello")], // put in key 1
    [dbi, key2, Buffer.from("World")], // put in key 2
    [dbi, key3], // delete any entry from key 3 (can also use null as value to indicate delete)
    [dbi, key4, valuePlusOne, oldValue] // you could atomically increment by specifying the require previous state
], options, (error, results) => {
    if (error) {
        console.error(error);
    } else {
        // operations finished and transaction was committed
        let didWriteToKey4Succeed = results[3] === 0
    }
})
```
The callback function will be either be called with an error in the first argument, or an array in the second argument with the results of the operations. The array will be the same length as the array of write operations, with one to one correspondence by position, and each value in the result array will be:
0 - Operation successfully written
1 - Condition not met (only can happen if a condition was provided)
2 - Attempt to delete non-existent key (only can happen if `ignoreNotFound` enabled)


The options include all the flags from `put` `options`, and this optional property:
* `progress` - This should be a function, if provided, will be called to report the progress of the write operations, returning the results array, with completion values filled in for completed operations, and all uncompleted operations will correspond to `undefined` in the eleemnt positions in the array. Progress events are best-effort in node; the write operations are performed in a separate thread, and progress events occur if and when node's event queue is free to run them (they are not guaranteed to fire if the main thread is busy).


### Basic concepts

LMDB has four different entities:

* `Env` represents a full database environment. The same environment can be used by multiple processes, but a particular `Env` object **must** be used by one process only. You can operate with the same environment from multiple threads.
* `Dbi` represents a sub-database which belongs to a database environment. The same environment can contain either multiple named databases (if you specify a string name) or an unnamed database (if you specify `null` instead of a name).
* `Txn` represents a transaction. Multiple threads can open transactions for the same `Env`, but a particular `Txn` object **must** only be accessed by one thread, and only one `Txn` object can be used on a thread at a time. (NOTE: The `noTls` option in the environment will change this behaviour for *read-only* transactions, so that a thread can then create any number of *read-only* transactions and any number of threads can access the same *read-only* transaction.) Note that **only one** *write* transaction can be open in an environment in any given time. `env.beginTxn()` will simply block until the previous one is either `commit()`ted or `abort()`ed.
* `Cursor` objects can be used to iterate through multiple keys in the same database.

Here is how you use LMDB in a typical scenario:

* You create an `Env` and `open()` it with the desired configuration options.
* You open a `Dbi` by calling `env.openDbi()` and passing the database configuration options.
* Now you can create `Txn`s with `env.beginTxn()` and operate on the database through a transaction by calling `txn.getString()`, `txn.putString()` etc.
* When you are done, you should either `abort()` or `commit()` your transactions and `close()` your databases and environment.

Example iteration over a database with a `Cursor`:

```javascript
var cursor = new lmdb.Cursor(txn, dbi);

for (var found = cursor.goToFirst(); found !== null; found = cursor.goToNext()) {
    // Here 'found' contains the key, and you can get the data with eg. getCurrentString/getCurrentBinary etc.
    // ...
}
```

The cursor `goTo` methods (`goToFirst`, `goToNext`, etc.) will return the current key. When an item is not found, `null` is returned.
Beware that the key itself could be a *falsy* JavaScript value, so you need to explicitly check against `null` with the `!==` operator in your loops.

### Data Types in node-lmdb

LMDB is very simple and fast. Using node-lmdb provides close to the native C API functionally, but expressed via a natural
javascript API. To make simple things simple, node-lmdb defaults to presenting keys and values in LMDB as strings.
For convenience number, boolean and `Buffer` values are also supported.

The simplest way to store complex data types (such as objects) is to use `JSON.stringify` before putting it into the database
and `JSON.parse` when you retrieve the data.

For more complex use cases access to keys and values as binary (node.js `Buffer` type) is provided. In LMDB itself keys 
(with one exception) and values are simply binary sequences of bytes. You can retrieve a key or value from an LMDB database
as binary even if it was written as a string. The same does not apply in reverse! Using binary access
also allows interoperation with LMDB databases created by, or shared with applications that use data serialisation formats
other than UTF-16 strings (including, in particular, strings using other encodings such as UTF-8).  
See our chapter *Working with strings* for more details.

#### Keys

* *Unsigned 32-bit integers*: The one exception in LMDBs representation of keys is an optimisation for fixed-length keys. This is exposed
by node-lmdb for one particular fixed length type: unsigned 32 bit integers. To use this optimisation specify `keyIsUint32: true`
to `openDbi`. Because the `keyIsUint32 : true` option is passed through to LMDB and stored in the LMDB metadata for the database,
a database created with this option set cannot be accessed without setting this option, and vice-versa.
* *Buffers*: If you pass `keyIsBuffer: true`, you can work with node `Buffer` instances as keys.
* *Strings*: This is the default. You can also use `keyIsString: true`.

When using a cursor keys are read from the database and it is necessary to specify how the keys should be returned.
The most direct mapping from LMDB C API is as a node.js Buffer (binary), however it is often more convenient to
return the key as a string, so that is the default.

You can specify the key type when you open a database:

```
dbi = env.openDbi({
    // ... etc.
    keyIsBuffer: true
});
```

When working with transactions, you can override the key type passed to `openDbi` by providing options to `put`, `get` and `del` functions.  
For example:

```
var buffer = new Buffer('48656c6c6f2c20776f726c6421', 'hex');
var key = new Buffer('key2');
txn.putBinary(dbi, key, buffer, { keyIsBuffer: true });
var data = txn.getBinary(dbi, key, { keyIsBuffer: true });
data.should.deep.equal(buffer);
txn.del(dbi, key, { keyIsBuffer: true });
```

Finally, when working with cursors, you can override the key type by passing similar options as the 3rd argument of the `Cursor` constructor:

```
cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });
```

### Examples

You can find some in the source tree. There are some basic examples and I intend to create some advanced ones too.

The basic examples we currently have:

* `examples/1-env.js` - shows basic usage of `Env`, `Dbi` and `Txn` operating on string values
* `examples/2-datatypes.js` - shows how to use various data types for your data
* `examples/3-multiple-transactions.js` - shows how LMDB will behave if you operate with multiple transactions
* `examples/4-cursors.js` - shows how to work with cursors on a basic database
* `examples/5-dupsort.js` - shows how to use a `dupSort` database with cursors
* `examples/6-asyncio.js` - shows how to use the fastest (but also most dangerous) way for async IO
* `examples/7-largedb.js` - shows how to work with an insanely large database
* `examples/8-multiple-cursors-single-transactions.js` - shows how to use multiple cursors with a single transaction
* `examples/9-unnamed-db.js` - shows how to use an unnamed database
* `examples/10-binkeycursors.js` - shows how to work with cursors on a database with binary keys

Advanced examples:

* `examples/advanced1-indexing.js` - this is a module pattern example which demonstrates the implementation of a search engine prototype
* *More will come later, so don't forget to check back!*

### Caveats

#### Unsafe Get Methods
Because of the nature of LMDB, the data returned by `txn.getStringUnsafe()`, `txn.getBinaryUnsafe()`, `cursor.getCurrentStringUnsafe()`
and `cursor.getCurrentBinaryUnsafe()` is **only valid until the next `put` operation or the end of the transaction**. Also, with Node 14+, you must detach the buffer after using it, by calling `env.detachBuffer(buffer)`. This must be done before accessing the same entry again (or V8 will crash).
If you need to use the data *later*, you can use the `txn.getBinary()`, `txn.getString()`, `cursor.getCurrentBinary()` and
`cursor.getCurrentString()` methods. For most usage, the optimisation (no copy) gain from using the unsafe methods is so small
as to be negligible - the `Unsafe` methods should be avoided.


#### Working with strings

Strings can come from many different places and can have many different encodings. In the JavaScript world (and therefore the node.js world) strings are encoded in UTF-16, so every string stored with node-lmdb is also encoded in UTF-16 internally. This means that the string API (`getString`, `putString`, etc.) will only work with UTF-16 encoded strings.

If you only use strings that come from JavaScript code or other code that is a “good node citizen”, you never have to worry about encoding.

##### How to use other encodings

This has come up many times in discussions, so here is a way to use other encodings supported by node.js. You can use `Buffer`s with node-lmdb, which are a very friendly way to work with binary data. They also come in handy when you store strings in your database with encodings other than UTF-16.

You can, for example, read a UTF-8 string as a buffer, and then use `Buffer`'s `toString` method and specify the encoding:

```javascript
// Get stored data as Buffer
var buf = txn.getBinary(dbi, key);
// Use the Buffer toString API to convert from UTF-8 to a JavaScript string
var str = buf.toString('utf8');
```

Useful links:

* Buffer API in node.js:  
https://nodejs.org/api/buffer.html
* The list of encodings supported by node.js:  
https://github.com/nodejs/node/blob/master/lib/buffer.js#L490

##### Storing UTF-16 strings as Buffers

While node.js doesn't require the UTF-16 strings to be zero-terminated, node-lmdb automatically and transparently zero-terminates every string internally.
As a user, this shouldn't concern you, but if you want to write a string using the Buffer API and read it as a string, you are in for a nasty surprise.

However, it will work correctly if you manually add the terminating zero to your buffer.

Conceptually, something like this will work:

```javascript
// The string we want to store using a buffer
var expectedString = 'Hello world!';

// node-lmdb internally stores a terminating zero, so we need to manually emulate that here
// NOTE: this would NEVER work without 'utf16le'!
var buf = Buffer.from(expectedString + '\0', 'utf16le');

// Store data as binary
txn.putBinary(dbi, key, buf);
      
// Retrieve same data as string and check
var data3 = txn.getString(dbi, key);

// At this point, data3 is equal to expectedString

```

### Limitations of node-lmdb

* Fixed address map (called `MDB_FIXEDMAP` in C) features are **not exposed** by this binding because they are highly experimental
* There is no option to specify a custom key comparison method, so if the order of traversal is important,
the key must be constructed so as to be correctly ordered using lexicographical comparison of the
binary byte sequence (LMDB's default comparison method). While LMDB itself does allow custom comparisons, exposing this through a
language binding is not recommended by LMDB's author. The validity of the database depends on a consistent key comparison function
so it is not appropriate to use this customisation except in very specialised use cases - exposing this customisation point
would encourage misuse and potential database corruption. In any case, LMDB performance is very sensitive to comparison performance
and many of the advantages of using LMDB would be lost were a complex (and non-native code) comparison function used.
* Not all functions are wrapped by the binding yet. If there's one that you would like to see, drop me a line.


Contributing
------------

If you find problems with this module, open an issue on GitHub.
Also feel free to send me pull requests. Contributions are more than welcome! :)

### Building node-lmdb

LMDB is bundled in `node-lmdb` so you can simply build this module using `node-gyp`.

```bash
# Install node-gyp globally (needs admin permissions)
npm -g install node-gyp

# Clone node-lmdb
git clone git@github.com:Venemo/node-lmdb.git

# Go to node-lmdb directory
cd node-lmdb

# At first, you need to download all dependencies
npm install

# Once you have all the dependencies, the build is this simple
node-gyp configure
node-gyp build
```

### Building node-lmdb on Windows

Windows isn't such a great platform for native node addons, but it can be made to work.
See this very informative thread: https://github.com/nodejs/node-gyp/issues/629

1. Install latest .NET Framework (v4.6.2 at the time of writing)
2. Install latest node.js (v7.9.0 at the time of writing).
3. This is Windows. Reboot.
4. Now open a node.js command prompt as administrator and run the following commands.  
*NOTE: these commands WILL take a LOT of time. Please be patient.*

```
npm -g install windows-build-tools
npm -g install node-gyp
npm -g install mocha
npm config set msvs_version 2015 --global
```

After this, close the command prompt and open a new one (so that changes to `PATH` and whatever else
can take proper effect). At this point you should have all the necessary junk for Windows to be able
to handle the build. (You won't need to run node as administrator anymore.)
Note that `windows-build-tools` will silently fail to install if you don't have the .NET Framework
installed on your machine.

5. Add python2 to `PATH`. Note that `windows-build-tools` installed python2 (v2.7.x) for you
already, so easiest is to use "Change installation" in the Control Panel and select "Change" and then
"Add python.exe to PATH".
6. This is Windows. Reboot again just to be sure.

Congrats! Now you can work with native node.js modules.

When you are building node-lmdb for the first time, you need to install node-lmdb's dependencies with `npm install`:

```
cd node-lmdb
npm install
```

Note that `npm install` will also attempt to build the module. However once you got all the dependencies,
you only need to do the following for a build:

```
cd node-lmdb
node-gyp configure
node-gyp build
```

### Managing the LMDB dependency

```bash
# Adding upstream LMDB as remote
git remote add lmdb https://git.openldap.org/openldap/openldap.git
# Fetch new remote
git fetch lmdb
# Adding the subtree (when it's not there yet)
git subtree add  --prefix=dependencies/lmdb lmdb mdb.master --squash
# Updating the subtree (when already added)
git subtree pull --prefix=dependencies/lmdb lmdb mdb.master --squash
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

### Acknowledgements

Below you can find a list of people who have contributed (in alphabetical order).
Big thank you to everybody!  
(NOTE: if you think your name should be here, but isn't, please contact the author.)

* @aholstenson (Andreas Holstenson)
* @antoinevw
* @b-ono
* @braydonf (Braydon Fuller)
* @da77a
* @erichocean (Erich Ocean)
* @jahewson (John Hewson)
* @jeffesquivels (Jeffrey Esquivel S.)
* @justmoon (Stefan Thomas)
* @kriszyp (Kris Zyp)
* @Matt-Esch
* @oliverzy (Oliver Zhou)
* @paberr (Pascal Berrang)
* @rneilson (Raymond Neilson)

Support
-------

node-lmdb is licensed to you under the terms of the MIT license, which means it comes with no warranty by default.

However,

* LMDB: Symas (the authors of LMDB) [offers commercial support of LMDB](https://symas.com/lightning-memory-mapped-database/).
* node-lmdb: If you have urgent issues with node-lmdb or would like to get support, you can contact @Venemo (the node-lmdb author).

You can also consider donating to support node-lmdb development:

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=venemo%40msn%2ecom&lc=US&item_name=to%20Timur%20Kristof%2c%20for%20node%2dlmdb%20development&item_number=node%2dlmdb&no_note=0&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donate_SM%2egif%3aNonHostedGuest)

