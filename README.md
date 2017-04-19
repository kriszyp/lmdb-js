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

### Data Types in node-lmdb

LMDB is very simple and fast. Using node-lmdb provides close to the native C API functionally, but expressed via a natural
javascript API. To make simple things simple, node-lmdb defaults to presenting keys and values in LMDB as strings.
For convenience number and boolean values are also supported.

The simplest way to store other data types as keys or values is to use `JSON.stringify` before putting it into the database
and `JSON.parse` when you retrieve the data.

For more complex use cases access to keys and values as binary (node.js `Buffer` type) is provided. In LMDB itself keys 
(with one exception) and values are simply binary sequences of bytes. You can retrieve a key or value from an LMDB database
as binary even if it was written as a string. The same does not apply in reverse! Using binary access
also allows interoperation with LMDB databases created by, or shared with applications that use data serialisation formats
other than utf-16 strings (including, in particular, strings using other encodings such as utf-8).

The one exception in LMDBs representation of keys is an optimisation for fixed-length keys. This is exposed
by node-lmdb for one particular fixed length type: unsigned 32 bit integers. To use this optimisation specify `keyIsUint32: true`
to `openDbi`. Because the `keyIsUint32 : true` option is passed through to LMDB and stored in the LMDB metadata for the database,
a database created with this option set cannot be accessed without setting this option, and vice-versa.


When using a cursor keys are read from the database and it is necessary to specify how the keys should be returned.
The most direct mapping from LMDB C API is as a node.js Buffer (binary), however it is often more convenient to
return the key as a string. To create a cursor that returns keys as Buffers, provide a third `true` prameter to the `cursor
constructor`. Set the third parameter to `false` to always return keys as strings. Note that this parameter is ignored if the
`dbi` was opened with `keyIsUint32` set - in this case all cursor functions will return the key as an integer.

If the third parameter to the `cursor constructor` is *not* given then:
   * If the `dbi` was opened with `keyIsUint32` set the key is returned as an integer
   * If the value is being read as binary (`getCurrentBinary` or `getCurrentBinaryUnsafe`) the key is returned as a binary `Buffer`.
   * Otherwise the key is returned as a `string`.
This mode is deprecated and may be removed (replaced by a default as if the `cursor constructor` third parameter were `false`) in a future release.

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
and `cursor.getCurrentBinaryUnsafe()` is **only valid until the next `put` operation or the end of the transaction**.
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
git remote add lmdb https://github.com/LMDB/lmdb.git
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
