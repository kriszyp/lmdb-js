LMDB is probably the fastest and most efficient database on the planet, if used correctly. `lmdb-store` provides a simple interface for interacting with LMDB, as a key-value store, that makes it easy to properly leverage the power, crash-proof design, and efficiency of LMDB. Used directly, LMDB has certain characteristics that can be very challenging, including fixed db size, inefficieny with flushing small transactions, and complicated cursors usage. `lmdb-store` offers several key features that make it NodeJS idiomatic, highly performant, and easy to use than LMDB efficiently:
* Automated database size handling
* Queueing asynchronous write operations with promise-based API
* Transaction management
* Iterable queries/cursors

`lmdb-store` is build on the excellent [node-lmdb](https://github.com/Venemo/node-lmdb) package.

## Design
When an `lmdb-store` is created, an LMDB environment/database is created, and starts with a default DB size of 1MB. LMDB itself uses a fixed size, but `lmdb-store` detects whenever the database goes beyond the current size, and automatically increases the size of DB, and re-executes the write operations after resizing. With this, you do not have to make any estimates of database size, the databases automatically grow as needed (as you would expect from a database!)

`lmdb-store` is designed for synchronous reads, and asynchronous writes. In idiomatic NodeJS code, I/O operations are performed asynchronously. `lmdb-store` observes this design pattern; because LMDB is a memory-mapped database, read operations do not use any I/O (other than the slight possibility of a page fault), and can almost always be performed faster than Node's event queue callbacks can even execute, and it is easier to write code for instant synchronous values from reads. On the otherhand, in default mode with sync'ed/flushed transactions, write operations do involve I/O, and furthermore can achieve vastly higher throughput by batching operations. The entire transaction of batch operation are performed in a separate thread. Consequently, `lmdb-store` is designed for writes to go through this asynchronous batching process and return a simple promise that resolves once the write is completed and flushed to disk.

LMDB supports multiple modes of transactions, including disabling of file sync'ing (noSync), which makes transaction commits much faster. We _highly_ discourage turning off sync'ing as it leaves the database prone to data corruption. With the default sync'ing enabled, LMDB has a crash-proof design; a machine can be turned off at any point, and data can only be corrupted if the written data is actually corrupted/changed. This does make transactions slower (although not necessarily less efficient). However, by batching writes, when a database is under load, slower transactions just enable more writes per transaction, and lmdb-store is able to drive LMDB to achieve the same levels of throughput with safe sync'ed transactions as without, while still preserving the durability/safety of sync'ed transactions.

`lmdb-store` supports and encourages the use of conditional writes; this allows for atomic operations that are dependendent on previously read data, and most transactional types of operations can be written with an optimistic-locking based, atomic-conditional-write pattern.

## Usage
An lmdb-store instances is created with by using `open` export from the main module:
```
const { open } = require('lmdb-store');
// or
// import { open } from 'lmdb-store';
let myStore = open('my-store', {
	// any options go where, write-map mode is faster:
	useWritemap: true
});
```
(see store options below for more options)
Once you have a store the following methods are available:
### `store.get(key: Buffer, copy?: Function): Buffer`
Get the value at the specified key. The `key` must be a buffer, and the return value will either be a buffer if the entry exists, or `undefined` if the entry does not exist.

For typical usage, no `copy` function is needed, and returned buffer will be a safe copy of the data from the database. However, some optimizations can be performed (such as decompression or immediate parsing to an object) by using using the `copy` argument, in which case a `buffer` as a reference directly to the shared, memory-mapped data in the database will provided to the `copy` function and it will be responsible for copying the data (or decompressing directly from the db). The shared memory reference should not be used outside the `copy` function, as it will be detached and unusable.

### `store.put(key: Buffer, value: Buffer, ifValue?: Buffer): Promise<boolean>`
This will set the provided value at the specified key. If the `ifValue` parameter is set, the put will only occur if the existing value at the provided key matches the value provided by `ifValue` at the instace the commit occurs (LMDB commits are atomic by default). If the `ifValue` parameter is not set, the put will occur regardless of the previous value.

This operation will be enqueued to be written in a batch transaction. Any other operations that occur within a certain timeframe (20ms by default) will also occur in the same transaction. This will return a promise for the completion of the put. The promise will resolve once the transaction has finished committing. The resolved value of the promise will be `true` if the `put` was successful, and `false` if the put did not occur due to the `ifValue` not matching at the time of the commit.

### `store.remove(key: Buffer, ifValue?: Buffer): Promise<boolean>`
This will delete the entry at the specified key. This functions like `put`, with the same optional conditional value. This is batched along with put operations, and returns a promise indicating the success of the operation.

### `store.putSync(key: Buffer, value: Buffer, ifValue?: Buffer): boolean`
This will set the provided value at the specified key, but will do so synchronously. If this is called inside of a synchronous transaction, this put will be added to the current transaction. If not, a transaction will be started, the put will be executed, and the transaction will be committed, and then the function will return. We do not recommend this be used for any high-frequency operations as it can be vastly slower (for the main JS thread) than the `put` operation (usually takes multiple milliseconds).

### `store.removeSync(key: Buffer, ifValue?: Buffer): boolean`
This will delete the entry at the specified key. This functions like `putSync`, providing synchronous entry deletion.

### store.transaction(execute: Function)
This will begin synchronous transaction, execute the provided function, and then commit the transaction. The provided function can perform `get`s, `putSync`s, and `removeSync`s within the transaction, and the result will be committed.

### `getRange(options: { start?: Buffer, end?: Buffer, reverse?: boolean}): Iterable<{ key: Buffer, value: Buffer }>`
This starts a cursor-based query of a range of data in the database, returning an iterable that also has `map`, `filter`, and `forEach` methods. The `start` and `end` indicate the starting and ending key for the range. The `reverse` flag can be used to indicate reverse traversal. The returned cursor/query is lazy, and retrieves data _as_ iteration takes place, so a large range could specified without forcing all the entries to be read and loaded in memory upfront, and one can exit out of the loop without traversing the whole range in the database. The query is iterable, we can use it directly in a for-of:
```
for (let { key, value } of db.getRange({ start, end })) {
	// for each key-value pair in the given range
}
```
Or we can use the provided methods:
```
db.getRange({ start, end })
	.filter(({ key, value }) => test(key))
	.forEach(({ key, value }) => {
		// for each key-value pair in the given range that matched the filter
	})
```
Note that `map` and `filter` are also lazy, they will only be executed once their returned iterable is iterated or `forEach` is called on it. The `map` and `filter` functions also support async/promise-based functions, and can create async iterable if the callback functions execute asynchronously (return a promise).

### openDB(dbName: string)
LMDB supports multiple databases per environment (an environment is a single memory-mapped file). When you initialize an LMDB store with `open`, the store uses the default database, `"data"`. However, you can use multiple databases per environment and instantiate a store for each one. To do this, make sure you set the `maxDbs` (it defaults to 1). For example, we can open multiple stores for a single environment:
```
const { open } = require('lmdb-store');
let myStore = open('all-my-data', {
	maxDbs: 5
});
let usersStore = myStore.openDB('users');
let groupsStore = myStore.openDB('groups');
let productsStore = myStore.openDB('products');
```
Each of the opened/returned stores has the same API as the default store for the environment. Each of the stores for one environment also share the same batch queue and automated transactions with each other, so immediately writing data from two stores with the same environment will be batched together in the same commit. For example:
```
usersStore.put(userKey, userData);
groupsStore.put(groupKey, groupData);
```
Both these puts will be batched and after 20ms be committed in the same transaction.

### Store Options
The open method has the following signature:
`open(path, options)`
If the `path` has an `.` in it, it is treated as a file name, otherwise it is treated as a directory name, where the data will be stored. The `options` argument should be an object, and supports the following properties, all of which are optional:
* commitDelay - This is the amount of time to wait (in milliseconds) for batching write operations before committing the writes (in a transaction). This defaults to 20ms. A shorter delay means more immediate commits, but a longer delay can be more efficient at collected more writes into a single transaction and reducing I/O load.
* immediateBatchThreshold - This parameter defines a limit on the number of batched bytes in write operations that can be pending for a transaction before ldmb-store will schedule the asynchronous commit for the immediate next even turn (with setImmediate). The default is 10,000,000 (bytes).
* syncBatchThreshold - This parameter defines a limit on the number of batched bytes in write operations that can be pending for a transaction before ldmb-store will be force an immediate synchronous commit of all pending batched data for the store. This provides a safeguard against too much data being enqueued for asynchronous commit, and excessive memory usage, that can sometimes occur for a large number of continuous `put` calls without waiting for an event turn for the timer to execute. The default is 200,000,000 (bytes).
The following options map to LMDB's env flags, <a href="http://www.lmdb.tech/doc/group__mdb.html">described here</a>:
* useWritemap - Use writemaps (this is the main flag we recommend using), as it improves performance by reducing malloc calls.
* noSubdir - Treat `path` as a filename instead of directory (this is the default if the path appears to end with an extension, has '.' in it)
* noSync - Doesn't sync the data to disk. We highly discourage this flag, since it can result in data corruption and lmdb-store mitigates performance issues associated with disk syncs by batching.
* noMetaSync - This isn't as dangerous as `noSync`, but doesn't improve performance much either.
* readOnly - Self-descriptive.
* mapAsync - Not recommended, lmdb-store provides the means to ensure commits are performed in a separate thread (asyncronous to JS), and this prevents accurate notification of when flushes finish.

## Events

The `lmdb-store` instance is an <a href="https://nodejs.org/dist/latest-v11.x/docs/api/events.html#events_class_eventemitter">EventEmitter</a>, allowing application to listen to database events. There is just one event right now:

`beforecommit` - This event is fired before a batched operation begins to start transaction to write all queued writes to the database. The callback function can perform additional (asynchronous) writes (`put` and `remove`) and they will be included in the transaction about to be performed (this can be useful for updating a global version stamp based on all previous writes, for example).

## License

`lmdb-store` is licensed under the terms of the MIT license.

## Related Projects

lmdb-store is built on top of [node-lmdb](https://github.com/Venemo/node-lmdb)
cobase is built on top of lmdb-store: [cobase](https://github.com/DoctorEvidence/cobase)

<a href="https://dev.doctorevidence.com/"><img src="./assets/powers-dre.png" width="203"/></a>
