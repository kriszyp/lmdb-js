'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var fs = _interopDefault(require('fs'));
var path = require('path');
var EventEmitter = _interopDefault(require('events'));
var module$1 = require('module');
var url = require('url');
var index_js = require('weak-lru-cache/index.js');
var index_js$1 = require('ordered-binary/index.js');
var os = _interopDefault(require('os'));

const require$1 = module$1.createRequire((typeof document === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : (document.currentScript && document.currentScript.src || new URL('index.cjs', document.baseURI).href)));
let nativeMethods, dirName = path.dirname(url.fileURLToPath((typeof document === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : (document.currentScript && document.currentScript.src || new URL('index.cjs', document.baseURI).href)))).replace(/dist$/, '');
try {
	console.log(dirName);
	nativeMethods = require$1('node-gyp-build')(dirName);
	if (process.versions.modules == 93)
		require$1('v8').setFlagsFromString('--turbo-fast-api-calls');
} catch(error) {
	if (process.versions.modules == 93) {
		// use this abi version as the backup version without turbo-fast-api-calls enabled
		Object.defineProperty(process.versions, 'modules', { value: '92' });
		try {
			nativeMethods = require$1('node-gyp-build')(dirName);
		} catch(secondError) {
			throw error
		} finally {
			Object.defineProperty(process.versions, 'modules', { value: '93' });
		}
	} else
		throw error
}
const { Env, Cursor, Compression, getBufferForAddress, getAddress } = nativeMethods;

let getLastVersion;
const mapGet = Map.prototype.get;
const CachingStore = Store => class extends Store {
	constructor(dbName, options) {
		super(dbName, options);
		if (!this.env.cacheCommitter) {
			this.env.cacheCommitter = true;
			this.on('aftercommit', ({ operations, results }) => {
				results = results || [];
				let activeCache;
				for (let i = 0, l = operations.length; i < l; i++) {
					let operation = operations[i];
					if (typeof operation[1] === 'object') {
						if (activeCache) {
							if (results[i] === 0) {
								let expirationPriority = ((operation[1] || 0).length || 0) >> 10;
								let entry = mapGet.call(activeCache, operation[0]);
								if (entry)
									activeCache.used(entry, expirationPriority); // this will enter it into the LRFU
							} else
								activeCache.delete(operation[0]); // just delete it from the map
						}
					} else if (operation && operation.length === undefined) {
						activeCache = operation.cachingDb && operation.cachingDb.cache;
					}
				}
			});
		}
		this.db.cachingDb = this;
		this.cache = new index_js.WeakLRUCache(options.cache);
	}
	get(id, cacheMode) {
		let value = this.cache.getValue(id);
		if (value !== undefined)
			return value
		value = super.get(id);
		if (value && typeof value === 'object' && !cacheMode && typeof id !== 'object') {
			let entry = this.cache.setValue(id, value, this.lastSize >> 10);
			if (this.useVersions) {
				entry.version = getLastVersion();
			}
		}
		return value
	}
	getEntry(id, cacheMode) {
		let entry = this.cache.get(id);
		if (entry)
			return entry
		let value = super.get(id);
		if (value === undefined)
			return
		if (value && typeof value === 'object' && !cacheMode && typeof id !== 'object') {
			entry = this.cache.setValue(id, value, this.lastSize >> 10);
		} else {
			entry = { value };
		}
		if (this.useVersions) {
			entry.version = getLastVersion();
		}
		return entry
	}
	putEntry(id, entry, ifVersion) {
		let result = super.put(id, entry.value, entry.version, ifVersion);
		if (typeof id === 'object')
			return result
		if (result && result.then)
			this.cache.setManually(id, entry); // set manually so we can keep it pinned in memory until it is committed
		else // sync operation, immediately add to cache
			this.cache.set(id, entry);
	}
	put(id, value, version, ifVersion) {
		// if (this.cache.get(id)) // if there is a cache entry, remove it from scheduledEntries and 
		let result = super.put(id, value, version, ifVersion);
		if (typeof id !== 'object') {
			// sync operation, immediately add to cache, otherwise keep it pinned in memory until it is committed
			let entry = this.cache.setValue(id, value, result.isSync ? 0 : -1);
			if (version !== undefined)
				entry.version = typeof version === 'object' ? version.version : version;
		}
		return result
	}
	putSync(id, value, version, ifVersion) {
		if (id !== 'object') {
			// sync operation, immediately add to cache, otherwise keep it pinned in memory until it is committed
			if (value && typeof value === 'object') {
				let entry = this.cache.setValue(id, value);
				if (version !== undefined) {
					entry.version = typeof version === 'object' ? version.version : version;
				}
			} else // it is possible that  a value used to exist here
				this.cache.delete(id);
		}
		return super.putSync(id, value, version, ifVersion)
	}
	remove(id, ifVersion) {
		this.cache.delete(id);
		return super.remove(id, ifVersion)
	}
	removeSync(id, ifVersion) {
		this.cache.delete(id);
		return super.removeSync(id, ifVersion)
	}
	clear() {
		this.cache.clear();
		super.clear();
	}
	childTransaction(execute) {
		throw new Error('Child transactions are not supported in caching stores')
	}
};
function setGetLastVersion(get) {
	getLastVersion = get;
}

const SKIP = {};
if (!Symbol.asyncIterator) {
	Symbol.asyncIterator = Symbol.for('Symbol.asyncIterator');
}

class ArrayLikeIterable {
	constructor(sourceArray) {
		if (sourceArray) {
			this[Symbol.iterator] = sourceArray[Symbol.iterator].bind(sourceArray);
		}
	}
	map(func) {
		let source = this;
		let result = new ArrayLikeIterable();
		result[Symbol.iterator] = (async) => {
			let iterator = source[Symbol.iterator](async);
			return {
				next(resolvedResult) {
					let result;
					do {
						let iteratorResult;
						if (resolvedResult) {
							iteratorResult = resolvedResult;
							resolvedResult = null; // don't go in this branch on next iteration
						} else {
							iteratorResult = iterator.next();
							if (iteratorResult.then) {
								return iteratorResult.then(iteratorResult => this.next(iteratorResult))
							}
						}
						if (iteratorResult.done === true) {
							this.done = true;
							return iteratorResult
						}
						result = func(iteratorResult.value);
						if (result && result.then) {
							return result.then(result =>
								result == SKIP ?
									this.next() :
									{
										value: result
									})
						}
					} while(result == SKIP)
					return {
						value: result
					}
				},
				return() {
					return iterator.return()
				},
				throw() {
					return iterator.throw()
				}
			}
		};
		return result
	}
	[Symbol.asyncIterator]() {
		return this[Symbol.iterator](true)
	}
	filter(func) {
		return this.map(element => func(element) ? element : SKIP)
	}

	forEach(callback) {
		let iterator = this[Symbol.iterator]();
		let result;
		while ((result = iterator.next()).done !== true) {
			callback(result.value);
		}
	}
	concat(secondIterable) {
		let concatIterable = new ArrayLikeIterable();
		concatIterable[Symbol.iterator] = (async) => {
			let iterator = this[Symbol.iterator]();
			let isFirst = true;
			let concatIterator = {
				next() {
					let result = iterator.next();
					if (isFirst && result.done) {
						isFirst = false;
						iterator = secondIterable[Symbol.iterator](async);
						return iterator.next()
					}
					return result
				},
				return() {
					return iterator.return()
				},
				throw() {
					return iterator.throw()
				}
			};
			return concatIterator
		};
		return concatIterable
	}
	toJSON() {
		if (this.asArray && this.asArray.forEach) {
			return this.asArray
		}
		throw new Error('Can not serialize async iteratables without first calling resolveJSON')
		//return Array.from(this)
	}
	get asArray() {
		if (this._asArray)
			return this._asArray
		let promise = new Promise((resolve, reject) => {
			let iterator = this[Symbol.iterator](true);
			let array = [];
			let iterable = this;
			function next(result) {
				while (result.done !== true) {
					if (result.then) {
						return result.then(next)
					} else {
						array.push(result.value);
					}
					result = iterator.next();
				}
				array.iterable = iterable;
				resolve(iterable._asArray = array);
			}
			next(iterator.next());
		});
		promise.iterable = this;
		return this._asArray || (this._asArray = promise)
	}
	resolveData() {
		return this.asArray
	}
}

index_js$1.enableNullTermination();

const writeUint32Key = (key, target, start) => {
	(target.dataView || (target.dataView = new DataView(target.buffer, 0, target.length))).setUint32(start, key, true);
	return start + 4
};
const readUint32Key = (target, start) => {
	return (target.dataView || (target.dataView = new DataView(target.buffer, 0, target.length))).getUint32(start, true)
};
const writeBufferKey = (key, target, start) => {
	if (key.length > 1978)
		throw new Error('Key buffer is too long')
	target.set(key, start);
	return key.length + start
};
const readBufferKey = (target, start, end) => {
	return Uint8ArraySlice.call(target, start, end)
};

function applyKeyHandling(store) {
 	if (store.encoding == 'ordered-binary') {
		store.encoder = store.decoder = {
			encode(value) {
				if (savePosition > 6200)
					allocateSaveBuffer();
				let start = savePosition;
				savePosition = index_js$1.writeKey(value, saveBuffer, start);
				let buffer = saveBuffer.subarray(start, savePosition);
				savePosition = (savePosition + 7) & 0xfffff8;
				return buffer
			},
			decode(buffer, end) { return index_js$1.readKey(buffer, 0, end) },
			writeKey: index_js$1.writeKey,
			readKey: index_js$1.readKey,
		};
	}
	if (store.keyIsUint32) {
		store.writeKey = writeUint32Key;
		store.readKey = readUint32Key;
	} else if (store.keyIsBuffer) {
		store.writeKey = writeBufferKey;
		store.readKey = readBufferKey;
	} else if (store.keyEncoder) {
		store.writeKey = store.keyEncoder.writeKey;
		store.readKey = store.keyEncoder.readKey;
	} else {
		store.writeKey = index_js$1.writeKey;
		store.readKey = index_js$1.readKey;
	}
}

let saveBuffer, saveDataView, saveDataAddress;
let savePosition = 8000;
function allocateSaveBuffer() {
	saveBuffer = Buffer.alloc(8192);
	saveBuffer.dataView = saveDataView = new DataView(saveBuffer.buffer, saveBuffer.byteOffset, saveBuffer.byteLength);
	saveBuffer.buffer.address = getAddress(saveBuffer.buffer);
	saveDataAddress = saveBuffer.buffer.address + saveBuffer.byteOffset;
	savePosition = 0;

}
function saveKey(key, writeKey, saveTo) {
	if (savePosition > 6200) {
		allocateSaveBuffer();
	}
	let start = savePosition;
	savePosition = writeKey(key, saveBuffer, start + 4);
	saveDataView.setUint32(start, savePosition - start - 4, true);
	saveTo.saveBuffer = saveBuffer;
	savePosition = (savePosition + 7) & 0xfffff8;
	return start + saveDataAddress
}

const ITERATOR_DONE = { done: true, value: undefined };

function addQueryMethods(LMDBStore, {
	getReadTxn, env, keyBytes, keyBytesView, getLastVersion
}) {
	let renewId = 1;
	LMDBStore.onReadReset = () => renewId++;
	Object.assign(LMDBStore.prototype, {
		getValues(key, options) {
			let defaultOptions = {
				key,
				valuesForKey: true
			};
			if (options && options.snapshot === false)
				throw new Error('Can not disable snapshots for getValues')
			return this.getRange(options ? Object.assign(defaultOptions, options) : defaultOptions)
		},
		getKeys(options) {
			if (!options)
				options = {};
			options.values = false;
			return this.getRange(options)
		},
		getCount(options) {
			if (!options)
				options = {};
			options.onlyCount = true;
			return this.getRange(options)[Symbol.iterator]()
		},
		getKeysCount(options) {
			if (!options)
				options = {};
			options.onlyCount = true;
			options.values = false;
			return this.getRange(options)[Symbol.iterator]()
		},
		getValuesCount(key, options) {
			if (!options)
				options = {};
			options.key = key;
			options.valuesForKey = true;
			options.onlyCount = true;
			return this.getRange(options)[Symbol.iterator]()
		},
		getRange(options) {
			let iterable = new ArrayLikeIterable();
			if (!options)
				options = {};
			let includeValues = options.values !== false;
			let includeVersions = options.versions;
			let valuesForKey = options.valuesForKey;
			let limit = options.limit;
			let db = this.db;
			let snapshot = options.snapshot;
			iterable[Symbol.iterator] = () => {
				let currentKey = valuesForKey ? options.key : options.start;
				const reverse = options.reverse;
				let count = 0;
				let cursor, cursorRenewId;
				let txn;
				let flags = (includeValues ? 0x100 : 0) | (reverse ? 0x400 : 0) |
					(valuesForKey ? 0x800 : 0) | (options.exactMatch ? 0x4000 : 0);
				function resetCursor() {
					try {
						if (cursor)
							finishCursor();
						let writeTxn = env.writeTxn;
						txn = writeTxn || getReadTxn();
						cursor = !writeTxn && db.availableCursor;
						if (cursor) {
							db.availableCursor = null;
							if (db.cursorTxn != txn)
								cursor.renew();
							else// if (db.currentRenewId != renewId)
								flags |= 0x2000;
						} else {
							cursor = new Cursor(db);
						}
						txn.cursorCount = (txn.cursorCount || 0) + 1; // track transaction so we always use the same one
						if (snapshot === false) {
							cursorRenewId = renewId; // use shared read transaction
							txn.renewingCursorCount = (txn.renewingCursorCount || 0) + 1; // need to know how many are renewing cursors
						}
					} catch(error) {
						if (cursor) {
							try {
								cursor.close();
							} catch(error) { }
						}
						throw error
					}
				}
				resetCursor();
				let store = this;
				if (options.onlyCount) {
					flags |= 0x1000;
					let count = position(options.offset);
					finishCursor();
					return count
				}
				function position(offset) {
					let keySize = store.writeKey(currentKey, keyBytes, 0);
					let endAddress;
					if (valuesForKey) {
						if (options.start === undefined && options.end === undefined)
							endAddress = 0;
						else {
							let startAddress;
							if (store.encoder.writeKey) {
								startAddress = saveKey(options.start, store.encoder.writeKey, iterable);
								keyBytesView.setFloat64(2000, startAddress, true);
								endAddress = saveKey(options.end, store.encoder.writeKey, iterable);
							} else if ((!options.start || options.start instanceof Uint8Array) && (!options.end || options.end instanceof Uint8Array)) {
								startAddress = saveKey(options.start, index_js$1.writeKey, iterable);
								keyBytesView.setFloat64(2000, startAddress, true);
								endAddress = saveKey(options.end, index_js$1.writeKey, iterable);
							} else {
								throw new Error('Only key-based encoding is supported for start/end values')
							}
						}
					} else
						endAddress = saveKey(options.end, store.writeKey, iterable);
					return cursor.position(flags, offset || 0, keySize, endAddress)
				}

				function finishCursor() {
					if (txn.isAborted)
						return
					if (cursorRenewId)
						txn.renewingCursorCount--;
					if (--txn.cursorCount <= 0 && txn.onlyCursor) {
						cursor.close();
						txn.abort(); // this is no longer main read txn, abort it now that we are done
						txn.isAborted = true;
					} else {
						if (db.availableCursor || txn != getReadTxn())
							cursor.close();
						else { // try to reuse it
							db.availableCursor = cursor;
							db.cursorTxn = txn;
						}
					}
				}
				return {
					next() {
						let keySize, lastSize;
						if (cursorRenewId && cursorRenewId != renewId) {
							resetCursor();
							keySize = position(0);
						}
						if (count === 0) { // && includeValues) // on first entry, get current value if we need to
							keySize = position(options.offset);
						} else
							keySize = cursor.iterate();
						if (keySize === 0 ||
								(count++ >= limit)) {
							finishCursor();
							return ITERATOR_DONE
						}
						if (!valuesForKey || snapshot === false)
							currentKey = store.readKey(keyBytes, 32, keySize + 32);
						if (includeValues) {
							let value;
							lastSize = keyBytesView.getUint32(0, true);
							if (store.decoder) {
								value = store.decoder.decode(db.unsafeBuffer, lastSize);
							} else if (store.encoding == 'binary')
								value = Uint8ArraySlice.call(db.unsafeBuffer, 0, lastSize);
							else {
								value = store.db.unsafeBuffer.toString('utf8', 0, lastSize);
								if (store.encoding == 'json' && value)
									value = JSON.parse(value);
							}
							if (includeVersions)
								return {
									value: {
										key: currentKey,
										value,
										version: getLastVersion()
									}
								}
 							else if (valuesForKey)
								return {
									value
								}
							else
								return {
									value: {
										key: currentKey,
										value,
									}
								}
						} else if (includeVersions) {
							return {
								value: {
									key: currentKey,
									version: getLastVersion()
								}
							}
						} else {
							return {
								value: currentKey
							}
						}
					},
					return() {
						finishCursor();
						return ITERATOR_DONE
					},
					throw() {
						finishCursor();
						return ITERATOR_DONE
					}
				}
			};
			return iterable
		}

	});
}

function when(promise, callback, errback) {
  if (promise && promise.then) {
    return errback ?
      promise.then(callback, errback) :
      promise.then(callback)
  }
  return callback(promise)
}

var backpressureArray;

const MAX_KEY_SIZE = 1978;
const STATUS_LOCKED = 0x200000;
const WAITING_OPERATION = 0x400000;
const BACKPRESSURE_THRESHOLD = 5000000;
const TXN_DELIMITER = 0x20000000;
const TXN_COMMITTED = 0x40000000;
const BATCH_DELIMITER = 0x8000000;

const SYNC_PROMISE_SUCCESS = Promise.resolve(true);
const SYNC_PROMISE_FAIL = Promise.resolve(false);
const ABORT = {};
const CALLBACK_THREW = {};
SYNC_PROMISE_SUCCESS.isSync = true;
SYNC_PROMISE_FAIL.isSync = true;
function addWriteMethods(LMDBStore, { env, fixedBuffer, resetReadTxn, useWritemap }) {
	var unwrittenResolution, lastQueuedResolution = {}, uncommittedResolution; 
	//  stands for write instructions
	var dynamicBytes;
	function allocateInstructionBuffer() {
		dynamicBytes = Buffer.allocUnsafeSlow(0x10000);
		dynamicBytes.uint32 = new Uint32Array(dynamicBytes.buffer, 0, 0x10000 >> 2);
		dynamicBytes.uint32[0] = 0;
		dynamicBytes.float64 = new Float64Array(dynamicBytes.buffer, 0, 0x10000 >> 3);
		dynamicBytes.buffer.address = getAddress(dynamicBytes.buffer);
		dynamicBytes.address = dynamicBytes.buffer.address + dynamicBytes.byteOffset;
		dynamicBytes.position = 0;
		return dynamicBytes
	}
	var lastCompressibleFloat64 = new Float64Array(1);
	var lastCompressiblePosition = 0;
	var outstandingWriteCount = 0;
	var startAddress = 0;
	var writeTxn = null;
	var abortedNonChildTransactionWarn;
	var nextTxnCallbacks = [];
	var commitPromise;
	var enqueuedStart;

	allocateInstructionBuffer();
	dynamicBytes.uint32[0] = TXN_DELIMITER;
	function writeInstructions(flags, store, key, value, version, ifVersion) {
		let writeStatus, compressionStatus = false;
		let targetBytes, position;
		let valueBuffer;
		if (flags & 2) {
			// encode first in case we have to write a shared structure
			if (store.encoder) {
				//if (!(value instanceof Uint8Array)) TODO: in a future version, directly store buffers that are provided
				valueBuffer = store.encoder.encode(value);
				if (typeof valueBuffer == 'string')
					valueBuffer = Buffer.from(valueBuffer); // TODO: Would be nice to write strings inline in the instructions
			} else if (typeof value == 'string') {
				valueBuffer = Buffer.from(value); // TODO: Would be nice to write strings inline in the instructions
			} else if (value instanceof Uint8Array)
				valueBuffer = value;
			else
				throw new Error('Invalid value to put in database ' + value + ' (' + (typeof value) +'), consider using encoder')
		}
		if (writeTxn) {
			targetBytes = fixedBuffer;
			position = 0;
		} else {
			targetBytes = dynamicBytes;
			position = targetBytes.position;
			if (position > 8100) { // 6000 bytes
				let lastPosition = targetBytes.position;
				let lastFloat64 = targetBytes.float64;
				let lastUint32 = targetBytes.uint32;
				targetBytes = allocateInstructionBuffer();
				position = targetBytes.position;
				lastFloat64[lastPosition + 1] = targetBytes.buffer.address + position;
				lastUint32[lastPosition << 1] = 3; // pointer instruction
			}
		}
		let uint32 = targetBytes.uint32, float64 = targetBytes.float64;
		let flagPosition = position << 1; // flagPosition is the 32-bit word starting position

		// don't increment Position until we are sure we don't have any key writing errors
		uint32[flagPosition + 1] = store.db.dbi;
		let nextCompressible;
		if (flags & 4) {
			let keyStartPosition = (position << 3) + 12;
			let endPosition;
			try {
				endPosition = store.writeKey(key, targetBytes, keyStartPosition);
			} catch(error) {
				targetBytes.fill(0, keyStartPosition);
				throw error
			}
			let keySize = endPosition - keyStartPosition;
			if (keySize > MAX_KEY_SIZE) {
				targetBytes.fill(0, keyStartPosition);
				throw new Error('Key size is too large')
			}
			uint32[flagPosition + 2] = keySize;
			position = (endPosition + 16) >> 3;
			if (flags & 2) {
				uint32[(position << 1) - 1] = valueBuffer.length;
				let valueArrayBuffer = valueBuffer.buffer;
				// record pointer to value buffer
				float64[position++] = (valueArrayBuffer.address || (valueArrayBuffer.address = getAddress(valueArrayBuffer))) + valueBuffer.byteOffset;
				if (store.compression && valueBuffer.length >= store.compression.threshold) {
					flags |= 0x100000;
					float64[position] = 0;
					float64[position + 1] = store.compression.address;
					nextCompressible = targetBytes.buffer.address + (position << 3);
					compressionStatus = !lastCompressibleFloat64[lastCompressiblePosition];
					lastCompressibleFloat64[lastCompressiblePosition] = nextCompressible;
					lastCompressiblePosition = position;
					lastCompressibleFloat64 = float64;
					position += 2;
				}
			}
			if (ifVersion !== undefined) {
				if (ifVersion === null)
					flags |= 0x10;
				else {
					flags |= 0x100;
					float64[position++] = ifVersion;
				}
			}
			if (version !== undefined) {
				flags |= 0x200;
				float64[position++] = version || 0;
			}
		} else
			position++;
		targetBytes.position = position;
		//console.log('js write', (targetBytes.buffer.address + (flagPosition << 2)).toString(16), flags.toString(16))
		if (writeTxn) {
			uint32[0] = flags;
			env.write(targetBytes.buffer.address);
			return () => (uint32[0] & 1) ? SYNC_PROMISE_FAIL : SYNC_PROMISE_SUCCESS
		}
		uint32[position << 1] = 0; // clear out the next slot
		return () => {
			//writeStatus = Atomics.or(uint32, flagPosition, flags) || writeStatus
			// write flags at the end so the writer never processes mid-stream, and do so th an atomic exchanges
			//writeStatus = atomicStatus(uint32, flagPosition, flags)
			uint32[flagPosition] = flags;
			writeStatus = lastUint32[lastFlagPosition];
			while (writeStatus & STATUS_LOCKED) {
				//console.log('spin lock!')
				writeStatus = lastUint32[lastFlagPosition];
			}
			//console.log('writeStatus: ' + writeStatus.toString(16) + ' address: ' + (lastUint32.buffer.address + (lastFlagPosition << 2)).toString(16), store.path)
	
			lastUint32 = uint32;
			lastFlagPosition = flagPosition;
			outstandingWriteCount++;
			if (writeStatus) {
				if (writeStatus & TXN_DELIMITER)
					commitPromise = null;
				if (writeStatus & WAITING_OPERATION) { // write thread is waiting
					//console.log('resume batch thread', targetBytes.buffer.address + (flagPosition << 2))
					env.startWriting(0);
				} else if ((writeStatus & BATCH_DELIMITER) && !startAddress) {
					startAddress = targetBytes.buffer.address + (flagPosition << 2);
				}
			} else if (compressionStatus) {
				env.compress(nextCompressible);
			} else if (outstandingWriteCount > BACKPRESSURE_THRESHOLD) {

				console.log('backpressure');
				if (!backpressureArray)
					backpressureArray = new Int8Array(new SharedArrayBuffer(4), 0, 1);
				Atomics.wait(backpressureArray, 0, 0, 1);
			}
			if (startAddress && (flags & 8) && !enqueuedStart) {
				//console.log('start address ' + startAddress.toString(16), store.path)
				function startWriting() {
					env.startWriting(startAddress, compressionStatus ? nextCompressible : 0, (status) => {
						//console.log('finished batch', unwrittenResolution && (unwrittenResolution.uint32[unwrittenResolution.flag]).toString(16), store.path)
						resolveWrites(true);
						switch (status) {
							case 0: case 1:
							break;
							case 2:
								executeTxnCallbacks();
								console.log('user callback');
							break
							default:
							console.error(status);
							if (commitRejectPromise) {
								commitRejectPromise.reject(status);
								commitRejectPromise = null;
							}
						}
					});
					startAddress = 0;
				}
				startWriting();
			}

			if ((outstandingWriteCount & 7) === 0)
				resolveWrites();
			let newResolution = {
				uint32,
				flag: flagPosition,
				valueBuffer,
				nextResolution: null,
			};
			if (!unwrittenResolution) {
				unwrittenResolution = newResolution;
				if (!uncommittedResolution)
					uncommittedResolution = newResolution;
			}
			lastQueuedResolution.nextResolution = newResolution;
			lastQueuedResolution = newResolution;
			if (ifVersion === undefined) {
				if (!commitPromise) {
					commitPromise = new Promise((resolve, reject) => {
						newResolution.resolve = resolve;
						newResolution.reject = reject;
					});
				}
				return commitPromise
			}
			return new Promise((resolve, reject) => {
				newResolution.resolve = resolve;
				newResolution.reject = reject;
			})
		}
	}
	var lastUint32 = new Uint32Array([BATCH_DELIMITER]), lastFlagPosition = 0;
	function resolveWrites(async) {
		// clean up finished instructions
		let instructionStatus;
		while (unwrittenResolution && (instructionStatus = unwrittenResolution.uint32[unwrittenResolution.flag]) & 0x10000000) {
			//console.log('instructionStatus: ' + instructionStatus.toString(16))
			if (unwrittenResolution.callbacks) {
				nextTxnCallbacks.push(unwrittenResolution.callbacks);
				unwrittenResolution.callbacks = null;
			}
			unwrittenResolution.valueBuffer = null;
			if (instructionStatus & TXN_DELIMITER) {
				let position = unwrittenResolution.flag;
				unwrittenResolution.flag = instructionStatus & 0x1000000f;
				if (instructionStatus & 0x80000000)
					rejectCommit();
				else if (instructionStatus & TXN_COMMITTED) {
					resolveCommit(async);
				} else {
					unwrittenResolution.flag = position; // restore position for next iteration
					return // revisit when it is done (but at least free the value buffer)
				}
			} else {
				if (!unwrittenResolution.nextResolution)
					return // don't advance yet, wait to see if it a transaction delimiter that will commit
				unwrittenResolution.flag = instructionStatus;
			}
			outstandingWriteCount--;
			unwrittenResolution.debuggingPosition = unwrittenResolution.flag;
			unwrittenResolution.uint32 = null;
			unwrittenResolution = unwrittenResolution.nextResolution;
		}
		/*if (!unwrittenResolution) {
			if ((instructionStatus = lastUint32[lastFlagPosition]) & TXN_DELIMITER) {
				if (instructionStatus & 0x80000000)
					rejectCommit()
				else if (instructionStatus & TXN_COMMITTED)
					resolveCommit(async)
			}
			return
		}*/
	}
	function resolveCommit(async) {
		if (async)
			resetReadTxn();
		else
			queueMicrotask(resetReadTxn); // TODO: only do this if there are actually committed writes?
		do {
			if (uncommittedResolution.resolve) {
				let flag = uncommittedResolution.flag;
				if (flag < 0)
					uncommittedResolution.reject(new Error("Error occurred in write"));
				else if (flag & 1) {
					uncommittedResolution.resolve(false);
				} else
					uncommittedResolution.resolve(true);
					
			}
			
			if (uncommittedResolution == unwrittenResolution) {
				return uncommittedResolution = uncommittedResolution.nextResolution
			}
		} while(uncommittedResolution = uncommittedResolution.nextResolution)
	}
	var commitRejectPromise;
	function rejectCommit() {
		if (!commitRejectPromise) {
			let rejectFunction;
			commitRejectPromise = new Promise((resolve, reject) => rejectFunction = reject);
			commitRejectPromise.reject = rejectFunction;
		}
		while (uncommittedResolution != unwrittenResolution && uncommittedResolution) {
			let flag = uncommittedResolution.flag & 0xf;
			let error = new Error("Commit failed (see commitError for details)");
			error.commitError = commitRejectPromise;
			uncommittedResolution.reject(error);
			uncommittedResolution = uncommittedResolution.nextResolution;
		}
	}
	function atomicStatus(uint32, flagPosition, newStatus) {
		uint32[flagPosition] = newStatus;
		let writeStatus = lastUint32[lastFlagPosition];
		let spinLock = 0;
		while (writeStatus & STATUS_LOCKED) {
			spinLock++;
			writeStatus = lastUint32[lastFlagPosition];
		}
		if (spinLock)
			console.warn('spin lock', spinLock);
		//console.warn('writeStatus: ' + writeStatus.toString(16) + ' address: ' + (lastUint32.buffer.address + (lastFlagPosition << 2)).toString(16))
		return writeStatus
	}
	async function executeTxnCallbacks() {
		env.beginTxn(0);
		env.writeTxn = writeTxn = {};
		let promises;
		let txnCallbacks;
		for (let i = 0, l = nextTxnCallbacks.length; i < l; i++) {
			txnCallbacks = nextTxnCallbacks[i];
			for (let i = 0, l = txnCallbacks.length; i < l; i++) {
				let userTxnCallback = txnCallbacks[i];
				let asChild = userTxnCallback.asChild;
				if (asChild) {
					if (promises) {
						// must complete any outstanding transactions before proceeding
						await Promise.all(promises);
						promises = null;
					}
					env.beginTxn(1); // abortable
					
					try {
						let result = userTxnCallback.callback();
						if (result && result.then) {
							await result;
						}
						if (result === ABORT)
							env.abortTxn();
						else
							env.commitTxn();
							txnCallbacks[i] = result;
					} catch(error) {
						env.abortTxn();
						txnError(error, i);
					}
				} else {
					try {
						let result = userTxnCallback();
						txnCallbacks[i] = result;
						if (result && result.then) {
							if (!promises)
								promises = [];
							promises.push(result.catch(() => {}));
						}
					} catch(error) {
						txnError(error, i);
					}
				}
			}
		}
		nextTxnCallbacks = [];
		if (promises) { // finish any outstanding commit functions
			await Promise.all(promises);
		}
		env.writeTxn = writeTxn = false;
		console.log('async callback resume write trhead');
		return env.commitTxn()
		function txnError(error, i) {
			(txnCallbacks.errors || (txnCallbacks.errors = []))[i] = error;
			txnCallbacks[i] = CALLBACK_THREW;
		}
	}
	Object.assign(LMDBStore.prototype, {
		put(key, value, versionOrOptions, ifVersion) {
			let flags = 15;
			if (typeof versionOrOptions == 'object') {
				if (versionOrOptions.noOverwrite)
					flags |= 0x10;
				if (versionOrOptions.noDupData)
					flags |= 0x20;
				if (versionOrOptions.append)
					flags |= 0x20000;
				if (versionOrOptions.ifVersion != undefined)
					ifVersion = versionsOrOptions.ifVersion;
				versionOrOptions = versionOrOptions.version;
			}
			return writeInstructions(flags, this, key, value, this.useVersions ? versionOrOptions || 0 : undefined, ifVersion)()
		},
		remove(key, ifVersionOrValue) {
			let flags = 13;
			let ifVersion, value;
			if (ifVersionOrValue !== undefined) {
				if (this.useVersions)
					ifVersion = ifVersionOrValue;
				else {
					flags = 14;
					value = ifVersionOrValue;
				}
			}
			return writeInstructions(flags, this, key, value, undefined, ifVersion)()
		},
		ifNoExists(key, callback) {
			return this.ifVersion(key, null, callback)
		},

		ifVersion(key, version, callback) {
			if (!callback) {
				return new Batch((operations, callback) => {
					let promise = this.ifVersion(key, version, operations);
					if (callback)
						promise.then(callback);
					return promise
				})
			}
			if (writeTxn) {
				if (this.doesExist(key, version)) {
					callback();
					return SYNC_PROMISE_SUCCESS
				}
				return SYNC_PROMISE_FAIL
			}
			let finishWrite = writeInstructions(typeof key === 'undefined' ? 1 : 4, this, key, undefined, undefined, version);
			let promise;
			console.warn('wrote start of ifVersion', this.path);
			try {
				if (typeof callback === 'function') {
					promise = finishWrite(); // commit to writing the whole block in the current transaction
					callback();
				} else {
					for (let i = 0, l = callback.length; i < l; i++) {
						let operation = callback[i];
						this[operation.type](operation.key, operation.value);
					}
					promise = finishWrite(); // finish write once all the operations have been written
				}
			} finally {
				console.warn('writing end of ifVersion', this.path, (dynamicBytes.buffer.address + ((dynamicBytes.position + 1) << 3)).toString(16));
				dynamicBytes.uint32[(dynamicBytes.position + 1) << 1] = 0; // clear out the next slot
				let writeStatus = atomicStatus(dynamicBytes.uint32, (dynamicBytes.position++) << 1, 2); // atomically write the end block
				if (writeStatus & WAITING_OPERATION) {
					console.warn('ifVersion resume write thread');
					env.startWriting(0);
				}
			}
			return promise
		},
		batch(callbackOrOperations) {
			return this.ifVersion(undefined, undefined, callbackOrOperations)
		},

		putSync(key, value, versionOrOptions, ifVersion) {
			if (writeTxn)
				return this.put(key, value, versionOrOptions, ifVersion)
			else
				return this.transactionSync(() =>
					this.put(key, value, versionOrOptions, ifVersion) == SYNC_PROMISE_SUCCESS,
					{ abortable: false })
		},
		removeSync(key, ifVersionOrValue) {
			if (writeTxn)
				return this.remove(key, ifVersionOrValue)
			else
				return this.transactionSync(() =>
					this.remove(key, ifVersionOrValue) == SYNC_PROMISE_SUCCESS,
					{ abortable: false })
		},
		transaction(callback, options) {
			if (options) {
 				if (options.synchronousStart)
 					return this.transactionSync(callback, options)
 				if (options.abortable)
					return this.childTransaction(callback)
			}
			if (writeTxn) {
				// already nested in a transaction, just execute and return
				return callback()
			}
			return this.transactionAsync(callback)
		},
		childTransaction(callback) {
			if (useWritemap)
				throw new Error('Child transactions are not supported in writemap mode')
			if (writeTxn) {
				env.beginTxn(1); // abortable
				try {
					return when(callback(), (result) => {
						if (result === ABORT)
							env.abortTxn();
						else
							env.commitTxn();
						return result
					}, (error) => {
						env.abortTxn();
						throw error
					})
				} catch(error) {
					env.abortTxn();
					throw error
				}
			}
			return this.transactionAsync(callback, true)
		},
		transactionAsync(callback, asChild) {
			// TODO: strict ordering
			let txnIndex;
			let txnCallbacks;
			if (!lastQueuedResolution || !lastQueuedResolution.callbacks) {
				txnCallbacks = [asChild ? { callback, asChild } : callback];
				txnCallbacks.results = writeInstructions(8, this)();
				lastQueuedResolution.callbacks = txnCallbacks;
				txnIndex = 0;
			} else {
				txnCallbacks = lastQueuedResolution.callbacks;
				txnIndex = txnCallbacks.push(asChild ? { callback, asChild } : callback) - 1;
			}
			return txnCallbacks.results.then((results) => {
				let result = txnCallbacks[txnIndex];
				if (result === CALLBACK_THREW)
					throw txnCallbacks.errors[txnIndex]
				return result
			})
		},
		transactionSync(callback, options) {
			if (writeTxn) {
				if (!useWritemap && !this.cache && !(options && options.abortable === false))
					// already nested in a transaction, execute as child transaction (if possible) and return
					return this.childTransaction(callback)
				let result = callback(); // else just run in current transaction
				if (result == ABORT && !abortedNonChildTransactionWarn) {
					console.warn('Can not abort a transaction inside another transaction with ' + (this.cache ? 'caching enabled' : 'useWritemap enabled'));
					abortedNonChildTransactionWarn = true;
				}
				return result
			}
			try {
				this.transactions++;
				let flags = 0;
				if (!(options && options.abortable === false))
					flags = 1;
				if (!(options && options.synchronousCommit === false))
					flags |= 2;
				env.beginTxn(flags);
				writeTxn = env.writeTxn = {};
				return when(callback(), (result) => {
					try {
						if (result === ABORT)
							env.abortTxn();
						else {
							env.commitTxn();
							resetReadTxn();
						}

						return result
					} finally {
						env.writeTxn = writeTxn = null;
					}
				}, (error) => {
					try { env.abortTxn(); } catch(e) {}
					env.writeTxn = writeTxn = null;
					throw error
				})
			} catch(error) {
				try { env.abortTxn(); } catch(e) {}
				env.writeTxn = writeTxn = null;
				throw error
			}
		}
	});
	LMDBStore.prototype.del = LMDBStore.prototype.remove;
}

class Batch extends Array {
	constructor(callback) {
		this.callback = callback;
	}
	put(key, value) {
		this.push({ type: 'put', key, value });
	}
	del(key) {
		this.push({ type: 'del', key });
	}
	clear() {
		this.splice(0, this.length);
	}
	write(callback) {
		this.callback(this, callback);
	}
}

const require$2 = module$1.createRequire((typeof document === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : (document.currentScript && document.currentScript.src || new URL('index.cjs', document.baseURI).href)));
setGetLastVersion(getLastVersion$1);
const Uint8ArraySlice$1 = Uint8Array.prototype.slice;
const keyBytes = Buffer.allocUnsafeSlow(2048);
const keyBuffer = keyBytes.buffer;
const keyBytesView = keyBytes.dataView = new DataView(keyBytes.buffer, 0, 2048); // max key size is actually 1978
keyBytes.uint32 = new Uint32Array(keyBuffer, 0, 512);
keyBytes.float64 = new Float64Array(keyBuffer, 0, 256);
keyBuffer.address = getAddress(keyBuffer);
const DEFAULT_COMMIT_DELAY = 0;

const allDbs = new Map();
const SYNC_PROMISE_RESULT = Promise.resolve(true);
const SYNC_PROMISE_FAIL$1 = Promise.resolve(false);
SYNC_PROMISE_RESULT.isSync = true;
SYNC_PROMISE_FAIL$1.isSync = true;
let defaultCompression;
let lastSize;
function open(path$1, options) {
	let env = new Env();
	let scheduledTransactions;
	let scheduledOperations;
	let asyncTransactionAfter = true, asyncTransactionStrictOrder;
	let readTxn, writeTxn, readTxnRenewed;
	if (typeof path$1 == 'object' && !options) {
		options = path$1;
		path$1 = options.path;
	}
	let extension = path.extname(path$1);
	let name = path.basename(path$1, extension);
	let is32Bit = os.arch().endsWith('32');
	let remapChunks = (options && options.remapChunks) || ((options && options.mapSize) ?
		(is32Bit && options.mapSize > 0x100000000) : // larger than fits in address space, must use dynamic maps
		is32Bit); // without a known map size, we default to being able to handle large data correctly/well*/
	options = Object.assign({
		path: path$1,
		noSubdir: Boolean(extension),
		isRoot: true,
		maxDbs: 12,
		remapChunks,
		keyBytes,
		// default map size limit of 4 exabytes when using remapChunks, since it is not preallocated and we can
		// make it super huge.
		mapSize: remapChunks ? 0x10000000000000 :
			0x20000, // Otherwise we start small with 128KB
	}, options);
	if (options.asyncTransactionOrder == 'before')
		asyncTransactionAfter = false;
	else if (options.asyncTransactionOrder == 'strict') {
		asyncTransactionStrictOrder = true;
		asyncTransactionAfter = false;
	}
	if (!fs.existsSync(options.noSubdir ? path.dirname(path$1) : path$1))
		fs.mkdirSync(options.noSubdir ? path.dirname(path$1) : path$1, { recursive: true });
	if (options.compression) {
		console.log('import.meta.url', (typeof document === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : (document.currentScript && document.currentScript.src || new URL('index.cjs', document.baseURI).href)));
		if (options.compression == true) {
			if (defaultCompression)
				options.compression = defaultCompression;
			else
				defaultCompression = options.compression = new Compression({
					threshold: 1000,
					dictionary: fs.readFileSync(new URL('./dict/dict.txt', (typeof document === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : (document.currentScript && document.currentScript.src || new URL('index.cjs', document.baseURI).href)).replace(/dist[\\\/]index.cjs$/, ''))),
				});
				defaultCompression.threshold = 1000;
		} else {
			let compressionOptions = Object.assign({
				threshold: 1000,
				dictionary: fs.readFileSync(new URL('./dict/dict.txt', (typeof document === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : (document.currentScript && document.currentScript.src || new URL('index.cjs', document.baseURI).href)).replace(/dist[\\\/]index.cjs$/, ''))),
			}, options.compression);
			options.compression = new Compression(compressionOptions);
			options.compression.threshold = compressionOptions.threshold;
		}
	}

	if (options && options.clearOnStart) {
		console.info('Removing', path$1);
		fs.removeSync(path$1);
		console.info('Removed', path$1);
	}
	let useWritemap = options.useWritemap;
	try {
		env.open(options);
	} catch(error) {
		throw error
	}
	env.readerCheck(); // clear out any stale entries
	function renewReadTxn() {
		if (readTxn)
			readTxn.renew();
		else
			readTxn = env.beginTxn(0x20000);
		readTxnRenewed = setImmediate(resetReadTxn);
		return readTxn
	}
	function resetReadTxn() {
		if (readTxnRenewed) {
			LMDBStore.onReadReset();
			readTxnRenewed = null;
			if (readTxn.cursorCount - (readTxn.renewingCursorCount || 0) > 0) {
				readTxn.onlyCursor = true;
				readTxn = null;
			}
			else
				readTxn.reset();
		}
	}
	class LMDBStore extends EventEmitter {
		constructor(dbName, dbOptions) {
			super();
			if (dbName === undefined)
				throw new Error('Database name must be supplied in name property (may be null for root database)')

			const openDB = () => {
				try {
					this.db = env.openDbi(Object.assign({
						name: dbName,
						create: true,
						txn: env.writeTxn,
					}, dbOptions));
					this.db.name = dbName || null;
				} catch(error) {
					handleError(error);
				}
			};
			if (dbOptions.compression && !(dbOptions.compression instanceof Compression)) {
				if (dbOptions.compression == true && options.compression)
					dbOptions.compression = options.compression; // use the parent compression if available
				else
					dbOptions.compression = new Compression(Object.assign({
						threshold: 1000,
						dictionary: fs.readFileSync(require$2.resolve('./dict/dict.txt')),
					}), dbOptions.compression);
			}

			if (dbOptions.dupSort && (dbOptions.useVersions || dbOptions.cache)) {
				throw new Error('The dupSort flag can not be combined with versions or caching')
			}
			openDB();
			resetReadTxn(); // a read transaction becomes invalid after opening another db
			this.name = dbName;
			this.env = env;
			this.reads = 0;
			this.writes = 0;
			this.transactions = 0;
			this.averageTransactionTime = 5;
			if (dbOptions.syncBatchThreshold)
				console.warn('syncBatchThreshold is no longer supported');
			if (dbOptions.immediateBatchThreshold)
				console.warn('immediateBatchThreshold is no longer supported');
			this.commitDelay = DEFAULT_COMMIT_DELAY;
			Object.assign(this, { // these are the options that are inherited
				path: options.path,
				encoding: options.encoding,
				strictAsyncOrder: options.strictAsyncOrder,
			}, dbOptions);
			if (!this.encoding || this.encoding == 'msgpack' || this.encoding == 'cbor') {
				this.encoder = this.decoder = new (this.encoding == 'cbor' ? require$2('cbor-x').Encoder : require$2('msgpackr').Encoder)
					(Object.assign(this.sharedStructuresKey ?
					this.setupSharedStructures() : {
						copyBuffers: true // need to copy any embedded buffers that are found since we use unsafe buffers
					}, options, dbOptions));
			} else if (this.encoding == 'json') {
				this.encoder = {
					encode: JSON.stringify,
				};
			}
			applyKeyHandling(this);
			allDbs.set(dbName ? name + '-' + dbName : name, this);
		}
		openDB(dbName, dbOptions) {
			if (typeof dbName == 'object' && !dbOptions) {
				dbOptions = dbName;
				dbName = options.name;
			} else
				dbOptions = dbOptions || {};
			try {
				return dbOptions.cache ?
					new (CachingStore(LMDBStore))(dbName, dbOptions) :
					new LMDBStore(dbName, dbOptions)
			} catch(error) {
				if (error.message.indexOf('MDB_DBS_FULL') > -1) {
					error.message += ' (increase your maxDbs option)';
				}
				throw error
			}
		}
		transactionAsync(callback, asChild) {
			let lastOperation;
			if (scheduledOperations) {
				lastOperation = asyncTransactionAfter ? scheduledOperations.appendAsyncTxn :
					scheduledOperations[asyncTransactionStrictOrder ? scheduledOperations.length - 1 : 0];
			} else {
				scheduledOperations = [];
				scheduledOperations.bytes = 0;
			}
			let transactionSet;
			let transactionSetIndex;
			if (lastOperation === true) { // continue last set of transactions
				transactionSetIndex = scheduledTransactions.length - 1;
				transactionSet = scheduledTransactions[transactionSetIndex];
			} else {
				// for now we signify transactions as a true
				if (asyncTransactionAfter) // by default we add a flag to put transactions after other operations
					scheduledOperations.appendAsyncTxn = true;
				else if (asyncTransactionStrictOrder)
					scheduledOperations.push(true);
				else // in before mode, we put all the async transaction at the beginning
					scheduledOperations.unshift(true);
				if (!scheduledTransactions) {
					scheduledTransactions = [];
				}
				transactionSetIndex = scheduledTransactions.push(transactionSet = []) - 1;
			}
			let index = (transactionSet.push(asChild ?
				{asChild, callback } : callback) - 1) << 1;
			return this.scheduleCommit().results.then((results) => {
				let transactionResults = results.transactionResults[transactionSetIndex];
				let error = transactionResults[index];
				if (error)
					throw error
				return transactionResults[index + 1]
			})
		}
		getSharedBufferForGet(id) {
			let txn = ( (readTxnRenewed ? readTxn : renewReadTxn()));
			lastSize = this.keyIsCompatibility ? txn.getBinaryShared(id) : this.db.get(this.writeKey(id, keyBytes, 0));
			if (lastSize === 0xffffffff) { // not found code
				return //undefined
			}
			return lastSize
		}

		getSizeBinaryFast(id) {
			(env.writeTxn || (readTxnRenewed ? readTxn : renewReadTxn()));
			lastSize = this.db.getByBinary(this.writeKey(id, keyBytes, 0));
		}
		getString(id) {
			(env.writeTxn || (readTxnRenewed ? readTxn : renewReadTxn()));
			let string = this.db.getStringByBinary(this.writeKey(id, keyBytes, 0));
			if (string)
				lastSize = string.length;
			return string
		}
		getBinaryFast(id) {
			this.getSizeBinaryFast(id);
			return lastSize === 0xffffffff ? undefined : this.db.unsafeBuffer.subarray(0, lastSize)
		}
		getBinary(id) {
			this.getSizeBinaryFast(id);
			return lastSize === 0xffffffff ? undefined : Uint8ArraySlice$1.call(this.db.unsafeBuffer, 0, lastSize)
		}
		get(id) {
			if (this.decoder) {
				this.getSizeBinaryFast(id);
				return lastSize === 0xffffffff ? undefined : this.decoder.decode(this.db.unsafeBuffer, lastSize)
			}
			if (this.encoding == 'binary')
				return this.getBinary(id)

			let result = this.getString(id);
			if (result) {
				if (this.encoding == 'json')
					return JSON.parse(result)
			}
			return result
		}
		getEntry(id) {
			let value = this.get(id);
			if (value !== undefined) {
				if (this.useVersions)
					return {
						value,
						version: getLastVersion$1(),
						//size: lastSize
					}
				else
					return {
						value,
						//size: lastSize
					}
			}
		}
		resetReadTxn() {
			resetReadTxn();
		}
		doesExist(key, versionOrValue) {
			let txn;
			try {
				if (env.writeTxn) {
					txn = env.writeTxn;
				} else {
					txn = readTxnRenewed ? readTxn : renewReadTxn();
				}
				if (versionOrValue === undefined) {
					this.getSizeBinaryFast(key);
					return lastSize !== 0xffffffff
				}
				else if (this.useVersions) {
					this.getSizeBinaryFast(key);
					return lastSize !== 0xffffffff && matches(getLastVersion$1(), versionOrValue)
				}
				else {
					if (this.encoder) {
						versionOrValue = this.encoder.encode(versionOrValue);
					}
					if (typeof versionOrValue == 'string')
						versionOrValue = Buffer.from(versionOrValue);
					return this.getValuesCount(key, { start: versionOrValue, exactMatch: true}) > 0
				}
			} catch(error) {
				return handleError(error)
			}
		}
		batch(operations) {
			/*if (writeTxn) {
				this.commitBatchNow(operations.map(operation => [this.db, operation.key, operation.value]))
				return Promise.resolve(true)
			}*/
			let scheduledOperations = this.getScheduledOperations();
			for (let operation of operations) {
				let value = operation.value;
				scheduledOperations.push([operation.key, value]);
				scheduledOperations.bytes += operation.key.length + (value && value.length || 0) + 200;
			}
			return this.scheduleCommit().unconditionalResults
		}
		backup(path) {
			return new Promise((resolve, reject) => env.copy(path, false, (error) => {
				if (error) {
					reject(error);
				} else {
					resolve();
				}
			}))
		}
		close() {
			this.db.close();
			if (this.isRoot) {
				if (readTxn) {
					try {
						readTxn.abort();
					} catch(error) {}
				}
				readTxnRenewed = null;
				env.close();
			}
		}
		getStats() {
			try {
				let stats = this.db.stat(readTxnRenewed ? readTxn : renewReadTxn());
				return stats
			}
			catch(error) {
				return handleError(error)
			}
		}
		sync(callback) {
			return env.sync(callback || function(error) {
				if (error) {
					console.error(error);
				}
			})
		}
		deleteDB() {
			this.transactionSync(() =>
				this.db.drop({
					justFreePages: false
				})
			, { abortable: false });
		}
		clear() {
			this.transactionSync(() =>
				this.db.drop({
					justFreePages: true
				})
			, { abortable: false });
			if (this.encoder && this.encoder.structures)
				this.encoder.structures = [];

		}
		readerCheck() {
			return env.readerCheck()
		}
		readerList() {
			return env.readerList().join('')
		}
		setupSharedStructures() {
			const getStructures = () => {
				let lastVersion; // because we are doing a read here, we may need to save and restore the lastVersion from the last read
				if (this.useVersions)
					lastVersion = getLastVersion$1();
				try {
					let buffer = this.getBinary(this.sharedStructuresKey);
					if (this.useVersions)
						setLastVersion(lastVersion);
					return buffer ? this.encoder.decode(buffer) : []
				} catch(error) {
					return handleError(error)
				}
			};
			return {
				saveStructures: (structures, previousLength) => {
					return this.transactionSync(() => {
						let existingStructuresBuffer = this.getBinary(this.sharedStructuresKey);
						let existingStructures = existingStructuresBuffer ? this.encoder.decode(existingStructuresBuffer) : [];
						if (existingStructures.length != previousLength)
							return false // it changed, we need to indicate that we couldn't update
						this.put(this.sharedStructuresKey, structures);
					}, { abortable: false, synchronousCommit: false })
				},
				getStructures,
				copyBuffers: true // need to copy any embedded buffers that are found since we use unsafe buffers
			}
		}
	}
	// if caching class overrides putSync, don't want to double call the caching code
	const putSync = LMDBStore.prototype.putSync;
	const removeSync = LMDBStore.prototype.removeSync;
	addQueryMethods(LMDBStore, { env, getReadTxn() {
		return readTxnRenewed ? readTxn : renewReadTxn()
	}, saveKey: saveKey$1, keyBytes, keyBytesView, getLastVersion: getLastVersion$1 });
	addWriteMethods(LMDBStore, { env, fixedBuffer: keyBytes, resetReadTxn, useWritemap });
	return options.cache ?
		new (CachingStore(LMDBStore))(options.name || null, options) :
		new LMDBStore(options.name || null, options)
	function handleError(error, store, txn, retry) {
		try {
			if (writeTxn)
				writeTxn.abort();
		} catch(error) {}

		if (error.message.startsWith('MDB_') &&
				!(error.message.startsWith('MDB_KEYEXIST') || error.message.startsWith('MDB_NOTFOUND')) ||
				error.message == 'The transaction is already closed.') {
			resetReadTxn(); // separate out cursor-based read txns
			try {
				if (readTxn) {
					readTxn.abort();
					readTxn.isAborted = true;
				}
			} catch(error) {}
			readTxn = null;
		}
		if (error.message.startsWith('MDB_PROBLEM'))
			console.error(error);
		error.message = 'In database ' + name + ': ' + error.message;
		throw error
	}
}

function matches(previousVersion, ifVersion){
	let matches;
	if (previousVersion) {
		if (ifVersion) {
			matches = previousVersion == ifVersion;
		} else {
			matches = false;
		}
	} else {
		matches = !ifVersion;
	}
	return matches
}
function getLastEntrySize() {
	return lastSize
}
function getLastVersion$1() {
	return keyBytesView.getFloat64(16, true)
}

function setLastVersion(version) {
	return keyBytesView.setFloat64(16, version, true)
}
let saveBuffer$1, saveDataView$1, saveDataAddress$1;
let savePosition$1 = 8000;
function allocateSaveBuffer$1() {
	saveBuffer$1 = Buffer.alloc(8192);
	saveBuffer$1.dataView = saveDataView$1 = new DataView(saveBuffer$1.buffer, saveBuffer$1.byteOffset, saveBuffer$1.byteLength);
	saveBuffer$1.buffer.address = getAddress(saveBuffer$1.buffer);
	saveDataAddress$1 = saveBuffer$1.buffer.address + saveBuffer$1.byteOffset;
	savePosition$1 = 0;

}
function saveKey$1(key, writeKey, saveTo) {
	if (savePosition$1 > 6200) {
		allocateSaveBuffer$1();
	}
	let start = savePosition$1;
	savePosition$1 = writeKey(key, saveBuffer$1, start + 4);
	saveDataView$1.setUint32(start, savePosition$1 - start - 4, true);
	saveTo.saveBuffer = saveBuffer$1;
	savePosition$1 = (savePosition$1 + 7) & 0xfffff8;
	return start + saveDataAddress$1
}

Object.defineProperty(exports, 'bufferToKeyValue', {
	enumerable: true,
	get: function () {
		return index_js$1.fromBufferKey;
	}
});
Object.defineProperty(exports, 'keyValueToBuffer', {
	enumerable: true,
	get: function () {
		return index_js$1.toBufferKey;
	}
});
exports.ABORT = ABORT;
exports.allDbs = allDbs;
exports.getLastEntrySize = getLastEntrySize;
exports.getLastVersion = getLastVersion$1;
exports.open = open;
exports.setLastVersion = setLastVersion;
