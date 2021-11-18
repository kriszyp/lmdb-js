import { ArrayLikeIterable }  from './util/ArrayLikeIterable.js';
import { getAddress, Cursor, setGlobalBuffer }  from './native.js';
import { saveKey }  from './keys.js';
import { writeKey }  from 'ordered-binary/index.js';
import { binaryBuffer } from './write.js';
const ITERATOR_DONE = { done: true, value: undefined };
const Uint8ArraySlice = Uint8Array.prototype.slice;
let getValueBytes = makeReusableBuffer(0);
let lastSize;

export function addReadMethods(LMDBStore, {
	getReadTxn, env, keyBytes, keyBytesView, getLastVersion
}) {
	let readTxn, readTxnRenewed;
	let renewId = 1;
	Object.assign(LMDBStore.prototype, {
		getString(id) {
			(env.writeTxn || (readTxnRenewed ? readTxn : renewReadTxn()));
			let string = this.db.getStringByBinary(this.writeKey(id, keyBytes, 0));
			if (typeof string === 'number') { // indicates the buffer wasn't large enough
				this._allocateGetBuffer(string);
				// and then try again
				string = this.db.getStringByBinary(this.writeKey(id, keyBytes, 0));
			}
			if (string)
				lastSize = string.length;
			return string;
		},
		getBinaryFast(id) {
			(env.writeTxn || (readTxnRenewed ? readTxn : renewReadTxn()));
			try {
				lastSize = this.db.getByBinary(this.writeKey(id, keyBytes, 0));
			} catch (error) {
				if (error.message.startsWith('MDB_BAD_VALSIZE') && this.writeKey(id, keyBytes, 0) == 0)
					error = new Error('Zero length key is not allowed in LMDB')
				throw error
			}
			let compression = this.compression;
			let bytes = compression ? compression.getValueBytes : getValueBytes;
			if (lastSize > bytes.maxLength) {
				if (lastSize === 0xffffffff)
					return;
				bytes = this._allocateGetBuffer(lastSize);
				lastSize = this.db.getByBinary(this.writeKey(id, keyBytes, 0));
			}
			bytes.length = lastSize;
			return bytes;
		},
		_allocateGetBuffer(lastSize) {
			let newLength = Math.min(Math.max(lastSize * 2, 0x1000), 0xfffffff8);
			let bytes;
			if (this.compression) {
				let dictionary = this.compression.dictionary || [];
				let dictLength = (dictionary.length >> 3) << 3;// make sure it is word-aligned
				bytes = makeReusableBuffer(newLength + dictLength);
				bytes.set(dictionary) // copy dictionary into start
				this.compression.setBuffer(bytes, dictLength);
				// the section after the dictionary is the target area for get values
				bytes = bytes.subarray(dictLength);
				bytes.maxLength = newLength;
				Object.defineProperty(bytes, 'length', { value: newLength, writable: true, configurable: true });
				this.compression.getValueBytes = bytes;
			} else {
				bytes = makeReusableBuffer(newLength);
				setGlobalBuffer(bytes);
				getValueBytes = bytes;
			}
			return bytes;
		},
		getBinary(id) {
			let fastBuffer = this.getBinaryFast(id);
			return fastBuffer && Uint8ArraySlice.call(fastBuffer, 0, lastSize);
		},
		get(id) {
			if (this.decoder) {
				let bytes = this.getBinaryFast(id);
				return bytes && this.decoder.decode(bytes);
			}
			if (this.encoding == 'binary')
				return this.getBinary(id);

			let result = this.getString(id);
			if (result) {
				if (this.encoding == 'json')
					return JSON.parse(result);
			}
			return result;
		},
		getEntry(id) {
			let value = this.get(id);
			if (value !== undefined) {
				if (this.useVersions)
					return {
						value,
						version: getLastVersion(),
						//size: lastSize
					};
				else
					return {
						value,
						//size: lastSize
					};
			}
		},
		resetReadTxn() {
			resetReadTxn();
		},
		doesExist(key, versionOrValue) {
			if (!env.writeTxn)
				readTxnRenewed ? readTxn : renewReadTxn();
			if (versionOrValue === undefined) {
				this.getBinaryFast(key);
				return lastSize !== 0xffffffff;
			}
			else if (this.useVersions) {
				this.getBinaryFast(key);
				return lastSize !== 0xffffffff && matches(getLastVersion(), versionOrValue);
			}
			else {
				if (versionOrValue && versionOrValue[binaryBuffer])
					versionOrValue = versionOrValue[binaryBuffer];
				else if (this.encoder)
					versionOrValue = this.encoder.encode(versionOrValue);
				if (typeof versionOrValue == 'string')
					versionOrValue = Buffer.from(versionOrValue);
				return this.getValuesCount(key, { start: versionOrValue, exactMatch: true}) > 0;
			}
		},
		getValues(key, options) {
			let defaultOptions = {
				key,
				valuesForKey: true
			};
			if (options && options.snapshot === false)
				throw new Error('Can not disable snapshots for getValues');
			return this.getRange(options ? Object.assign(defaultOptions, options) : defaultOptions);
		},
		getKeys(options) {
			if (!options)
				options = {};
			options.values = false;
			return this.getRange(options);
		},
		getCount(options) {
			if (!options)
				options = {};
			options.onlyCount = true;
			return this.getRange(options)[Symbol.iterator]();
		},
		getKeysCount(options) {
			if (!options)
				options = {};
			options.onlyCount = true;
			options.values = false;
			return this.getRange(options)[Symbol.iterator]();
		},
		getValuesCount(key, options) {
			if (!options)
				options = {};
			options.key = key;
			options.valuesForKey = true;
			options.onlyCount = true;
			return this.getRange(options)[Symbol.iterator]();
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
			let compression = this.compression;
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
						txn = writeTxn || (readTxnRenewed ? readTxn : renewReadTxn());
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
						throw error;
					}
				}
				resetCursor();
				let store = this;
				if (options.onlyCount) {
					flags |= 0x1000;
					let count = position(options.offset);
					finishCursor();
					return count;
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
								startAddress = saveKey(options.start, writeKey, iterable);
								keyBytesView.setFloat64(2000, startAddress, true);
								endAddress = saveKey(options.end, writeKey, iterable);
							} else {
								throw new Error('Only key-based encoding is supported for start/end values');
								let encoded = store.encoder.encode(options.start);
								let bufferAddress = encoded.buffer.address || (encoded.buffer.address = getAddress(encoded) - encoded.byteOffset);
								startAddress = bufferAddress + encoded.byteOffset;
							}
						}
					} else
						endAddress = saveKey(options.end, store.writeKey, iterable);
					return cursor.position(flags, offset || 0, keySize, endAddress);
				}

				function finishCursor() {
					if (txn.isAborted)
						return;
					if (cursorRenewId)
						txn.renewingCursorCount--;
					if (--txn.cursorCount <= 0 && txn.onlyCursor) {
						cursor.close();
						txn.abort(); // this is no longer main read txn, abort it now that we are done
						txn.isAborted = true;
					} else {
						if (db.availableCursor || txn != readTxn)
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
							return ITERATOR_DONE;
						}
						if (!valuesForKey || snapshot === false)
							currentKey = store.readKey(keyBytes, 32, keySize + 32);
						if (includeValues) {
							let value;
							lastSize = keyBytesView.getUint32(0, true);
							let bytes = compression ? compression.getValueBytes : getValueBytes;
							if (lastSize > bytes.maxLength) {
								bytes = store._allocateGetBuffer(lastSize);
								cursor.getCurrentValue();
							}
							bytes.length = lastSize;
							if (store.decoder) {
								value = store.decoder.decode(bytes, lastSize);
							} else if (store.encoding == 'binary')
								value = Uint8ArraySlice.call(bytes, 0, lastSize);
							else {
								value = bytes.toString('utf8', 0, lastSize);
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
								};
 							else if (valuesForKey)
								return {
									value
								};
							else
								return {
									value: {
										key: currentKey,
										value,
									}
								};
						} else if (includeVersions) {
							return {
								value: {
									key: currentKey,
									version: getLastVersion()
								}
							};
						} else {
							return {
								value: currentKey
							};
						}
					},
					return() {
						finishCursor();
						return ITERATOR_DONE;
					},
					throw() {
						finishCursor();
						return ITERATOR_DONE;
					}
				};
			};
			return iterable;
		},
		getMany(keys, callback) {
			let results = new Array(keys.length);
			for (let i = 0, l = keys.length; i < l; i++) {
				results[i] = get.call(this, keys[i]);
			}
			if (callback)
				callback(null, results);
			return Promise.resolve(results); // we may eventually make this a true async operation
		},
		getSharedBufferForGet(id) {
			let txn = (env.writeTxn || (readTxnRenewed ? readTxn : renewReadTxn()));
			lastSize = this.keyIsCompatibility ? txn.getBinaryShared(id) : this.db.get(this.writeKey(id, keyBytes, 0));
			if (lastSize === 0xffffffff) { // not found code
				return; //undefined
			}
			return lastSize;
			lastSize = keyBytesView.getUint32(0, true);
			let bufferIndex = keyBytesView.getUint32(12, true);
			lastOffset = keyBytesView.getUint32(8, true);
			let buffer = buffers[bufferIndex];
			let startOffset;
			if (!buffer || lastOffset < (startOffset = buffer.startOffset) || (lastOffset + lastSize > startOffset + 0x100000000)) {
				if (buffer)
					env.detachBuffer(buffer.buffer);
				startOffset = (lastOffset >>> 16) * 0x10000;
				console.log('make buffer for address', bufferIndex * 0x100000000 + startOffset);
				buffer = buffers[bufferIndex] = Buffer.from(getBufferForAddress(bufferIndex * 0x100000000 + startOffset));
				buffer.startOffset = startOffset;
			}
			lastOffset -= startOffset;
			return buffer;
			return buffer.slice(lastOffset, lastOffset + lastSize);/*Uint8ArraySlice.call(buffer, lastOffset, lastOffset + lastSize)*/
		},
		close(callback) {
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
			this.status = 'closed';
			if (callback)
				callback();			
		},
		getStats() {
			return this.db.stat(readTxnRenewed ? readTxn : renewReadTxn());
		}
	});
	let get = LMDBStore.prototype.get;
	function renewReadTxn() {
		if (readTxn)
			readTxn.renew();
		else
			readTxn = env.beginTxn(0x20000);
		readTxnRenewed = setImmediate(resetReadTxn);
		return readTxn;
	}
	function resetReadTxn() {
		if (readTxnRenewed) {
			renewId++;
			readTxnRenewed = null;
			if (readTxn.cursorCount - (readTxn.renewingCursorCount || 0) > 0) {
				readTxn.onlyCursor = true;
				readTxn = null;
			}
			else
				readTxn.reset();
		}
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
	return matches;
}
export function makeReusableBuffer(size) {
	let bytes = Buffer.alloc(size)
	bytes.maxLength = size;
	Object.defineProperty(bytes, 'length', { value: size, writable: true, configurable: true });
	return bytes;
}
