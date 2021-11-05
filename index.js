import { extname, basename, dirname} from 'path';
import EventEmitter from 'events';
import { Env, Compression, getAddress, require, arch, fs } from './native.js';
import { CachingStore, setGetLastVersion } from './caching.js';
import { addQueryMethods } from './query.js';
import { addWriteMethods } from './writer.js';
import { applyKeyHandling } from './keys.js';
import { Encoder as MsgpackrEncoder } from 'msgpackr';
const binaryBuffer = Symbol('binaryBuffer');
setGetLastVersion(getLastVersion);
const Uint8ArraySlice = Uint8Array.prototype.slice;
let keyBytes, keyBytesView;
const buffers = [];

const DEFAULT_SYNC_BATCH_THRESHOLD = 200000000; // 200MB
const DEFAULT_IMMEDIATE_BATCH_THRESHOLD = 10000000; // 10MB
const DEFAULT_COMMIT_DELAY = 0;
const READING_TNX = {
	readOnly: true
};

export const allDbs = new Map();
let env;
let defaultCompression;
let lastSize, lastOffset, lastVersion;
let abortedNonChildTransactionWarn;
export function open(path, options) {
	if (!keyBytes)
		allocateFixedBuffer();
	let env = new Env();
	let committingWrites;
	let scheduledTransactions;
	let scheduledOperations;
	let asyncTransactionAfter = true, asyncTransactionStrictOrder;
	let transactionWarned;
	let readTxn, writeTxn, pendingBatch, currentCommit, runNextBatch, readTxnRenewed;
	if (typeof path == 'object' && !options) {
		options = path;
		path = options.path;
	}
	let extension = extname(path);
	let name = basename(path, extension);
	let is32Bit = arch().endsWith('32');
	let remapChunks = (options && options.remapChunks) || ((options && options.mapSize) ?
		(is32Bit && options.mapSize > 0x100000000) : // larger than fits in address space, must use dynamic maps
		is32Bit); // without a known map size, we default to being able to handle large data correctly/well*/
	options = Object.assign({
		path,
		noSubdir: Boolean(extension),
		isRoot: true,
		maxDbs: 12,
		remapChunks,
		keyBytes,
		//overlappingSync: true,
		// default map size limit of 4 exabytes when using remapChunks, since it is not preallocated and we can
		// make it super huge.
		mapSize: remapChunks ? 0x10000000000000 :
			0x20000, // Otherwise we start small with 128KB
	}, options);
	if (options.asyncTransactionOrder == 'before') {
		console.warn('asyncTransactionOrder: "before" is deprecated');
		asyncTransactionAfter = false;
	} else if (options.asyncTransactionOrder == 'strict') {
		asyncTransactionStrictOrder = true;
		asyncTransactionAfter = false;
	}
	if (!fs.existsSync(options.noSubdir ? dirname(path) : path))
		fs.mkdirSync(options.noSubdir ? dirname(path) : path, { recursive: true });
	if (options.compression) {
		let setDefault;
		if (options.compression == true) {
			if (defaultCompression)
				options.compression = defaultCompression;
			else
				defaultCompression = options.compression = new Compression({
					threshold: 1000,
					dictionary: fs.readFileSync(new URL('./dict/dict.txt', import.meta.url.replace(/dist[\\\/]index.cjs$/, ''))),
				});
				defaultCompression.threshold = 1000;
		} else {
			let compressionOptions = Object.assign({
				threshold: 1000,
				dictionary: fs.readFileSync(new URL('./dict/dict.txt', import.meta.url.replace(/dist[\\\/]index.cjs$/, ''))),
			}, options.compression);
			options.compression = new Compression(compressionOptions);
			options.compression.threshold = compressionOptions.threshold;
		}
	}

	if (options && options.clearOnStart) {
		console.info('Removing', path);
		fs.removeSync(path);
		console.info('Removed', path);
	}
	env.open(options);
	env.readerCheck(); // clear out any stale entries
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
	let stores = [];
	class LMDBStore extends EventEmitter {
		constructor(dbName, dbOptions) {
			super();
			if (dbName === undefined)
				throw new Error('Database name must be supplied in name property (may be null for root database)');

			const openDB = () => {
				this.db = env.openDbi(Object.assign({
					name: dbName,
					create: true,
					txn: env.writeTxn,
				}, dbOptions));
				this.db.name = dbName || null;
			};
			if (dbOptions.compression && !(dbOptions.compression instanceof Compression)) {
				if (dbOptions.compression == true && options.compression)
					dbOptions.compression = options.compression; // use the parent compression if available
				else
					dbOptions.compression = new Compression(Object.assign({
						threshold: 1000,
						dictionary: fs.readFileSync(require.resolve('./dict/dict.txt')),
					}), dbOptions.compression);
			}

			if (dbOptions.dupSort && (dbOptions.useVersions || dbOptions.cache)) {
				throw new Error('The dupSort flag can not be combined with versions or caching');
			}
			openDB();
			resetReadTxn(); // a read transaction becomes invalid after opening another db
			this.name = dbName;
			this.status = 'open';
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
				this.encoder = this.decoder = new (this.encoding == 'cbor' ? require('cbor-x').Encoder : MsgpackrEncoder)
					(Object.assign(this.sharedStructuresKey ?
					this.setupSharedStructures() : {
						copyBuffers: true, // need to copy any embedded buffers that are found since we use unsafe buffers
					}, options, dbOptions));
			} else if (this.encoding == 'json') {
				this.encoder = {
					encode: JSON.stringify,
				};
			}
			applyKeyHandling(this);
			allDbs.set(dbName ? name + '-' + dbName : name, this);
			stores.push(this);
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
					new LMDBStore(dbName, dbOptions);
			} catch(error) {
				if (error.message.indexOf('MDB_DBS_FULL') > -1) {
					error.message += ' (increase your maxDbs option)';
				}
				throw error;
			}
		}
		open(dbOptions, callback) {
			let db = this.openDB(dbOptions);
			if (callback)
				callback(null, db);
			return db;
		}
		transactionAsync(callback, asChild) {
			let lastOperation;
			let after, strictOrder;
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
					throw error;
				return transactionResults[index + 1];
			});
		}
		getSharedBufferForGet(id) {
			let txn = (writeTxn || (readTxnRenewed ? readTxn : renewReadTxn()));
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
			return string;
		}
		getBinaryFast(id) {
			this.getSizeBinaryFast(id);
			return lastSize === 0xffffffff ? undefined : this.db.unsafeBuffer.subarray(0, lastSize);
		}
		getBinary(id) {
			this.getSizeBinaryFast(id);
			return lastSize === 0xffffffff ? undefined : Uint8ArraySlice.call(this.db.unsafeBuffer, 0, lastSize);
		}
		get(id) {
			if (this.decoder) {
				this.getSizeBinaryFast(id);
				return lastSize === 0xffffffff ? undefined : this.decoder.decode(this.db.unsafeBuffer, lastSize);
			}
			if (this.encoding == 'binary')
				return this.getBinary(id);

			let result = this.getString(id);
			if (result) {
				if (this.encoding == 'json')
					return JSON.parse(result);
			}
			return result;
		}
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
		}
		resetReadTxn() {
			resetReadTxn();
		}
		doesExist(key, versionOrValue) {
			if (!env.writeTxn)
				readTxnRenewed ? readTxn : renewReadTxn();
			if (versionOrValue === undefined) {
				this.getSizeBinaryFast(key);
				return lastSize !== 0xffffffff;
			}
			else if (this.useVersions) {
				this.getSizeBinaryFast(key);
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
		}
		backup(path) {
			return new Promise((resolve, reject) => env.copy(path, false, (error) => {
				if (error) {
					reject(error);
				} else {
					resolve();
				}
			}));
		}
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
		}
		isOperational() {
			return this.status == 'open';
		}
		getStats() {
			return this.db.stat(readTxnRenewed ? readTxn : renewReadTxn());
		}
		sync(callback) {
			return env.sync(callback || function(error) {
				if (error) {
					console.error(error);
				}
			});
		}
		deleteDB() {
			console.warn('deleteDB() is deprecated, use drop or dropSync instead');
			return this.dropSync();
		}
		dropSync() {
			this.transactionSync(() =>
				this.db.drop({
					justFreePages: false
				}),
			{ abortable: false });
		}
		clear(callback) {
			if (typeof callback == 'function')
				return this.clearAsync(callback);
			console.warn('clear() is deprecated, use clearAsync or clearSync instead');
			this.clearSync();
		}
		clearSync() {
			if (this.encoder && this.encoder.structures)
				this.encoder.structures = [];
			this.transactionSync(() =>
				this.db.drop({
					justFreePages: true
				}),
			{ abortable: false });
		}
		readerCheck() {
			return env.readerCheck();
		}
		readerList() {
			return env.readerList().join('');
		}
		setupSharedStructures() {
			const getStructures = () => {
				let lastVersion; // because we are doing a read here, we may need to save and restore the lastVersion from the last read
				if (this.useVersions)
					lastVersion = getLastVersion();
				let buffer = this.getBinary(this.sharedStructuresKey);
				if (this.useVersions)
					setLastVersion(lastVersion);
				return buffer ? this.encoder.decode(buffer) : [];
			};
			return {
				saveStructures: (structures, previousLength) => {
					return this.transactionSyncStart(() => {
						let existingStructuresBuffer = this.getBinary(this.sharedStructuresKey);
						let existingStructures = existingStructuresBuffer ? this.encoder.decode(existingStructuresBuffer) : [];
						if (existingStructures.length != previousLength)
							return false; // it changed, we need to indicate that we couldn't update
						this.put(this.sharedStructuresKey, structures);
					});
				},
				getStructures,
				copyBuffers: true, // need to copy any embedded buffers that are found since we use unsafe buffers
			};
		}
	}
	// if caching class overrides putSync, don't want to double call the caching code
	const putSync = LMDBStore.prototype.putSync;
	const removeSync = LMDBStore.prototype.removeSync;
	addQueryMethods(LMDBStore, { env, getReadTxn() {
		return readTxnRenewed ? readTxn : renewReadTxn();
	}, saveKey, keyBytes, keyBytesView, getLastVersion });
	addWriteMethods(LMDBStore, { env, fixedBuffer: keyBytes, resetReadTxn, binaryBuffer, ...options });
	LMDBStore.prototype.supports = {
		permanence: true,
		bufferKeys: true,
		promises: true,
		snapshots: true,
		clear: true,
		status: true,
		deferredOpen: true,
		openCallback: true,	
	};
	return options.cache ?
		new (CachingStore(LMDBStore))(options.name || null, options) :
		new LMDBStore(options.name || null, options);
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

class Entry {
	constructor(value, version, db) {
		this.value = value;
		this.version = version;
		this.db = db;
	}
	ifSamePut() {

	}
	ifSameRemove() {

	}
}
export function getLastEntrySize() {
	return lastSize;
}
export function getLastVersion() {
	return keyBytesView.getFloat64(16, true);
}

export function setLastVersion(version) {
	return keyBytesView.setFloat64(16, version, true);
}
export function asBinary(buffer) {
	return {
		[binaryBuffer]: buffer
	};
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
function allocateFixedBuffer() {
	keyBytes = Buffer.allocUnsafeSlow(2048);
	const keyBuffer = keyBytes.buffer;
	keyBytesView = keyBytes.dataView = new DataView(keyBytes.buffer, 0, 2048); // max key size is actually 1978
	keyBytes.uint32 = new Uint32Array(keyBuffer, 0, 512);
	keyBytes.float64 = new Float64Array(keyBuffer, 0, 256);
	keyBytes.uint32.address = keyBytes.address = keyBuffer.address = getAddress(keyBuffer);
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
	return start + saveDataAddress;
}
