import { Compression, getAddress, require, arch, fs, path as pathModule, lmdbError, EventEmitter, MsgpackrEncoder, Env, tmpdir, os, isWorkerThread } from './external.js';
import { CachingStore, setGetLastVersion } from './caching.js';
import { addReadMethods, makeReusableBuffer } from './read.js';
import { addWriteMethods } from './write.js';
import { applyKeyHandling } from './keys.js';
setGetLastVersion(getLastVersion);
let keyBytes, keyBytesView;
const buffers = [];


// this is hard coded as an upper limit because it is important assumption of the fixed buffers in writing instructions
// this corresponds to the max key size for 8KB pages, which is currently the default
const MAX_KEY_SIZE = 4026;
const DEFAULT_COMMIT_DELAY = 0;

export const allDbs = new Map();
let defaultCompression;
let lastSize, lastOffset, lastVersion;
let abortedNonChildTransactionWarn;
export function open(path, options) {
	if (!keyBytes) // TODO: Consolidate get buffer and key buffer (don't think we need both)
		allocateFixedBuffer();
	let committingWrites;
	let scheduledTransactions;
	let scheduledOperations;
	let asyncTransactionAfter = true, asyncTransactionStrictOrder;
	let transactionWarned;
	if (typeof path == 'object' && !options) {
		options = path;
		path = options.path;
	}
	if (!path) {
		if (!options)
			options = {};
		options.deleteOnClose = true;
		options.noSync = true;
		path = tmpdir() + '/' + Math.floor(Math.random() * 2821109907455).toString(36) + '.mdb'
	}
	let extension = pathModule.extname(path);
	let name = pathModule.basename(path, extension);
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
		pageSize: 4096,
		overlappingSync: (options && (options.noSync || options.readOnly)) ? false : (os != 'win32' && !isWorkerThread),
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

	if (!exists(options.noSubdir ? pathModule.dirname(path) : path))
		fs.mkdirSync(options.noSubdir ? pathModule.dirname(path) : path, { recursive: true }
		);
	function makeCompression(compressionOptions) {
		if (compressionOptions instanceof Compression)
			return compressionOptions;
		let useDefault = typeof compressionOptions != 'object';
		if (useDefault && defaultCompression)
			return defaultCompression;
		compressionOptions = Object.assign({
			threshold: 1000,
			dictionary: fs.readFileSync(new URL('./dict/dict.txt', import.meta.url.replace(/dist[\\\/]index.cjs$/, ''))),
			getValueBytes: makeReusableBuffer(0),
		}, compressionOptions);
		let compression = Object.assign(new Compression(compressionOptions), compressionOptions);
		if (useDefault)
			defaultCompression = compression;
		return compression;
	}

	if (options.compression)
		options.compression = makeCompression(options.compression);
	let flags =
		(options.overlappingSync ? 0x1000 : 0) |
		(options.noSubdir ? 0x4000 : 0) |
		(options.noSync ? 0x10000 : 0) |
		(options.readOnly ? 0x20000 : 0) |
		(options.noMetaSync ? 0x40000 : 0) |
		(options.useWritemap ? 0x80000 : 0) |
		(options.mapAsync ? 0x100000 : 0) |
		(options.noReadAhead ? 0x800000 : 0) |
		(options.noMemInit ? 0x1000000 : 0) |
		(options.usePreviousSnapshot ? 0x2000000 : 0) |
		(options.remapChunks ? 0x4000000 : 0);

	let env = new Env();
	let jsFlags = (options.separateFlushed ? 1 : 0) |
		(options.deleteOnClose ? 2 : 0)
	let rc = env.open(options, flags, jsFlags);
   if (rc)
		lmdbError(rc);
	let maxKeySize = env.getMaxKeySize();
	maxKeySize = Math.min(maxKeySize, MAX_KEY_SIZE);
	env.readerCheck(); // clear out any stale entries
	let stores = [];
	class LMDBStore extends EventEmitter {
		constructor(dbName, dbOptions) {
			super();
			if (dbName === undefined)
				throw new Error('Database name must be supplied in name property (may be null for root database)');

			if (options.compression && dbOptions.compression !== false && typeof dbOptions.compression != 'object')
				dbOptions.compression = options.compression; // use the parent compression if available
			else if (dbOptions.compression)
				dbOptions.compression = makeCompression(dbOptions.compression);

			if (dbOptions.dupSort && (dbOptions.useVersions || dbOptions.cache)) {
				throw new Error('The dupSort flag can not be combined with versions or caching');
			}
			// make sure we are using a fresh read txn, so we don't want to share with a cursor txn
			this.resetReadTxn();
			this.ensureReadTxn();
			let keyIsBuffer = dbOptions.keyIsBuffer
			if (dbOptions.keyEncoding == 'uint32') {
				dbOptions.keyIsUint32 = true;
			} else if (dbOptions.keyEncoder) {
				if (dbOptions.keyEncoder.enableNullTermination) {
					dbOptions.keyEncoder.enableNullTermination()
				} else
					keyIsBuffer = true;
			} else if (dbOptions.keyEncoding == 'binary') {
				keyIsBuffer = true;
			}
			let flags = (dbOptions.reverseKey ? 0x02 : 0) |
				(dbOptions.dupSort ? 0x04 : 0) |
				(dbOptions.dupFixed ? 0x10 : 0) |
				(dbOptions.integerDup ? 0x20 : 0) |
				(dbOptions.reverseDup ? 0x40 : 0) |
				(dbOptions.useVersions ? 0x1000 : 0);
			let keyType = (dbOptions.keyIsUint32 || dbOptions.keyEncoding == 'uint32') ? 2 : keyIsBuffer ? 3 : 0;
			if (keyType == 2)
				flags |= 0x08; // integer key
			if (!((flags & 0xff) && !dbName)) // if there are any dupsort options on the main db, skip as we have to use a write txn below
				this.db = env.openDbi(flags, dbName, keyType, dbOptions.compression);
			this._commitReadTxn(); // current read transaction becomes invalid after opening another db
			if (!this.db) {// not found
				if (dbOptions.create !== false && !options.readOnly) {
					flags |= 0x40000; // add create flag
					this.transactionSync(() => {
						this.db = env.openDbi(flags, dbName, keyType, dbOptions.compression);
					});
				} else {
					return; // return undefined to indicate it could not be found
				}
			}
			this.db.name = dbName || null;
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
			let Encoder;
			if (this.encoder && this.encoder.Encoder) {
				Encoder = this.encoder.Encoder;
				this.encoder = null; // don't copy everything from the module
			}
			if (!Encoder && !(this.encoder && this.encoder.encode) && (!this.encoding || this.encoding == 'msgpack' || this.encoding == 'cbor')) {
				Encoder = (this.encoding == 'cbor' ? require('cbor-x').Encoder : MsgpackrEncoder);
			}
			if (Encoder) {
				this.encoder = new Encoder(Object.assign(
					assignConstrainedProperties(['copyBuffers', 'getStructures', 'saveStructures', 'useFloat32', 'useRecords', 'structuredClone', 'variableMapSize', 'useTimestamp32', 'largeBigIntToFloat', 'encodeUndefinedAsNil', 'int64AsNumber', 'onInvalidDate', 'mapsAsObjects', 'useTag259ForMaps', 'pack', 'maxSharedStructures', 'shouldShareStructure'],
					this.sharedStructuresKey ? this.setupSharedStructures() : {
						copyBuffers: true, // need to copy any embedded buffers that are found since we use unsafe buffers
					}, options, dbOptions), this.encoder));
			}
			if (this.encoding == 'json') {
				this.encoder = {
					encode: JSON.stringify,
				};
			} else if (this.encoder) {
				this.decoder = this.encoder;
			}
			this.maxKeySize = maxKeySize;
			applyKeyHandling(this);
			allDbs.set(dbName ? name + '-' + dbName : name, this);
			stores.push(this);
		}
		openDB(dbName, dbOptions) {
			if (this.dupSort && this.name == null)
				throw new Error('Can not open named databases if the main database is dupSort')
			if (typeof dbName == 'object' && !dbOptions) {
				dbOptions = dbName;
				dbName = dbOptions.name;
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
		backup(path) {
			return new Promise((resolve, reject) => env.copy(path, false, (error) => {
				if (error) {
					reject(error);
				} else {
					resolve();
				}
			}));
		}
		isOperational() {
			return this.status == 'open';
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
			if (this.encoder) {
				if (this.encoder.clearSharedData)
					this.encoder.clearSharedData()
				else if (this.encoder.structures)
					this.encoder.structures = []
			}
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
				return buffer && this.decoder.decode(buffer);
			};
			return {
				saveStructures: (structures, isCompatible) => {
					return this.transactionSyncStart(() => {
						let existingStructuresBuffer = this.getBinary(this.sharedStructuresKey);
						let existingStructures = existingStructuresBuffer && this.decoder.decode(existingStructuresBuffer);
						if (typeof isCompatible == 'function' ?
								!isCompatible(existingStructures) :
								(existingStructures && existingStructures.length != isCompatible))
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
	addReadMethods(LMDBStore, { env, maxKeySize, keyBytes, keyBytesView, getLastVersion });
	if (!options.readOnly)
		addWriteMethods(LMDBStore, { env, maxKeySize, fixedBuffer: keyBytes,
			resetReadTxn: LMDBStore.prototype.resetReadTxn, ...options });
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


export function getLastEntrySize() {
	return lastSize;
}
export function getLastVersion() {
	return keyBytesView.getFloat64(16, true);
}

export function setLastVersion(version) {
	return keyBytesView.setFloat64(16, version, true);
}

const KEY_BUFFER_SIZE = 4096;
function allocateFixedBuffer() {
	keyBytes = typeof Buffer != 'undefined' ? Buffer.allocUnsafeSlow(KEY_BUFFER_SIZE) : new Uint8Array(KEY_BUFFER_SIZE);
	const keyBuffer = keyBytes.buffer;
	keyBytesView = keyBytes.dataView = new DataView(keyBytes.buffer, 0, KEY_BUFFER_SIZE); // max key size is actually 4026
	keyBytes.uint32 = new Uint32Array(keyBuffer, 0, KEY_BUFFER_SIZE >> 2);
	keyBytes.float64 = new Float64Array(keyBuffer, 0, KEY_BUFFER_SIZE >> 3);
	keyBytes.uint32.address = keyBytes.address = keyBuffer.address = getAddress(keyBytes);
}

function exists(path) {
	if (fs.existsSync)
		return fs.existsSync(path);
	try {
		return fs.statSync(path);
	} catch (error) {
//		if (error.name == 'NotFound')
			return false
//		throw error
	}
}

function assignConstrainedProperties(allowedProperties, target) {
	for (let i = 2; i < arguments.length; i++) {
		let source = arguments[i];
		for (let key in source) {
			if (allowedProperties.includes(key))
				target[key] = source[key];
		}
	}
	return target;
}