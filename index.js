import { extname, basename, dirname} from 'path';
import EventEmitter from 'events';
import { Env, Compression, getAddress, require, arch, fs } from './native.js';
import { CachingStore, setGetLastVersion } from './caching.js';
import { addReadMethods, makeReusableBuffer } from './read.js';
import { addWriteMethods } from './write.js';
import { applyKeyHandling } from './keys.js';
import { Encoder as MsgpackrEncoder } from 'msgpackr';
setGetLastVersion(getLastVersion);
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
		pageSize: 4096,
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
	if (options.separateFlushed === undefined)
		options.separateFlushed = options.overlappingSync;

	if (!fs.existsSync(options.noSubdir ? dirname(path) : path))
		fs.mkdirSync(options.noSubdir ? dirname(path) : path, { recursive: true });
	if (options.compression) {
		let setDefault;
		if (options.compression == true) {
			if (defaultCompression)
				options.compression = defaultCompression;
			else {
				let compressionOptions = {
					threshold: 1000,
					dictionary: fs.readFileSync(new URL('./dict/dict.txt',
						import.meta.url.replace(/dist[\\\/]index.cjs$/, ''))),
					getValueBytes: makeReusableBuffer(0),
				};
				defaultCompression = options.compression = new Compression(compressionOptions);
				Object.assign(defaultCompression, compressionOptions);
			}
		} else {
			let compressionOptions = Object.assign({
				threshold: 1000,
				dictionary: fs.readFileSync(new URL('./dict/dict.txt', import.meta.url.replace(/dist[\\\/]index.cjs$/, ''))),
				getValueBytes: makeReusableBuffer(0),
			}, options.compression);
			options.compression = new Compression(compressionOptions);
			Object.assign(options.compression, compressionOptions);
		}
	}

	if (options && options.clearOnStart) {
		console.info('Removing', path);
		fs.removeSync(path);
		console.info('Removed', path);
	}
	let maxKeySize = env.open(options);
	maxKeySize = Math.min(maxKeySize, 4026);
	env.readerCheck(); // clear out any stale entries
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
				}, dbOptions));
				this.db.name = dbName || null;
			};
			if (dbOptions.compression instanceof Compression) {
				// do nothing, already compression object
			} else if (dbOptions.compression && typeof dbOptions.compression == 'object')
				dbOptions.compression = new Compression(Object.assign({
					threshold: 1000,
					dictionary: fs.readFileSync(require.resolve('./dict/dict.txt')),
				}), dbOptions.compression);
			else if (options.compression && dbOptions.compression !== false) 
				dbOptions.compression = options.compression; // use the parent compression if available

			if (dbOptions.dupSort && (dbOptions.useVersions || dbOptions.cache)) {
				throw new Error('The dupSort flag can not be combined with versions or caching');
			}

			if (dbOptions.keyEncoding == 'uint32')
				dbOptions.keyIsUint32 = true; // for now this ensure compatibility
			else if (dbOptions.keyEncoding == 'binary')
				dbOptions.keyIsBuffer = true;
			openDB();
			this.resetReadTxn(); // a read transaction becomes invalid after opening another db
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
			if (this.encoder) {
				Encoder = this.encoder.Encoder;
			} else if (!this.encoding || this.encoding == 'msgpack' || this.encoding == 'cbor') {
				Encoder = (this.encoding == 'cbor' ? require('cbor-x').Encoder : MsgpackrEncoder);
			}
			if (Encoder) {
				this.encoder = new Encoder(Object.assign(
					this.sharedStructuresKey ? this.setupSharedStructures() : {
						copyBuffers: true, // need to copy any embedded buffers that are found since we use unsafe buffers
					}, options, dbOptions));
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
				return buffer ? this.decoder.decode(buffer) : [];
			};
			return {
				saveStructures: (structures, previousLength) => {
					return this.transactionSyncStart(() => {
						let existingStructuresBuffer = this.getBinary(this.sharedStructuresKey);
						let existingStructures = existingStructuresBuffer ? this.decoder.decode(existingStructuresBuffer) : [];
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
	addReadMethods(LMDBStore, { env, maxKeySize, keyBytes, keyBytesView, getLastVersion });
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

const KEY_BUFFER_SIZE = 4096
function allocateFixedBuffer() {
	keyBytes = Buffer.allocUnsafeSlow(KEY_BUFFER_SIZE);
	const keyBuffer = keyBytes.buffer;
	keyBytesView = keyBytes.dataView = new DataView(keyBytes.buffer, 0, KEY_BUFFER_SIZE); // max key size is actually 8122
	keyBytes.uint32 = new Uint32Array(keyBuffer, 0, KEY_BUFFER_SIZE >> 2);
	keyBytes.float64 = new Float64Array(keyBuffer, 0, KEY_BUFFER_SIZE >> 3);
	keyBytes.uint32.address = keyBytes.address = keyBuffer.address = getAddress(keyBytes);
}
