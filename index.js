const { sync: mkdirpSync } = require('mkdirp')
const fs = require('fs')
const { extname, basename, dirname} = require('path')
const { ArrayLikeIterable } = require('./util/ArrayLikeIterable')
const when  = require('./util/when')
const EventEmitter = require('events')
Object.assign(exports, require('node-gyp-build')(__dirname))
const { Env, Cursor, Compression, getLastVersion, setLastVersion } = exports
const { CachingStore, setGetLastVersion } = require('./caching')
setGetLastVersion(getLastVersion)

const DEFAULT_SYNC_BATCH_THRESHOLD = 200000000 // 200MB
const DEFAULT_IMMEDIATE_BATCH_THRESHOLD = 10000000 // 10MB
const DEFAULT_COMMIT_DELAY = 1
const READING_TNX = {
	readOnly: true
}

const allDbs = exports.allDbs = new Map()
const SYNC_PROMISE_RESULT = Promise.resolve(true)
const SYNC_PROMISE_FAIL = Promise.resolve(false)
SYNC_PROMISE_RESULT.isSync = true
SYNC_PROMISE_FAIL.isSync = true
const LAST_KEY = String.fromCharCode(0xffff)
const LAST_BUFFER_KEY = Buffer.from([255, 255, 255, 255])
const FIRST_BUFFER_KEY = Buffer.from([0])
let env
let defaultCompression
let lastSize
exports.open = open
function open(path, options) {
	let env = new Env()
	let committingWrites
	let scheduledWrites
	let scheduledOperations
	let readTxn, writeTxn, pendingBatch, currentCommit, runNextBatch, readTxnRenewed, cursorTxns = []
	if (typeof path == 'object' && !options) {
		options = path
		path = options.path
	}
	let extension = extname(path)
	let name = basename(path, extension)
	options = Object.assign({
		path,
		noSubdir: Boolean(extension),
		isRoot: true,
		maxDbs: 12,
	}, options)
	if (!fs.existsSync(options.noSubdir ? dirname(path) : path))
		mkdirpSync(options.noSubdir ? dirname(path) : path)
	if (options.compression) {
		let setDefault
		if (options.compression == true) {
			if (defaultCompression)
				options.compression = defaultCompression
			else
				defaultCompression = options.compression = new Compression({
					threshold: 1000,
					dictionary: fs.readFileSync(require.resolve('./dict/dict.txt')),
				})
		} else
			options.compression = new Compression(Object.assign({
				threshold: 1000,
				dictionary: fs.readFileSync(require.resolve('./dict/dict.txt')),
			}), options.compression)
	}

	if (options && options.clearOnStart) {
		console.info('Removing', path)
		fs.removeSync(path)
		console.info('Removed', path)
	}
	try {
		env.open(options)
	} catch(error) {
		if (error.message.startsWith('MDB_INVALID')) {
			require('./util/upgrade-lmdb').upgrade(path, options, open)
			env = new Env()
			env.open(options)
		} else
			throw error
	}
	function renewReadTxn() {
		if (readTxn)
			readTxn.renew()
		else
			readTxn = env.beginTxn(READING_TNX)
		readTxnRenewed = setImmediate(resetReadTxn)
		return readTxn
	}
	function resetReadTxn() {
		if (readTxnRenewed) {
			readTxnRenewed = null
			if (readTxn.cursorCount > 0) {
				readTxn.onlyCursor = true
				cursorTxns.push(readTxn)
				readTxn = null
			}
			else
				readTxn.reset()
		}
	}
	let stores = []
	class LMDBStore extends EventEmitter {
		constructor(dbName, dbOptions) {
			super()
			if (dbName === undefined)
				throw new Error('Database name must be supplied in name property (may be null for root database)')

			const openDB = () => {
				try {
					this.db = env.openDbi(Object.assign({
						name: dbName,
						create: true,
						txn: writeTxn,
					}, dbOptions))
					this.db.name = dbName || null
				} catch(error) {
					handleError(error, null, null, openDB)
				}
			}
			if (dbOptions.compression && !(dbOptions.compression instanceof Compression)) {
				if (dbOptions.compression == true && options.compression)
					dbOptions.compression = options.compression // use the parent compression if available
				else
					dbOptions.compression = new Compression(Object.assign({
						threshold: 1000,
						dictionary: fs.readFileSync(require.resolve('./dict/dict.txt')),
					}), dbOptions.compression)
			}

			if (dbOptions.dupSort && (dbOptions.useVersions || dbOptions.cache)) {
				throw new Error('The dupSort flag can not be combined with versions or caching')
			}
			openDB()
			resetReadTxn() // a read transaction becomes invalid after opening another db
			this.name = dbName
			this.env = env
			this.reads = 0
			this.writes = 0
			this.transactions = 0
			this.averageTransactionTime = 5
			this.syncBatchThreshold = DEFAULT_SYNC_BATCH_THRESHOLD
			this.immediateBatchThreshold = DEFAULT_IMMEDIATE_BATCH_THRESHOLD
			this.commitDelay = DEFAULT_COMMIT_DELAY
			Object.assign(this, { // these are the options that are inherited
				path: options.path,
				encoding: options.encoding,
			}, dbOptions)
			if (!this.encoding || this.encoding == 'msgpack' || this.encoding == 'cbor') {
				this.encoder = this.decoder = new (this.encoding == 'cbor' ? require('cbor-x').Encoder : require('msgpackr').Encoder)
					(Object.assign(this.sharedStructuresKey ?
					this.setupSharedStructures() : {
						copyBuffers: true // need to copy any embedded buffers that are found since we use unsafe buffers
					}, options, dbOptions))
			} else if (this.encoding == 'json') {
				this.encoder = {
					encode: JSON.stringify,
				}
			}
			allDbs.set(dbName ? name + '-' + dbName : name, this)
			stores.push(this)
		}
		openDB(dbName, dbOptions) {
			if (typeof dbName == 'object' && !dbOptions) {
				dbOptions = dbName
				dbName = options.name
			} else
				dbOptions = dbOptions || {}
			try {
				return dbOptions.cache ?
					new (CachingStore(LMDBStore))(dbName, dbOptions) :
					new LMDBStore(dbName, dbOptions)
			} catch(error) {
				if (error.message.indexOf('MDB_DBS_FULL') > -1) {
					error.message += ' (increase your maxDbs option)'
				}
				throw error
			}
		}
		transaction(execute, abort) {
			let result
			if (writeTxn) {
				// already nested in a transaction, just execute and return
				result = execute()
				return result
			}
			let txn
			try {
				this.transactions++
				txn = writeTxn = env.beginTxn()
				/*if (scheduledOperations && runNextBatch) {
					runNextBatch((operations, callback) => {
						try {
							callback(null, this.commitBatchNow(operations))
						} catch (error) {
							callback(error)
						}
					})
				}
				TODO: To reenable forced sequential writes, we need to re-execute the operations if we get an env resize
				*/
				return when(execute(), (result) => {
					try {
						if (abort) {
							txn.abort()
						} else {
							txn.commit()
							resetReadTxn()
						}
						writeTxn = null
						return result
					} catch(error) {
						if (error.message == 'The transaction is already closed.') {
							return result
						}
						return handleError(error, this, txn, () => this.transaction(execute))
					}
				}, (error) => {
					return handleError(error, this, txn, () => this.transaction(execute))
				})
			} catch(error) {
				return handleError(error, this, txn, () => this.transaction(execute))
			}
		}
		get(id) {
			let txn
			try {
				if (writeTxn) {
					txn = writeTxn
				} else {
					txn = readTxnRenewed ? readTxn : renewReadTxn()
				}
				let result
				if (this.decoder) {
					this.lastSize = result = txn.getBinaryUnsafe(this.db, id)
					return result && this.decoder.decode(this.db.unsafeBuffer, result)
				}
				if (this.encoding == 'binary') {
					result = txn.getBinary(this.db, id)
					this.lastSize = result
					return result
				}
				result = txn.getUtf8(this.db, id)
				if (result) {
					this.lastSize = result.length
					if (this.encoding == 'json')
						return JSON.parse(result)
				}
				return result
			} catch(error) {
				return handleError(error, this, txn, () => this.get(id))
			}
		}
		getEntry(id) {
			let value = this.get(id)
			if (value !== undefined) {
				if (this.useVersions)
					return {
						value,
						version: getLastVersion(),
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
			resetReadTxn()
		}
		ifNoExists(key, callback) {
			return this.ifVersion(key, null, callback)
		}
		ifVersion(key, version, callback) {
			if (typeof version != 'number') {
				if (version == null) {
					if (version === null)
						version = -4.2434325325532E-199 // NO_EXIST_VERSION
					else {// if undefined, just do callback without any condition being added
						callback()
						// TODO: if we are inside another ifVersion, use that promise, or use ANY_VERSION
						return pendingBatch ? pendingBatch.unconditionalResults : Promise.resolve(true) // be consistent in returning a promise, indicate success
					}
				} else {
					throw new Error('Version must be a number or null')
				}
			}
			let scheduledOperations = this.getScheduledOperations()
			let index = scheduledOperations.push([key, version]) - 1
			try {
				callback()
				let commit = this.scheduleCommit()
				return commit.results.then((writeResults) => {
					if (writeResults[index] === 0)
						return true
					if (writeResults[index] === 3) {
						throw new Error('The key size was 0 or too large')
					}
					return false
				})
			} finally {
				scheduledOperations.push(false) // reset condition
			}
		}
		getScheduledOperations() {
			if (!scheduledOperations) {
				scheduledOperations = []
				scheduledOperations.bytes = 0
			}
			if (scheduledOperations.store != this) {
				// issue action to switch dbs
				scheduledOperations.store = this
				scheduledOperations.push(this.db)
			}
			return scheduledOperations
		}
		put(id, value, version, ifVersion) {
			if (id.length > 511) {
				throw new Error('Key is larger than maximum key size (511)')
			}
			this.writes++
			if (writeTxn) {
				if (ifVersion !== undefined) {
					this.get(id)
					let previousVersion = this.get(id) ? getLastVersion() : null
					if (!matches(previousVersion, ifVersion)) {
						return SYNC_PROMISE_FAIL
					}
				}
				this.putSync(id, value, version)
				return SYNC_PROMISE_RESULT
			}
			if (this.encoder)
				value = this.encoder.encode(value)
			else if (typeof value != 'string' && !(value && value.readUInt16BE))
				throw new Error('Invalid value to put in database ' + value + ' (' + (typeof value) +'), consider using encoder')
			let operations = this.getScheduledOperations()
			let index = operations.push(ifVersion == null ? version == null ? [id, value] : [id, value, version] : [id, value, version, ifVersion]) - 1
			// track the size of the scheduled operations (and include the approx size of the array structure too)
			operations.bytes += (id.length || 6) + (value && value.length || 0) + 100
			let commit = this.scheduleCommit()
			return ifVersion === undefined ? commit.unconditionalResults : // TODO: Technically you can get a bad key if an array is passed in there is no ifVersion and still fail
				commit.results.then((writeResults) => {
					if (writeResults[index] === 0)
						return true
					if (writeResults[index] === 3) {
						throw new Error('The key size was 0 or too large')
					}
					return false
				})
		}
		putSync(id, value, version) {
			if (id.length > 511) {
				throw new Error('Key is larger than maximum key size (511)')
			}
			let localTxn
			try {
				this.writes++
				if (!writeTxn)
					localTxn = writeTxn = env.beginTxn()
				if (this.encoder)
					value = this.encoder.encode(value)
				if (typeof value == 'string') {
					writeTxn.putUtf8(this.db, id, value, version)
				} else {
					if (!(value && value.readUInt16BE)) {
						throw new Error('Invalid value type ' + typeof value + ' used ' + value)
					}
					writeTxn.putBinary(this.db, id, value, version)
				}
				if (localTxn) {
					writeTxn = null
					localTxn.commit()
					resetReadTxn()
				}
			} catch(error) {
				if (!localTxn)
					throw error // if we are in a transaction, the whole transaction probably needs to restart
				return handleError(error, this, localTxn, () => this.putSync(id, value, version))
			}
		}
		removeSync(id, ifVersionOrValue) {
			if (id.length > 511) {
				throw new Error('Key is larger than maximum key size (511)')
			}
			let localTxn
			try {
				if (!writeTxn)
					localTxn = writeTxn = env.beginTxn()
				let deleteValue
				if (ifVersionOrValue !== undefined) {
					if (this.useVersions) {
						let previousVersion = this.get(id) ? getLastVersion() : null
						if (!matches(previousVersion, ifVersionOrValue))
							return false
					} else if (this.encoder)
						deleteValue = this.encoder.encode(ifVersionOrValue)
				}
				this.writes++
				let result
				if (deleteValue)
					result = writeTxn.del(this.db, id, deleteValue)
				else
					result = writeTxn.del(this.db, id)
				if (localTxn) {
					writeTxn = null
					localTxn.commit()
					resetReadTxn()
				}
				return result // object found and deleted
			} catch(error) {
				if (!localTxn)
					throw error // if we are in a transaction, the whole transaction probably needs to restart
				return handleError(error, this, localTxn, () => this.removeSync(id))
			}
		}
		remove(id, ifVersionOrValue) {
			if (id.length > 511) {
				throw new Error('Key is larger than maximum key size (511)')
			}
			this.writes++
			if (writeTxn) {
				if (this.removeSync(id, ifVersionOrValue) === false)
					return SYNC_PROMISE_FAIL
				return SYNC_PROMISE_RESULT
			}
			let scheduledOperations = this.getScheduledOperations()
			let operation
			if (ifVersionOrValue === undefined)
				operation = [id]
			else if (this.useVersions)
				operation = [id, undefined, undefined, ifVersionOrValue] // version condition
			else {
				if (this.encoder)
					operation = [id, this.encoder.encode(ifVersionOrValue), true]
				else
					operation = [id, ifVersionOrValue, true]
			}
			let index = scheduledOperations.push(operation) - 1 // remove specific values
			scheduledOperations.bytes += (id.length || 6) + 100
			let commit = this.scheduleCommit()
			return ifVersionOrValue === undefined ? commit.unconditionalResults :
				commit.results.then((writeResults) => {
					if (writeResults[index] === 0)
						return true
					if (writeResults[index] === 3) {
						throw new Error('The key size was 0 or too large')
					}
					return false
				})
		}
		getValues(key, options) {
			let defaultOptions = {
				start: key,
				valuesForKey: true
			}
			return this.getRange(options ? Object.assign(defaultOptions, options) : defaultOptions)
		}
		getKeys(options) {
			if (!options)
				options = {}
			options.values = false
			return this.getRange(options)
		}
		getRange(options) {
			let iterable = new ArrayLikeIterable()
			if (!options)
				options = {}
			let includeValues = options.values !== false
			let includeVersions = options.versions
			let valuesForKey = options.valuesForKey
			let db = this.db
			iterable[Symbol.iterator] = () => {
				let currentKey = options.start !== undefined ? options.start :
					(options.reverse ? this.keyIsUint32 ? 0xffffffff : this.keyIsBuffer ? LAST_BUFFER_KEY : LAST_KEY :
						this.keyIsUint32 ? 0 : this.keyIsBuffer ? FIRST_BUFFER_KEY : false)
				let endKey = options.end !== undefined ? options.end :
					(options.reverse ? this.keyIsUint32 ? 0 : this.keyIsBuffer ? FIRST_BUFFER_KEY : false :
						this.keyIsUint32 ? 0xffffffff : this.keyIsBuffer ? LAST_BUFFER_KEY : LAST_KEY)
				const reverse = options.reverse
				let count = 0
				let cursor
				let txn
				function resetCursor() {
					try {
						txn = writeTxn || (readTxnRenewed ? readTxn : renewReadTxn())
						cursor = new Cursor(txn, db)
						txn.cursorCount = (txn.cursorCount || 0) + 1
						if (reverse) {
							if (valuesForKey) {
								// position at key
								currentKey = cursor.goToKey(currentKey)
								// now move to next key and then previous entry to get to last value
								if (currentKey) {
									cursor.goToNextNoDup()
									cursor.goToPrev()
								}
							} else {
								// for reverse retrieval, goToRange is backwards because it positions at the key equal or *greater than* the provided key
								let nextKey = cursor.goToRange(currentKey)
								if (nextKey) {
									if (compareKey(nextKey, currentKey)) {
										// goToRange positioned us at a key after the provided key, so we need to go the previous key to be less than the provided key
										currentKey = cursor.goToPrev()
									} else
										currentKey = nextKey // they match, we are good, and currentKey is already correct
								} else {
									// likewise, we have been position beyond the end of the index, need to go to last
									currentKey = cursor.goToLast()
								}
							}
						} else {
							// for forward retrieval, goToRange does what we want
							currentKey = valuesForKey ? cursor.goToKey(currentKey) : cursor.goToRange(currentKey)
						}
						// TODO: Make a makeCompare(endKey)
					} catch(error) {
						if (cursor) {
							try {
								cursor.close()
							} catch(error) { }
						}
						return handleError(error, this, txn, () => iterable[Symbol.iterator]())
					}
				}
				resetCursor()
				let store = this
				function finishCursor() {
					cursor.close()
					if (--txn.cursorCount <= 0 && txn.onlyCursor) {
						let index = cursorTxns.indexOf(txn)
						if (index > -1)
							cursorTxns.splice(index, 1)
						txn.abort() // this is no longer main read txn, abort it now that we are done
					}
					return { done: true }
				}
				return {
					next() {
						if (txn.isAborted)
							resetCursor()
						if (count > 0)
							currentKey = reverse ?
								valuesForKey ? cursor.goToPrevDup() :
									includeValues ? cursor.goToPrev() : cursor.goToPrevNoDup() :
								valuesForKey ? cursor.goToNextDup() :
									includeValues ? cursor.goToNext() : cursor.goToNextNoDup()
						if (currentKey === undefined ||
								(reverse ? compareKey(currentKey, endKey) <= 0 : compareKey(currentKey, endKey) >= 0) ||
								(count++ >= options.limit)) {
							return finishCursor()
						}
						if (includeValues) {
							let value
							if (store.decoder) {
								lastSize = value = cursor.getCurrentBinaryUnsafe()
								if (value)
									value = store.decoder.decode(store.db.unsafeBuffer, value)
							} else if (store.encoding == 'binary')
								value = cursor.getCurrentBinary()
							else {
								value = cursor.getCurrentUtf8()
								if (store.encoding == 'json' && value)
									value = JSON.parse(value)
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
							cursor.getCurrentBinaryUnsafe()
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
						return finishCursor()
					},
					throw() {
						return finishCursor()
					}
				}
			}
			return iterable
		}
		scheduleCommit() {
			if (!pendingBatch) {
				// pendingBatch promise represents the completion of the transaction
				let whenCommitted = new Promise((resolve, reject) => {
					runNextBatch = (sync) => {
						if (!whenCommitted)
							return
						runNextBatch = null
						if (pendingBatch) {
							for (const store of stores) {
								store.emit('beforecommit', { scheduledOperations })
							}
						}
						clearTimeout(timeout)
						currentCommit = whenCommitted
						whenCommitted = null
						pendingBatch = null
						if (scheduledOperations) {
							// operations to perform, collect them as an array and start doing them
							let operations = scheduledOperations
							scheduledOperations = null
							const writeBatch = () => {
								let start = Date.now()
								let results = Buffer.alloc(operations.length)
								let callback = (error) => {
									let duration = Date.now() - start
									this.averageTransactionTime = (this.averageTransactionTime * 3 + duration) / 4
									//console.log('did batch', (duration) + 'ms', name, operations.length/*map(o => o[1].toString('binary')).join(',')*/)
									resetReadTxn()
									if (error) {
										try {
											// see if we can recover from recoverable error (like full map with a resize)
											handleError(error, this, null, writeBatch)
										} catch(error) {
											currentCommit = null
											for (const store of stores) {
												store.emit('aftercommit', { operations })
											}
											reject(error)
										}
									} else {
										currentCommit = null
										for (const store of stores) {
											store.emit('aftercommit', { operations, results })
										}
										resolve(results)
									}
								}
								try {
									if (sync === true) {
										env.batchWrite(operations, results)
										callback()
									} else
										env.batchWrite(operations, results, callback)
								} catch (error) {
									callback(error)
								}
							}
							try {
								writeBatch()
							} catch(error) {
								reject(error)
							}
						} else {
							resolve([])
						}
					}
					let timeout = setTimeout(() => {
						when(currentCommit, () => whenCommitted && runNextBatch())
					}, this.commitDelay)
				})
				pendingBatch = {
					results: whenCommitted,
					unconditionalResults: whenCommitted.then(() => true) // for returning from non-conditional operations
				}
			}
			if (scheduledOperations && scheduledOperations.bytes >= this.immediateBatchThreshold && runNextBatch) {
				if (scheduledOperations && scheduledOperations.bytes >= this.syncBatchThreshold) {
					// past a certain threshold, run it immediately and synchronously
					let batch = pendingBatch
					console.warn('Performing synchronous commit because over ' + this.syncBatchThreshold + ' bytes were included in one transaction, should run transactions over separate event turns to avoid this or increase syncBatchThreshold')
					runNextBatch(true)
					return batch
				} else if (!runNextBatch.immediate) {
					let thisNextBatch = runNextBatch
					runNextBatch.immediate = setTimeout(() => when(currentCommit, () => thisNextBatch()), 0)
				}
			}
			return pendingBatch
		}

		batch(operations) {
			/*if (writeTxn) {
				this.commitBatchNow(operations.map(operation => [this.db, operation.key, operation.value]))
				return Promise.resolve(true)
			}*/
			let scheduledOperations = this.getScheduledOperations()
			for (let operation of operations) {
				let value = operation.value
				scheduledOperations.push([operation.key, value])
				scheduledOperations.bytes += operation.key.length + (value && value.length || 0) + 200
			}
			return this.scheduleCommit().unconditionalResults
		}
		backup(path, compact) {
			return new Promise((resolve, reject) => env.copy(path, compact, (error) => {
				if (error) {
					reject(error)
				} else {
					resolve()
				}
			}))
		}
		close() {
			this.db.close()
			if (this.isRoot)
				env.close()
		}
		getStats() {
			try {
				let stats = this.db.stat(readTxnRenewed ? readTxn : renewReadTxn())
				return stats
			}
			catch(error) {
				return handleError(error, this, readTxn, () => this.getStats())
			}
		}
		sync(callback) {
			return env.sync(callback || function(error) {
				if (error) {
					console.error(error)
				}
			})
		}
		deleteDB() {
			//console.log('clearing db', name)
			try {
				this.db.drop({
					justFreePages: false,
					txn: writeTxn,
				})
			} catch(error) {
				handleError(error, this, null, () => this.clear())
			}
		}
		clear() {
			//console.log('clearing db', name)
			try {
				this.db.drop({
					justFreePages: true,
					txn: writeTxn,
				})
			} catch(error) {
				handleError(error, this, null, () => this.clear())
			}
			if (this.encoder && this.encoder.structures)
				this.encoder.structures = []

		}
		setupSharedStructures() {
			return {
				saveStructures: (structures, previousLength) => {
					return this.transaction(() => {
						let existingStructuresBuffer = writeTxn.getBinary(this.db, this.sharedStructuresKey)
						let existingStructures = existingStructuresBuffer ? this.encoder.decode(existingStructuresBuffer) : []
						if (existingStructures.length != previousLength)
							return false // it changed, we need to indicate that we couldn't update
						writeTxn.putBinary(this.db, this.sharedStructuresKey, this.encoder.encode(structures))
					})
				},
				getStructures: () => {
					let lastVersion // because we are doing a read here, we may need to save and restore the lastVersion from the last read
					if (this.useVersions)
						lastVersion = getLastVersion()
					let buffer = (writeTxn || (readTxnRenewed ? readTxn : renewReadTxn())).getBinary(this.db, this.sharedStructuresKey)
					if (this.useVersions)
						setLastVersion(lastVersion)
					return buffer ? this.encoder.decode(buffer) : []
				},
				copyBuffers: true // need to copy any embedded buffers that are found since we use unsafe buffers
			}
		}
	}
	return options.cache ?
		new (CachingStore(LMDBStore))(options.name || null, options) :
		new LMDBStore(options.name || null, options)
	function handleError(error, store, txn, retry) {
		try {
			if (writeTxn)
				writeTxn.abort()
		} catch(error) {}

		if (writeTxn)
			writeTxn = null
		if (error.message == 'The transaction is already closed.') {
			try {
				if (readTxn)
					readTxn.abort()
			} catch(error) {}
			try {
				readTxn = env.beginTxn(READING_TNX)
			} catch(error) {
				return handleError(error, store, null, retry)
			}
			return retry()
		}
		if (error.message.startsWith('MDB_MAP_FULL') || error.message.startsWith('MDB_MAP_RESIZED')) {
			const oldSize = env.info().mapSize
			const newSize = Math.floor(((1.06 + 3000 / Math.sqrt(oldSize)) * oldSize) / 0x200000) * 0x200000 // increase size, more rapidly at first, and round to nearest 2 MB
			for (const store of stores) {
				store.emit('remap')
			}
			resetReadTxn() // separate out cursor-based read txns
			try {
				if (readTxn)
					readTxn.abort()
			} catch(error) {}
			readTxnRenewed = null
			readTxn = null
			env.resize(newSize)
			let result = retry()
			return result
		}/* else if (error.message.startsWith('MDB_PAGE_NOTFOUND') || error.message.startsWith('MDB_CURSOR_FULL') || error.message.startsWith('MDB_CORRUPTED') || error.message.startsWith('MDB_INVALID')) {
			// the noSync setting means that we can have partial corruption and we need to be able to recover
			for (const store of stores) {
				store.emit('remap')
			}
			try {
				env.close()
			} catch (error) {}
			console.warn('Corrupted database,', path, 'attempting to delete the store file and restart', error)
			fs.removeSync(path + '.mdb')
			env = new Env()
			env.open(options)
			openDB()
			return retry()
		}*/
		error.message = 'In database ' + name + ': ' + error.message
		throw error
	}
}

function matches(previousVersion, ifVersion){
	let matches
	if (previousVersion) {
		if (ifVersion) {
			matches = previousVersion == ifVersion
		} else {
			matches = false
		}
	} else {
		matches = !ifVersion
	}
	return matches
}

function compareKey(a, b) {
	// compare with type consistency that matches ordered-binary
	if (typeof a == 'object') {
		if (!a) {
			return b == null ? 0 : -1
		}
		if (a.compare) {
			if (b == null) {
				return 1
			} else if (b.compare) {
				return a.compare(b)
			} else {
				return -1
			}
		}
		let arrayComparison
		if (b instanceof Array) {
			let i = 0
			while((arrayComparison = compareKey(a[i], b[i])) == 0 && i <= a.length)  {
				i++
			}
			return arrayComparison
		}
		arrayComparison = compareKey(a[0], b)
		if (arrayComparison == 0 && a.length > 1)
			return 1
		return arrayComparison
	} else if (typeof a == typeof b) {
		if (typeof a === 'symbol') {
			a = Symbol.keyFor(a)
			b = Symbol.keyFor(b)
		}
		return a < b ? -1 : a === b ? 0 : 1
	}
	else if (typeof b == 'object') {
		if (b instanceof Array)
			return -compareKey(b, a)
		return 1
	} else {
		return typeOrder[typeof a] < typeOrder[typeof b] ? -1 : 1
	}
}
class Entry {
	constructor(value, version, db) {
		this.value = value
		this.version = version
		this.db = db
	}
	ifSamePut() {

	}
	ifSameRemove() {

	}
}
exports.compareKey = compareKey
const typeOrder = {
	symbol: 0,
	undefined: 1,
	boolean: 2,
	number: 3,
	string: 4
}
exports.getLastEntrySize = function() {
	return lastSize
}
