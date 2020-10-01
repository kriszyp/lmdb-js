const fs = require('fs-extra')
const { extname, basename, dirname} = require('path')
const { ArrayLikeIterable } = require('./util/ArrayLikeIterable')
const when  = require('./util/when')
const EventEmitter = require('events')
const { Packr, pack, unpack } = require('msgpackr')
Object.assign(exports, require('node-gyp-build')(__dirname))
const { Env, Cursor, Compression, getLastVersion, setLastVersion } = exports
const { CachingStore, setGetLastVersion } = require('./cache')
setGetLastVersion(getLastVersion)

const RANGE_BATCH_SIZE = 100
const DEFAULT_SYNC_BATCH_THRESHOLD = 200000000 // 200MB
const DEFAULT_IMMEDIATE_BATCH_THRESHOLD = 10000000 // 10MB
const DEFAULT_COMMIT_DELAY = 1
const READING_TNX = {
	readOnly: true
}
const SHARED_STRUCTURE_CHANGE = { name: 'SharedStructureChange' }

const allDbs = exports.allDbs = new Map()
function genericErrorHandler(err) {
	if (err) {
		console.error(err)
	}
}
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
	let readTxn, writeTxn, pendingBatch, currentCommit, runNextBatch, readTxnRenewed
	if (typeof path == 'object' && !options) {
		options = path
		path = options.path
	}
	let extension = extname(path)
	let name = basename(path, extension)
	if (!fs.existsSync(extension ? dirname(path) : path))
	    	fs.ensureDirSync(extension ? dirname(path) : path)
	options = Object.assign({
		path,
		noSubdir: Boolean(extension),
		maxDbs: 12,
	}, options)
	if (options.compression) {
		let setDefault
		if (options.compression == true) {
			if (defaultCompression)
				options.compression = defaultCompression
			else
				setDefault = true
		}
		options.compression = new Compression(Object.assign({
			threshold: 1000,
			dictionary: fs.readFileSync(require.resolve('./dict/dict.txt')),
		}), options.compression)
		if (setDefault)
			defaultCompression = options.compression
	}

	if (options && options.clearOnStart) {
		console.info('Removing', path)
		fs.removeSync(path)
		console.info('Removed', path)
	}
	env.open(options)
	readTxn = env.beginTxn(READING_TNX)
	readTxn.reset()
	function renewReadTxn() {
		readTxnRenewed = setImmediate(resetReadTxn)
		readTxn.renew()
		return readTxn
	}
	function resetReadTxn() {
		if (readTxnRenewed) {
			readTxnRenewed = null
			readTxn.reset()
		}
	}
	let stores = []
	class LMDBStore extends EventEmitter {
		constructor(dbName, dbOptions) {
			super()
			if (typeof dbName == 'object' && !dbOptions) {
				dbOptions = dbName
				dbName = options.name
			}
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
			Object.assign(this, options, dbOptions)
			if (!this.encoding || this.encoding == 'msgpack') {
				this.packr = new Packr(Object.assign(this.sharedStructuresKey ?
					this.setupSharedStructures() : {
						copyBuffers: true // need to copy any embedded buffers that are found since we use unsafe buffers
					}, options, dbOptions))
			}
			allDbs.set(dbName ? name + '-' + dbName : name, this)
			stores.push(this)
		}
		openDB(dbName, dbOptions) {
			try {
				return options.cache ?
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
				if (this.packr) {
					lastSize = result = txn.getBinaryUnsafe(this.db, id)
					return result && this.packr.unpack(this.db.unsafeBuffer, result)
				}
				if (this.encoding == 'binary')
					return txn.getBinary(this.db, id)
				result = txn.getUtf8(this.db, id)
				if (this.encoding == 'json' && result) {
					lastSize = result.length
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
		ifNoExists(key, version, callback) {
			return ifVersion(key, null, callback)
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
		getWithVersion(key) {
			return {
				value: get(key),
				version: getLastVersion(),
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
						return Promise.resolve(false)
					}
				}
				this.putSync(id, value, version)
				return Promise.resolve(true)
			}
			if (this.packr)
				value = this.packr.pack(value)
			else if (this.encoding == 'json')
				value = JSON.stringify(value)
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
				if (this.packr)
					value = this.packr.pack(value)
				else if (this.encoding == 'json')
					value = JSON.stringify(value)
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
				if (writeTxn)
					throw error // if we are in a transaction, the whole transaction probably needs to restart
				return handleError(error, this, txn, () => this.putSync(id, value, version))
			}
		}
		removeSync(id) {
			if (id.length > 511) {
				throw new Error('Key is larger than maximum key size (511)')
			}
			let txn
			try {
				txn = writeTxn || env.beginTxn()
				this.writes++
				txn.del(this.db, id)
				if (!writeTxn) {
					txn.commit()
					resetReadTxn()
				}
				return true // object found and deleted
			} catch(error) {
				if (error.message.startsWith('MDB_NOTFOUND')) {
					if (!writeTxn)
						txn.abort()
					return false // calling remove on non-existent property is fine, but we will indicate its lack of existence with the return value
				}
				if (writeTxn)
					throw error // if we are in a transaction, the whole transaction probably needs to restart
				return handleError(error, this, txn, () => this.removeSync(id))
			}
		}
		remove(id, ifVersion) {
			if (id.length > 511) {
				throw new Error('Key is larger than maximum key size (511)')
			}
			this.writes++
			if (writeTxn) {
				if (ifVersion !== undefined) {
					let previousVersion = this.get(id) ? getLastVersion() : null
					if (!matches(previousVersion, ifVersion)) {
						return Promise.resolve(false)
					}
				}
				return Promise.resolve(this.removeSync(id))
			}
			let scheduledOperations = this.getScheduledOperations()
			let index = scheduledOperations.push(typeof ifVersion == 'number' ?
				[id, undefined, undefined, ifVersion] : [id]) - 1
			scheduledOperations.bytes += (id.length || 6) + 100
			let commit = this.scheduleCommit()
			return ifVersion === undefined ? commit.unconditionalResults :
				commit.results.then((writeResults) => {
					if (writeResults[index] === 0)
						return true
					if (writeResults[index] === 3) {
						throw new Error('The key size was 0 or too large')
					}
					return false
				})
		}
		getRange(options) {
			let iterable = new ArrayLikeIterable()
			if (!options)
				options = {}
			let includeValues = options.values !== false
			let includeVersions = options.versions
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
				const goToDirection = reverse ? 'goToPrev' : 'goToNext'
				const getNextBlock = () => {
					array = []
					let cursor
					let txn
					try {
						if (writeTxn) {
							txn = writeTxn
						} else {
							txn = readTxnRenewed ? readTxn : renewReadTxn()
						}
						cursor = new Cursor(txn, db)
						if (reverse) {
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
						} else {
							// for forward retrieval, goToRange does what we want
							currentKey = cursor.goToRange(currentKey)
						}
						let i = 0
						// TODO: Make a makeCompare(endKey)
						while (!(finished = currentKey === undefined ||
								(reverse ? compareKey(currentKey, endKey) <= 0 : compareKey(currentKey, endKey) >= 0)) &&
							i++ < RANGE_BATCH_SIZE) {
							if (includeValues) {
								let value
								if (this.packr) {
									lastSize = value = cursor.getCurrentBinaryUnsafe()
									if (value)
										value = this.packr.unpack(this.db.unsafeBuffer, value)
								} else if (this.encoding == 'binary')
									value = cursor.getCurrentBinary()
								else {
									value = cursor.getCurrentUtf8()
									if (this.encoding == 'json' && value)
										value = JSON.parse(value)
								}
								if (includeVersions)
									array.push(currentKey, value, getLastVersion())
								else
									array.push(currentKey, value)
							} else if (includeVersions) {
								cursor.getCurrentBinaryUnsafe()
								array.push(currentKey, getLastVersion())
							} else
								array.push(currentKey)
							if (++count >= options.limit) {
								finished = true
								break
							}
							currentKey = cursor[goToDirection]()
						}
						cursor.close()
					} catch(error) {
						if (cursor) {
							try {
								cursor.close()
							} catch(error) { }
						}
						return handleError(error, this, txn, getNextBlock)
					}
				}
				let array
				let i = 0
				let finished
				getNextBlock()
				let store = this
				return {
					next() {
						let length = array.length
						if (i === length) {
							if (finished) {
								return { done: true }
							} else {
								getNextBlock()
								i = 0
								return this.next()
							}
						}
						if (includeValues) {
							let key = array[i++]
							let value = array[i++]
							store.bytesRead += value && value.length || 0
							if (includeVersions) {
								let version = array[i++]
								return {
									value: {
										key, value, version
									}
								}

							}
							return {
								value: {
									key, value
								}
							}
						} else {
							if (includeVersions) {
								return {
									value: {
										key: array[i++],
										version: array[i++]
									}
								}
							}
							return {
								value: array[i++]
							}
						}
					},
					return() {
						return { done: true }
					},
					throw() {
						console.log('throw called on iterator', this.ended)
						return { done: true }
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
			if (this.packr && this.packr.structures)
				this.packr.structures = []

		}
		setupSharedStructures() {
			return {
				saveStructures: (structures, previousLength) => {
					return this.transaction(() => {
						let existingStructuresBuffer = writeTxn.getBinary(this.db, this.sharedStructuresKey)
						let existingStructures = existingStructuresBuffer ? unpack(existingStructuresBuffer) : []
						if (existingStructures.length != previousLength)
							return false // it changed, we need to indicate that we couldn't update
						writeTxn.putBinary(this.db, this.sharedStructuresKey, pack(structures))
					})
				},
				getStructures: () => {
					let lastVersion // because we are doing a read here, we may need to save and restore the lastVersion from the last read
					if (this.useVersions)
						lastVersion = getLastVersion()
					let buffer = (writeTxn || (readTxnRenewed ? readTxn : renewReadTxn())).getBinary(this.db, this.sharedStructuresKey)
					if (this.useVersions)
						setLastVersion(lastVersion)
					return buffer ? unpack(buffer) : []
				},
				copyBuffers: true // need to copy any embedded buffers that are found since we use unsafe buffers
			}
		}
	}
	return options.cache ?
		new (CachingStore(LMDBStore))(options.name || null, options) :
		new LMDBStore(options.name || null, options)
	function handleError(error, store, txn, retry) {
		if (error === SHARED_STRUCTURE_CHANGE) {
			store.packr.structures = unpack(txn.getBinary(store.db, store.sharedStructuresKey))
			return retry()
		}
		try {
			if (readTxn) {
				readTxn.abort()
			}
		} catch(error) {
		//	console.warn('txn already aborted')
		}
		try {
			if (writeTxn)
				writeTxn.abort()
		} catch(error) {
		//	console.warn('txn already aborted')
		}
		try {
			if (txn && txn !== readTxn && txn !== writeTxn)
				txn.abort()
		} catch(error) {
		//	console.warn('txn already aborted')
		}

		if (writeTxn)
			writeTxn = null
		if (error.message == 'The transaction is already closed.') {
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

			console.log('Resizing database', name, 'to', newSize)
			env.resize(newSize)
			readTxnRenewed = null
			readTxn = env.beginTxn(READING_TNX)
			readTxn.reset()
			let result = retry()
			return result
		} else if (error.message.startsWith('MDB_PAGE_NOTFOUND') || error.message.startsWith('MDB_CURSOR_FULL') || error.message.startsWith('MDB_CORRUPTED') || error.message.startsWith('MDB_INVALID')) {
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
		}
		try {
			readTxnRenewed = null
			readTxn = env.beginTxn(READING_TNX)
			readTxn.reset()
		} catch(error) {
			console.error(error.toString());
		}
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
	} else if (typeof a == typeof b)
		return a < b ? -1 : a === b ? 0 : 1
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
