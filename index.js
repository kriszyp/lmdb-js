const fs = require('fs-extra')
const pathModule = require('path')
const { Env, openDbi, Cursor } = require('node-lmdb')
const { ArrayLikeIterable } = require('./util/ArrayLikeIterable')
//import { Database } from './Database'
const when  = require('./util/when')
const EventEmitter = require('events')

const RANGE_BATCH_SIZE = 100
const DEFAULT_SYNC_BATCH_THRESHOLD = 20000000
const DEFAULT_COMMIT_DELAY = 20
const AS_BINARY = {
	keyIsBuffer: true
}
const AS_STRING = {
	asBuffer: false
}
const READING_TNX = {
	readOnly: true
}
const allDbs = exports.allDbs = new Map()
function genericErrorHandler(err) {
	if (err) {
		console.error(err)
	}
}
let env
exports.open = open
function open(path, options) {
	let env = new Env()
	let committingWrites
	let scheduledWrites
	let scheduledOperations
	let readTxn, writeTxn
	let extension = pathModule.extname(path)
	let name = pathModule.basename(path, extension)
	if (!fs.existsSync(pathModule.dirname(path)))
    	fs.ensureDirSync(pathModule.dirname(path))
	options = Object.assign({
		path,
		noSubdir: Boolean(extension),
		//useWritemap: true, // this provides better performance
	}, options)

	if (options && options.clearOnStart) {
		console.info('Removing', path)
		fs.removeSync(path)
		console.info('Removed', path)
	}
	env.open(options)
	readTxn = env.beginTxn(READING_TNX)
	readTxn.reset()
	let stores = []
	class LMDBStore extends EventEmitter {
		constructor(dbName) {
			super()
			const openDB = () => {
				try {
					this.db = env.openDbi({
						name: dbName || 'data',
						create: true,
						keyIsBuffer: true,
					})
				} catch(error) {
					handleError(error, null, null, openDB)
				}
			}
			openDB()
			this.dbName = dbName
			this.env = env
			this.reads = 0
			this.writes = 0
			this.transactions = 0
			this.averageTransactionTime = 5
			this.syncBatchThreshold = DEFAULT_SYNC_BATCH_THRESHOLD
			this.commitDelay = DEFAULT_COMMIT_DELAY
			Object.assign(this, options)
			allDbs.set(dbName ? name + '-' + dbName : name, this)
			stores.push(this)
		}
		openDB(dbName) {
			return new LMDBStore(dbName)
		}
		transaction(execute, noSync, abort) {
			let result
			if (writeTxn) {
				// already nested in a transaction, just execute and return
				result = execute()
				if (noSync)
					return result
				else
					return this.onDemandSync
			}
			let txn
			let committed
			try {
				this.transactions++
				txn = writeTxn = env.beginTxn()
			    let startCpu = process.cpuUsage()
				let start = Date.now()
				result = execute()
				//console.log('after execute', Date.now() - start, process.cpuUsage(startCpu))
				if (abort) {
					txn.abort()
				} else {
					txn.commit()
				}
				//console.log('after commit', Date.now() - start, process.cpuUsage(startCpu))
				committed = true
				if (noSync)
					return result
				else
					return this.onDemandSync
			} catch(error) {
				return handleError(error, this, txn, () => this.transaction(execute))
			} finally {
				if (!committed) {
					try {
						txn.abort()
					} catch(error) {}
				}
				writeTxn = null
			}
		}
		get(id, copy) {
			let txn
			try {
				if (writeTxn) {
					txn = writeTxn
				} else {
					txn = readTxn
					txn.renew()
				}
				let result = copy ? txn.getBinaryUnsafe(this.db, id) : txn.getBinary(this.db, id)
				if (result === null) // missing entry, really should be undefined
					result = undefined
				try {
					if (copy)
						result = copy(result)
				} finally {
					if (!writeTxn) {
						txn.reset()
					}
				}
				this.reads++
				return result
			} catch(error) {
				return handleError(error, this, txn, () => this.get(id, copy))
			}
		}
		put(id, value, ifValue) {
			if (id.length > 511) {
				throw new Error('Key is larger than maximum key size (511)')
			}
			if (!scheduledOperations) {
				scheduledOperations = []
				scheduledOperations.bytes = 0
			}
			let index = scheduledOperations.push([this.db, id, value, ifValue]) - 1
			// track the size of the scheduled operations (and include the approx size of the array structure too)
			scheduledOperations.bytes += id.length + (value && value.length || 0) + (ifValue && ifValue.length || 0) + 200
			let commit = this.scheduleCommit()
			return ifValue === undefined ? commit.unconditionalResults :
				commit.results.then((writeResults) => writeResults[index] === 0)
		}
		putSync(id, value) {
			if (id.length > 511) {
				throw new Error('Key is larger than maximum key size (511)')
			}
			let txn
			try {
				if (typeof value !== 'object') {
					throw new Error('putting string value')
					value = Buffer.from(value)
				}
				this.writes++
			    let startCpu = process.cpuUsage()
				let start = Date.now()

				txn = writeTxn || env.beginTxn()
				txn.putBinary(this.db, id, value)
				/*if (Date.now() - start > 20)
					console.log('after put', Date.now() - start, process.cpuUsage(startCpu))*/
				if (!writeTxn) {
					txn.commit()
					//console.log('after commit', Date.now() - start, process.cpuUsage(startCpu))
				}
			} catch(error) {
				if (writeTxn)
					throw error // if we are in a transaction, the whole transaction probably needs to restart
				return handleError(error, this, txn, () => this.putSync(id, value))
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
		remove(id, ifValue) {
			if (id.length > 511) {
				throw new Error('Key is larger than maximum key size (511)')
			}
			if (!scheduledOperations) {
				scheduledOperations = []
				scheduledOperations.bytes = 0
			}
			let index = scheduledOperations.push([this.db, id, undefined, ifValue]) - 1
			scheduledOperations.bytes += id.length + (ifValue && ifValue.length || 0) + 200
			let commit = this.scheduleCommit()
			return ifValue === undefined ? commit.unconditionalResults :
				commit.results.then((writeResults) => writeResults[index] === 0)
		}
		iterable(options) {
			console.warn('iterable is deprecated')
			return this.getRange(options)
		}
		getRange(options) {
			let iterable = new ArrayLikeIterable()
			iterable[Symbol.iterator] = () => {
				let currentKey = options.start || (options.reverse ? Buffer.from([255, 255]) : Buffer.from([0]))
				let endKey = options.end || (options.reverse ? Buffer.from([0]) : Buffer.from([255, 255]))
				const reverse = options.reverse
				let count = 0
				const goToDirection = reverse ? 'goToPrev' : 'goToNext'
				const getNextBlock = () => {
					array = []
					let cursor
					try {
						readTxn.renew()
						cursor = new Cursor(readTxn, this.db)
						if (reverse) {
							// for reverse retrieval, goToRange is backwards because it positions at the key equal or *greater than* the provided key
							let nextKey = cursor.goToRange(currentKey)
							if (nextKey) {
								if (!nextKey.equals(currentKey)) {
									// goToRange positioned us at a key after the provided key, so we need to go the previous key to be less than the provided key
									currentKey = cursor.goToPrev()
								} // else they match, we are good, and currentKey is already correct
							} else {
								// likewise, we have been position beyond the end of the index, need to go to last
								currentKey = cursor.goToLast()
							}
						} else {
							// for forward retrieval, goToRange does what we want
							currentKey = cursor.goToRange(currentKey)
						}
						let i = 0
						while (!(finished = currentKey === null ||
								(reverse ? currentKey.compare(endKey) <= 0 : currentKey.compare(endKey) >= 0)) &&
							i++ < RANGE_BATCH_SIZE) {
							try {
								array.push(currentKey, options.values === false ? null : cursor.getCurrentBinary())
							} catch(error) {
								console.log('error uncompressing value for key', currentKey)
							}
							if (count++ >= options.limit) {
								finished = true
								break
							}
							currentKey = cursor[goToDirection]()
						}
						cursor.close()
						readTxn.reset()
					} catch(error) {
						if (cursor) {
							try {
								cursor.close()
							} catch(error) { }
						}
						return handleError(error, this, readTxn, getNextBlock)
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
						let key = array[i++]
						let value = array[i++]
						store.bytesRead += value && value.length || 0
						return {
							value: {
								key, value
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
			if (!this.pendingBatch) {
				// pendingBatch promise represents the completion of the transaction
				let whenCommitted = new Promise((resolve, reject) => {
					when(this.currentCommit, () => {
						let timeout = setTimeout(this.runNextBatch = (batchWriter) => {
							this.runNextBatch = null
							for (const store of stores) {
								store.emit('beforecommit', { scheduledOperations })
							}
							clearTimeout(timeout)
							this.currentCommit = whenCommitted
							this.pendingBatch = null
							this.pendingSync = null
							if (scheduledOperations) {
								// operations to perform, collect them as an array and start doing them
								let operations = scheduledOperations
								scheduledOperations = null
								const writeBatch = () => {
									let start = Date.now()
									let callback = (error, results) => {
										let duration = Date.now() - start
										this.averageTransactionTime = (this.averageTransactionTime * 3 + duration) / 4
										//console.log('did batch', (duration) + 'ms', name, operations.length/*map(o => o[1].toString('binary')).join(',')*/)
										if (error) {
											try {
												// see if we can recover from recoverable error (like full map with a resize)
												handleError(error, this, null, writeBatch)
											} catch(error) {
												this.currentCommit = null
												reject(error)
											}
										} else {
											this.currentCommit = null
											resolve(results)
										}
									}
									if (typeof batchWriter === 'function')
										batchWriter(operations, callback)
									else
										env.batchWrite(operations, callback)
								}
								writeBatch()
							} else if (error) {
								reject(error)
							} else {
								resolve(results && results.length ? results : [])
							}
						}, this.commitDelay)
					})
				})
				this.pendingBatch = {
					results: whenCommitted,
					unconditionalResults: whenCommitted.then(() => true) // for returning from non-conditional operations
				}
			}
			if (scheduledOperations && scheduledOperations.bytes >= this.syncBatchThreshold && this.runNextBatch) {
				// past a certain threshold, run it immediately and synchronously
				let batch = this.pendingBatch
				this.runNextBatch((operations, callback) => {
					try {
						callback(null, this.commitBatchNow(operations))
					} catch (error) {
						callback(error)
					}
				})
				return batch
			}
			return this.pendingBatch
		}
		commitBatchNow(operations) {
			let value
			let results = new Array(operations.length)
			this.transaction(() => {
				for (let i = 0, l = operations.length; i < l; i++) {
					let [db, id, value, ifValue] = operations[i]
					if (ifValue !== undefined) {
						value = this.get(id)
						let matches
						if (value) {
							if (ifValue) {
								matches = value.length >= ifValue.length && value.slice(0, ifValue.length).equals(ifValue)
							} else {
								matches = false
							}
						} else {
							matches = !ifValue
						}
						if (!matches) {
							results[i] = 1
							continue
						}
					}
					if (value === undefined) {
						results[i] = this.removeSync(id) ? 0 : 2
					} else {
						this.putSync(id, value)
						results[i] = 0
					}
				}
			})
			return results
		}
		batch(operations) {
			this.writes += operations.length
			if (!scheduledOperations) {
				scheduledOperations = []
				scheduledOperations.bytes = 0
			}
			for (let operation of operations) {
				if (typeof operation.key != 'object')
					throw new Error('non-buffer key')
				let value = operation.value
				scheduledOperations.push([this.db, operation.key, value])
				scheduledOperations.bytes += operation.key.length + (value && value.length || 0) + 200
			}
			return this.scheduleCommit().unconditionalResults
		}
		close() {
			this.db.close()
			env.close()
		}
		sync(callback) {
			return env.sync(callback || function(error) {
				if (error) {
					console.error(error)
				}
			})
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
		}
		testResize() {
			handleError(new Error('MDB_MAP_FULL'), this, null, () => {
				console.log('done resizing')
			})
		}
	}
	return new LMDBStore()
	function handleError(error, store, txn, retry) {
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
			const newSize = Math.ceil(env.info().mapSize * 1.3 / 0x200000 + 1) * 0x200000
			for (const store of stores) {
				store.emit('remap')
			}

			env.resize(newSize)
			console.log('Resized database', name, 'to', newSize)
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
			console.warn('Corrupted database,', location, 'attempting to delete the store file and restart', error)
			fs.removeSync(location + '.mdb')
			env = new Env()
			env.open(options)
			openDB()
			return retry()
		}
		readTxn = env.beginTxn(READING_TNX)
		readTxn.reset()
		error.message = 'In database ' + name + ': ' + error.message
		throw error
	}
}

class ConditionalWriteResult {
	constructor(syncResults, index) {
		this.syncResults = syncResults
		this.index = index
	}
	get synced() {
		return this._synced || (this._synced = this.syncResults.then((writeResults) =>
			writeResults[this.index] === 0)) // 0 is success
	}
	get committed() {
		return this._committed || (this._committed = this.syncResults.committed.then((writeResults) =>
			writeResults[this.index] === 0))
	}
	get written() {
		// TODO: If we provide progress events, we can fulfill this as soon as this is written in the transaction
		return this.committed
	}
	then(onFulfilled, onRejected) {
		return this.synced.then(onFulfilled, onRejected)
	}
}
