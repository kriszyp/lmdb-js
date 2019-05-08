const fs = require('fs-extra')
const pathModule = require('path')
const { Env, openDbi, Cursor } = require('node-lmdb')
const { ArrayLikeIterable } = require('./util/ArrayLikeIterable')
//import { Database } from './Database'
const when  = require('./util/when')
const { WeakValueMap } = require('./util/WeakValueMap')

const STARTING_ARRAY = [null]
const VALUE_OVERFLOW_THRESHOLD = 2048
const AS_STRING = {
	asBuffer: false
}
const AS_BINARY = {
	keyIsBuffer: true
}
const AS_BINARY_ALLOW_NOT_FOUND = {
	keyIsBuffer: true,
	ignoreNotFound: true
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
const EXTENSION = '.mdpack'
exports.open = open
function open(path, options) {
	let env = new Env()
	let db
	let committingWrites
	let scheduledWrites
	let scheduledOperations
	let sharedBuffersActive = new WeakValueMap()
	let sharedBuffersToInvalidate = new WeakValueMap()
	let shareId = 0
	let extension = pathModule.extname(path)
	let name = pathModule.basename(path, extension)
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

	function openDB() {
		try {
			db = env.openDbi({
				name: 'data',
				create: true,
				keyIsBuffer: true,
			})
		} catch(error) {
			handleError(error, null, null, openDB)
		}
	}
	openDB()
	const store = {
		db,
		env,
		path,
		name,
		bytesRead: 0,
		bytesWritten: 0,
		reads: 0,
		writes: 0,
		transactions: 0,
		readTxn: env.beginTxn(READING_TNX),
//		sharedBuffersActiveTxn: env.beginTxn(READING_TNX),
//		sharedBuffersToInvalidateTxn: env.beginTxn(READING_TNX),
		transaction(execute, noSync, abort) {
			let result
			if (this.writeTxn) {
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
				txn = this.writeTxn = env.beginTxn()
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
				this.writeTxn = null
			}
		},
		get(id, options) {
			let txn
			try {
				const writeTxn = this.writeTxn
				if (writeTxn) {
					txn = writeTxn
				} else {
					txn = this.readTxn
					txn.renew()
				}
				let result = (options && options.noCopy) ? txn.getBinaryUnsafe(db, id, AS_BINARY) : txn.getBinary(db, id, AS_BINARY)
				
				if (!writeTxn) {
					txn.reset()
				}
				this.bytesRead += result && result.length || 1
				this.reads++
				if (result !== null) // missing entry, really should be undefined
					return result
			} catch(error) {
				return handleError(error, this, txn, () => this.get(id))
			}
		},
		notifyOnInvalidation(buffer, onInvalidation) {
			if (!buffer)
				return
			let parentArrayBuffer = buffer.buffer // this is the internal ArrayBuffer with that references the external/shared memory
			sharedBuffersActive.set(shareId++, parentArrayBuffer)
			parentArrayBuffer.onInvalidation = onInvalidation
		},
		put(id, value, ifValue) {
			if (!scheduledOperations) {
				scheduledOperations = []
			}
			let index = scheduledOperations.push([db, id, value, ifValue]) - 1
			let commit = this.scheduleCommit()
			return ifValue === undefined ? commit.unconditionalResults :
				commit.results.then((writeResults) => writeResults[index] === 0)
		},
		putSync(id, value) {
			let txn
			try {
				if (typeof value !== 'object') {
					throw new Error('putting string value')
					value = Buffer.from(value)
				}
				this.bytesWritten += value && value.length || 0
				this.writes++
			    let startCpu = process.cpuUsage()
				let start = Date.now()

				txn = this.writeTxn || env.beginTxn()
				txn.putBinary(db, id, value, AS_BINARY)
				/*if (Date.now() - start > 20)
					console.log('after put', Date.now() - start, process.cpuUsage(startCpu))*/
				if (!this.writeTxn) {
					txn.commit()
					//console.log('after commit', Date.now() - start, process.cpuUsage(startCpu))
				}
			} catch(error) {
				if (this.writeTxn)
					throw error // if we are in a transaction, the whole transaction probably needs to restart
				return handleError(error, this, txn, () => this.put(id, value))
			}
		},
		removeSync(id) {
			let txn
			try {
				txn = this.writeTxn || env.beginTxn()
				this.writes++
				txn.del(db, id)
				if (!this.writeTxn) {
					txn.commit()
				}
				return true // object found and deleted
			} catch(error) {
				if (error.message.startsWith('MDB_NOTFOUND')) {
					if (!this.writeTxn)
						txn.abort()
					return false // calling remove on non-existent property is fine, but we will indicate its lack of existence with the return value
				}
				if (this.writeTxn)
					throw error // if we are in a transaction, the whole transaction probably needs to restart
				return handleError(error, this, txn, () => this.remove(id))
			}
		},
		remove(id, ifValue) {
			if (!scheduledOperations) {
				scheduledOperations = []
			}
			let index = scheduledOperations.push([db, id, undefined, ifValue]) - 1
			let commit = this.scheduleCommit()
			return ifValue === undefined ? commit.unconditionalResults :
				commit.results.then((writeResults) => writeResults[index] === 0)
		},
		iterable(options) {
			let iterable = new ArrayLikeIterable()
			iterable[Symbol.iterator] = (async) => {
				let currentKey = options.start || (options.reverse ? Buffer.from([255, 255]) : Buffer.from([0]))
				let endKey = options.end || (options.reverse ? Buffer.from([0]) : Buffer.from([255, 255]))
				const reverse = options.reverse
				let count = 0
				const goToDirection = reverse ? 'goToPrev' : 'goToNext'
				const getNextBlock = () => {
					array = []
					let cursor, txn = store.readTxn
					try {
						txn.renew()
						cursor = new Cursor(txn, db, AS_BINARY)
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
						while (!(finished = currentKey === null || (reverse ? currentKey.compare(endKey) <= 0 : currentKey.compare(endKey) >= 0)) && i++ < 100) {
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
						txn.reset()
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
						console.log('return called on iterator', this.ended)
						return { done: true }
					},
					throw() {
						console.log('throw called on iterator', this.ended)
						return { done: true }
					}
				}
			}
			return iterable
		},
		averageTransactionTime: 5,
		scheduleCommit() {
			if (!this.pendingBatch) {
				// pendingBatch promise represents the completion of the transaction
				let whenCommitted = new Promise((resolve, reject) => {
					when(this.currentCommit, () => {
						let timeout = setTimeout(this.runNextBatch = () => {
							this.runNextBatch = null
							clearTimeout(timeout)
							this.currentCommit = whenCommitted
							this.pendingBatch = null
							this.pendingSync = null
							if (scheduledOperations) {
								// operations to perform, collect them as an array and start doing them
								let operations = scheduledOperations
								scheduledOperations = null
								const doBatch = () => {
									let start = Date.now()
									env.batchWrite(operations, AS_BINARY_ALLOW_NOT_FOUND, (error, results) => {
										let duration = Date.now() - start
										this.averageTransactionTime = (this.averageTransactionTime * 3 + duration) / 4
										//console.log('did batch', (duration) + 'ms', name, operations.length/*map(o => o[1].toString('binary')).join(',')*/)
										if (error) {
											try {
												// see if we can recover from recoverable error (like full map with a resize)
												handleError(error, this, null, doBatch)
											} catch(error) {
												this.currentCommit = null
												reject(error)
											}
										} else {
											this.currentCommit = null
											resolve(results)
										}
									})
								}
								doBatch()
							}
						}, 20)
					})
				})
				this.pendingBatch = {
					results: whenCommitted,
					unconditionalResults: whenCommitted.then(() => true) // for returning for non-conditional
				}
			}
			if (scheduledOperations && scheduledOperations.length > 3000 && this.runNextBatch) {
				// past a certain threshold, run it immediately
				let batch = this.pendingBatch
				this.runNextBatch()
				return batch
			}
			return this.pendingBatch
		},
		batch(operations) {
			this.writes += operations.length
			this.bytesWritten += operations.reduce((a, b) => a + (b.value && b.value.length || 0), 0)
			for (let operation of operations) {
				if (typeof operation.key != 'object')
					throw new Error('non-buffer key')
				try {
					let value = operation.value
					if (!scheduledOperations) {
						scheduledOperations = []
					}
					scheduledOperations.push([db, operation.key, value])
				} catch (error) {
					if (error.message.startsWith('MDB_NOTFOUND')) {
						// not an error
					} else {
						throw error
					}
				}
			}
			return this.scheduleCommit().unconditionalResults
		},
		close() {
			db.close()
			env.close()
		},
		resetSharedBuffers(force) {
			// these have to overlap, so we can access the old buffers and be assured anything that sticks around still has a read txn before it
/*			let toAbort = this.sharedBuffersToInvalidateTxn
			this.sharedBuffersToInvalidateTxn = this.sharedBuffersActiveTxn
			if (!force)
				this.sharedBuffersActiveTxn = env.beginTxn(READING_TNX)*/

			let newSharedBuffersActive = new WeakValueMap();
			[sharedBuffersToInvalidate, sharedBuffersActive].forEach((sharedBuffers, i) => {
				let bufferIds = sharedBuffers._keysAsArray()
				for (const id of bufferIds) {
					let buffer = sharedBuffers.get(id)
					let forceUnload = force || buffer.length < VALUE_OVERFLOW_THRESHOLD
					if (buffer && buffer.onInvalidation) {
						if (buffer.onInvalidation(forceUnload || i) === false && !forceUnload) {
							newSharedBuffersActive.set(id, buffer)
						}
						// else false is specifically indicating that the shared buffer is still valid, so keep it around in that case
					}
				}
			})
			if (force) {
				sharedBuffersToInvalidate = new WeakValueMap()
			} else {
				sharedBuffersToInvalidate = sharedBuffersActive
			}
			sharedBuffersActive = newSharedBuffersActive
			/*try {
				toAbort.abort() // release the previous shared buffer txn
			} catch(error) {
				console.warn(error)
			}
			try {
			if (force) {
				this.sharedBuffersToInvalidateTxn.abort()
			}
			} catch(error) {
				console.warn(error)
			}*/
		},
		sync(callback) {
			return env.sync(callback || function(error) {
				if (error) {
					console.error(error)
				}
			})
		},
		clear() {
			//console.log('clearing db', name)
			try {
				db.drop({
					justFreePages: true,
					txn: this.writeTxn,
				})
			} catch(error) {
				handleError(error, this, null, () => this.clear())
			}
		},
		testResize() {
			handleError(new Error('MDB_MAP_FULL'), this, null, () => {
				console.log('done resizing')
			})
		}
	}
	store.readTxn.reset()
	allDbs.set(name, store)
	return store
	function handleError(error, db, txn, retry) {
		try {
			if (db && db.readTxn) {
				db.readTxn.abort()
			}
		} catch(error) {
		//	console.warn('txn already aborted')
		}
		try {
			if (db && db.writeTxn)
				db.writeTxn.abort()
		} catch(error) {
		//	console.warn('txn already aborted')
		}
		try {
			if (txn && txn !== (db && db.readTxn) && txn !== (db && db.writeTxn))
				txn.abort()
		} catch(error) {
		//	console.warn('txn already aborted')
		}

		if (db && db.writeTxn)
			db.writeTxn = null
		if (error.message == 'The transaction is already closed.') {
			try {
				db.readTxn = env.beginTxn(READING_TNX)
			} catch(error) {
				return handleError(error, db, null, retry)
			}
			return retry()
		}
		if (error.message.startsWith('MDB_MAP_FULL') || error.message.startsWith('MDB_MAP_RESIZED')) {
			const newSize = Math.ceil(env.info().mapSize * 1.3 / 0x200000 + 1) * 0x200000
			if (db) {
				try {
				db.resetSharedBuffers(true)
				}catch (error) {
					console.error(error)
				}
			}

			env.resize(newSize)
			console.log('Resized database', name, 'to', newSize)
			if (db) {
				db.readTxn = env.beginTxn(READING_TNX)
				db.readTxn.reset()
				//db.sharedBuffersActiveTxn = env.beginTxn(READING_TNX)
				//db.sharedBuffersToInvalidateTxn = env.beginTxn(READING_TNX)
			}
			let result = retry()
			return result
		} else if (error.message.startsWith('MDB_PAGE_NOTFOUND') || error.message.startsWith('MDB_CURSOR_FULL') || error.message.startsWith('MDB_CORRUPTED') || error.message.startsWith('MDB_INVALID')) {
			// the noSync setting means that we can have partial corruption and we need to be able to recover
			try {
				env.close()
			} catch (error) {}
			console.warn('Corrupted database,', location, 'attempting to delete the db file and restart', error)
			fs.removeSync(location + '.mdb')
			env = new Env()
			env.open(options)
			openDB()
			return retry()
		}
		db.readTxn = env.beginTxn(READING_TNX)
		db.readTxn.reset()
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
