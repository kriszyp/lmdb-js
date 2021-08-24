const { getAddress } = require('./native')
const when  = require('./util/when')
var backpressureArray

const MAX_KEY_SIZE = 1978
const PROCESSING = 0x20000000
const STATUS_LOCKED = 0x200000;
const WAITING_OPERATION = 0x400000;
const BACKPRESSURE_THRESHOLD = 5000000
const TXN_DELIMITER = 0x20000000
const TXN_COMMITTED = 0x40000000
const BATCH_DELIMITER = 0x8000000;

const SYNC_PROMISE_SUCCESS = Promise.resolve(true)
const SYNC_PROMISE_FAIL = Promise.resolve(false)
const ABORT = {}
const CALLBACK_THREW = {}
const IMMEDIATE = -1
exports.ABORT = ABORT
SYNC_PROMISE_SUCCESS.isSync = true
SYNC_PROMISE_FAIL.isSync = true

var log = []
exports.addWriteMethods = function(LMDBStore, { env, fixedBuffer, resetReadTxn, useWritemap }) {
	var unwrittenResolution, lastQueuedResolution = {}, uncommittedResolution 
	//  stands for write instructions
	var dynamicBytes
	function allocateInstructionBuffer() {
		dynamicBytes = Buffer.allocUnsafeSlow(0x10000)
		dynamicBytes.uint32 = new Uint32Array(dynamicBytes.buffer, 0, 0x10000 >> 2)
		dynamicBytes.uint32[0] = 0
		dynamicBytes.float64 = new Float64Array(dynamicBytes.buffer, 0, 0x10000 >> 3)
		dynamicBytes.buffer.address = getAddress(dynamicBytes.buffer)
		dynamicBytes.address = dynamicBytes.buffer.address + dynamicBytes.byteOffset
		dynamicBytes.position = 0
		return dynamicBytes
	}
	var lastCompressibleFloat64 = new Float64Array(1)
	var lastCompressiblePosition = 0
	var lastDynamicBytes
	var compressionCount = 0
	var outstandingWriteCount = 0
	var startAddress = 0
	var writeTxn = null
	var abortedNonChildTransactionWarn
	var nextTxnCallbacks
	var lastQueuedTxnCallbacks
	var commitPromise
	var commitDelay = IMMEDIATE
	var enqueuedStart

	allocateInstructionBuffer()
	dynamicBytes.uint32[0] = TXN_DELIMITER
	function writeInstructions(flags, store, key, value, version, ifVersion) {
		let writeStatus, compressionStatus = false
		let targetBytes, position
		let valueBuffer
		if (flags & 2) {
			// encode first in case we have to write a shared structure
			if (store.encoder) {
				//if (!(value instanceof Uint8Array)) TODO: in a future version, directly store buffers that are provided
				valueBuffer = store.encoder.encode(value)
				if (typeof valueBuffer == 'string')
					valueBuffer = Buffer.from(valueBuffer) // TODO: Would be nice to write strings inline in the instructions
			} else if (typeof value == 'string') {
				valueBuffer = Buffer.from(value) // TODO: Would be nice to write strings inline in the instructions
			} else if (value instanceof Uint8Array)
				valueBuffer = value
			else
				throw new Error('Invalid value to put in database ' + value + ' (' + (typeof value) +'), consider using encoder')
		}
		if (writeTxn) {
			targetBytes = fixedBuffer
			position = 0
		} else {
			targetBytes = dynamicBytes
			position = targetBytes.position
			if (position > 8100) { // 6000 bytes
				// make new buffer and make pointer to it
				let lastBuffer = targetBytes
				let lastPosition = targetBytes.position
				let lastFloat64 = targetBytes.float64
				let lastUint32 = targetBytes.uint32
				targetBytes = allocateInstructionBuffer()
				position = targetBytes.position
				lastFloat64[lastPosition + 1] = targetBytes.buffer.address + position
				lastUint32[lastPosition << 1] = 3 // pointer instruction
			}
		}
		let uint32 = targetBytes.uint32, float64 = targetBytes.float64
		let flagPosition = position << 1 // flagPosition is the 32-bit word starting position

		// don't increment Position until we are sure we don't have any key writing errors
		uint32[flagPosition + 1] = store.db.dbi
		let nextCompressible
		if (flags & 4) {
			let keyStartPosition = (position << 3) + 12
			let endPosition
			try {
				endPosition = store.writeKey(key, targetBytes, keyStartPosition)
			} catch(error) {
				targetBytes.fill(0, keyStartPosition)
				throw error
			}
			let keySize = endPosition - keyStartPosition
			if (keySize > MAX_KEY_SIZE) {
				targetBytes.fill(0, keyStartPosition)
				throw new Error('Key size is too large')
			}
			uint32[flagPosition + 2] = keySize
			position = (endPosition + 16) >> 3
			if (flags & 2) {
				uint32[(position << 1) - 1] = valueBuffer.length
				let valueArrayBuffer = valueBuffer.buffer
				// record pointer to value buffer
				float64[position++] = (valueArrayBuffer.address || (valueArrayBuffer.address = getAddress(valueArrayBuffer))) + valueBuffer.byteOffset
				if (store.compression && valueBuffer.length >= store.compression.threshold) {
					flags |= 0x100000;
					float64[position] = 0
					float64[position + 1] = store.compression.address
					nextCompressible = targetBytes.buffer.address + (position << 3)
					compressionStatus = !lastCompressibleFloat64[lastCompressiblePosition]
					lastCompressibleFloat64[lastCompressiblePosition] = nextCompressible
					lastCompressiblePosition = position
					lastCompressibleFloat64 = float64
					position += 2
					compressionCount++
				}
			}
			if (ifVersion !== undefined) {
				if (ifVersion === null)
					flags |= 0x10
				else {
					flags |= 0x100
					float64[position++] = ifVersion
				}
			}
			if (version !== undefined) {
				flags |= 0x200
				float64[position++] = version || 0
			}
		} else
			position++
		targetBytes.position = position
		//console.log('js write', (targetBytes.buffer.address + (flagPosition << 2)).toString(16), flags.toString(16))
		if (writeTxn) {
			uint32[0] = flags
			env.write(targetBytes.buffer.address)
			return () => (uint32[0] & 1) ? SYNC_PROMISE_FAIL : SYNC_PROMISE_SUCCESS
		}
		uint32[position << 1] = 0 // clear out the next slot
		return () => {
			//writeStatus = Atomics.or(uint32, flagPosition, flags) || writeStatus
			// write flags at the end so the writer never processes mid-stream, and do so th an atomic exchanges
			//writeStatus = atomicStatus(uint32, flagPosition, flags)
			uint32[flagPosition] = flags
			writeStatus = lastUint32[lastFlagPosition]
			while (writeStatus & STATUS_LOCKED) {
				//console.log('spin lock!')
				writeStatus = lastUint32[lastFlagPosition]
			}
			//console.log('writeStatus: ' + writeStatus.toString(16) + ' address: ' + (lastUint32.buffer.address + (lastFlagPosition << 2)).toString(16), store.path)
	
			lastUint32 = uint32
			lastFlagPosition = flagPosition
			outstandingWriteCount++
			if (writeStatus) {
				if (writeStatus & TXN_DELIMITER)
					commitPromise = null
				if (writeStatus & WAITING_OPERATION) { // write thread is waiting
					//console.log('resume batch thread', targetBytes.buffer.address + (flagPosition << 2))
					env.startWriting(0)
				} else if ((writeStatus & BATCH_DELIMITER) && !startAddress) {
					startAddress = targetBytes.buffer.address + (flagPosition << 2)
				}
			} else if (compressionStatus) {
				env.compress(nextCompressible)
			} else if (outstandingWriteCount > BACKPRESSURE_THRESHOLD) {
				console.log('backpressure')
				if (!backpressureArray)
					backpressureArray = new Int8Array(new SharedArrayBuffer(4), 0, 1)
				Atomics.wait(backpressure, 0, 0, 1)
			}
			if (startAddress && (flags & 8) && !enqueuedStart) {
				//console.log('start address ' + startAddress.toString(16), store.path)
				function startWriting() {
					env.startWriting(startAddress, compressionStatus ? nextCompressible : 0, (status) => {
						//console.log('finished batch', unwrittenResolution && (unwrittenResolution.uint32[unwrittenResolution.flag]).toString(16), store.path)
						resolveWrites(true)
						switch (status) {
							case 0: case 1:
							break;
							case 2:
								executeTxnCallbacks()
								console.log('user callback');
							break
							default:
							console.error(status)
							if (commitRejectPromise) {
								commitRejectPromise.reject(status)
								commitRejectPromise = null
							}
						}
					})
					startAddress = 0
				}
				if (commitDelay == IMMEDIATE)
					startWriting()
				else {
					setImmediate(startWriting)
					enqueuedStart = true
				}
			}

			if ((outstandingWriteCount & 7) === 0)
				resolveWrites()
			let newResolution = {
				uint32,
				flag: flagPosition,
				valueBuffer,
				nextResolution: null,
			}
			if (!unwrittenResolution) {
				unwrittenResolution = newResolution
				if (!uncommittedResolution)
					uncommittedResolution = newResolution
			}
			lastQueuedResolution.nextResolution = newResolution
			lastQueuedResolution = newResolution
			if (ifVersion === undefined) {
				if (!commitPromise) {
					commitPromise = new Promise((resolve, reject) => {
						newResolution.resolve = resolve
						newResolution.reject = reject
					})
				}
				return commitPromise
			}
			return new Promise((resolve, reject) => {
				newResolution.resolve = resolve
				newResolution.reject = reject
			})
		}
	}
	var lastUint32 = new Uint32Array([BATCH_DELIMITER]), lastFlagPosition = 0
	function resolveWrites(async) {
		// clean up finished instructions
		let instructionStatus
		while (unwrittenResolution && (instructionStatus = unwrittenResolution.uint32[unwrittenResolution.flag]) & 0x10000000) {
			//console.log('instructionStatus: ' + instructionStatus.toString(16))
			unwrittenResolution.valueBuffer = null
			if (instructionStatus & TXN_DELIMITER) {
				let position = unwrittenResolution.flag
				unwrittenResolution.flag = instructionStatus & 0x1000000f
				if (instructionStatus & 0x80000000)
					rejectCommit()
				else if (instructionStatus & TXN_COMMITTED) {
					resolveCommit(async	)					
				} else {
					unwrittenResolution.flag = position // restore position for next iteration
					return // revisit when it is done (but at least free the value buffer)
				}
			} else {
				if (!unwrittenResolution.nextResolution)
					return // don't advance yet, wait to see if it a transaction delimiter that will commit
				unwrittenResolution.flag = instructionStatus
			}
			outstandingWriteCount--
			unwrittenResolution.debuggingPosition = unwrittenResolution.flag
			unwrittenResolution.uint32 = null
			unwrittenResolution = unwrittenResolution.nextResolution
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
			resetReadTxn()
		else
			queueMicrotask(resetReadTxn) // TODO: only do this if there are actually committed writes?
		do {
			if (uncommittedResolution.resolve) {
				let flag = uncommittedResolution.flag
				if (flag < 0)
					uncommittedResolution.reject(new Error("Error occurred in write"))
				else if (flag & 1) {
					uncommittedResolution.resolve(false)
				} else
					uncommittedResolution.resolve(true)
					
			}
			
			if (uncommittedResolution == unwrittenResolution) {
				return uncommittedResolution = uncommittedResolution.nextResolution
			}
		} while(uncommittedResolution = uncommittedResolution.nextResolution)
	}
	var commitRejectPromise
	function rejectCommit() {
		if (!commitRejectPromise) {
			let rejectFunction
			commitRejectPromise = new Promise((resolve, reject) => rejectFunction = reject)
			commitRejectPromise.reject = rejectFunction
		}
		while (uncommittedResolution != unwrittenResolution && uncommittedResolution) {
			let flag = uncommittedResolution.flag & 0xf
			let error = new Error("Commit failed (see commitError for details)")
			error.commitError = commitRejectPromise
			uncommittedResolution.reject(error)
			uncommittedResolution = uncommittedResolution.nextResolution
		}
	}
	function atomicStatus(uint32, flagPosition, newStatus) {
		uint32[flagPosition] = newStatus
		let writeStatus = lastUint32[lastFlagPosition]
		while (writeStatus & STATUS_LOCKED) {
			//console.log('spin lock!')
			writeStatus = lastUint32[lastFlagPosition]
		}
		//console.log('writeStatus: ' + writeStatus.toString(16) + ' address: ' + (lastUint32.buffer.address + (lastFlagPosition << 2)).toString(16))
		return writeStatus
	}
	async function executeTxnCallbacks() {
		let continuedWriteTxn = env.beginTxn(0)
		let promises, i
		for (i = 0, l = nextTxnCallbacks.length; i < l; i++) {
			let userTxnCallback = nextTxnCallbacks[i]
			let asChild = userTxnCallback.asChild
			if (asChild) {
				if (promises) {
					// must complete any outstanding transactions before proceeding
					await Promise.all(promises)
					promises = null
				}
				let childTxn = env.writeTxn = writeTxn = env.beginTxn(null, continuedWriteTxn)
				
				try {
					let result = userTxnCallback.callback()
					if (result && result.then) {
						await result
					}
					if (result === ABORT)
						childTxn.abort()
					else
						childTxn.commit()
						nextTxnCallbacks[i] = result
				} catch(error) {
					childTxn.abort()
					txnError(error, i)
				}
			} else {
				env.writeTxn = writeTxn = continuedWriteTxn
				try {
					let result = userTxnCallback()
					nextTxnCallbacks[i] = result
					if (result && result.then) {
						if (!promises)
							promises = []
						promises.push(result.catch(() => {}))
					}
				} catch(error) {
					txnError(error, i)
				}
			}
		}
		if (promises) { // finish any outstanding commit functions
			await Promise.all(promises)
		}
		env.writeTxn = writeTxn = null
		console.log('async callback resume write trhead')
		nextTxnCallbacks = nextTxnCallbacks.next
		lastQueuedTxnCallbacks = null
		return env.commitTxn()
		function txnError(error, i) {
			(nextTxnCallbacks.errors || (nextTxnCallbacks.errors = []))[i] = error
			nextTxnCallbacks[i] = CALLBACK_THREW
		}
	}
	Object.assign(LMDBStore.prototype, {
		put(key, value, versionOrOptions, ifVersion) {
			let sync, flags = 15
			if (typeof versionOrOptions == 'object') {
				if (versionOrOptions.noOverwrite)
					flags |= 0x10
				if (versionOrOptions.noDupData)
					flags |= 0x20
				if (versionOrOptions.append)
					flags |= 0x20000
				if (versionOrOptions.ifVersion != undefined)
					ifVersion = versionsOrOptions.ifVersion
				versionOrOptions = versionOrOptions.version
			}
			return writeInstructions(flags, this, key, value, this.useVersions ? versionOrOptions || 0 : undefined, ifVersion)()
		},
		remove(key, ifVersionOrValue) {
			let flags = 13
			let ifVersion, value
			if (ifVersionOrValue !== undefined) {
				if (this.useVersions)
					ifVersion = ifVersionOrValue
				else {
					flags = 14
					value = ifVersionOrValue
				}
			}
			return writeInstructions(flags, this, key, value, undefined, ifVersion)()
		},
		ifVersion(key, version, callback) {
			if (writeTxn) {

			}
			let finishWrite = writeInstructions(4, this, key, undefined, undefined, version)
			if (callback) {
				let promise = finishWrite() // commit to writing the whole block in the current transaction
				console.log('wrote start of ifVersion', this.path)
				try {
					callback()
				} catch(error) {
					// TODO: Restore state
					throw error
				}
				console.log('writing end of ifVersion', this.path, (dynamicBytes.buffer.address + ((dynamicBytes.position + 1) << 3)).toString(16))
				dynamicBytes.uint32[(dynamicBytes.position + 1) << 1] = 0 // clear out the next slot
				let writeStatus = atomicStatus(dynamicBytes.uint32, (dynamicBytes.position++) << 1, 2) // atomically write the end block
				if (writeStatus & WAITING_OPERATION) {
					console.log('ifVersion resume write thread')
					env.startWriting(0)
				}
				return promise
			} else {
				return new Batch(() => {
					// write the end block
					dynamicBytes.uint32[(dynamicBytes.position + 1) << 1] = 0
					dynamicBytes.uint32[(dynamicBytes.position++) << 1] = 2
					// and then write the start block to so it is enqueued atomically
					return finishWrite()
				})
			}
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
		transaction(callback) {
			if (writeTxn) {
				// already nested in a transaction, just execute and return
				if (useWritemap)
					return callback()
				else
					return this.childTransaction(callback)
			}
			return this.transactionAsync(callback)
		},
		childTransaction(callback) {
			if (useWritemap)
				throw new Error('Child transactions are not supported in writemap mode')
			if (writeTxn) {
				let parentTxn = writeTxn
				let childTxn = env.writeTxn = writeTxn = env.beginTxn(null, parentTxn)
				try {
					return when(callback(), (result) => {
						env.writeTxn = writeTxn = parentTxn
						if (result === ABORT)
							childTxn.abort()
						else
							childTxn.commit()
						return result
					}, (error) => {
						env.writeTxn = writeTxn = parentTxn
						childTxn.abort()
						throw error
					})
				} catch(error) {
					env.writeTxn = writeTxn = parentTxn
					childTxn.abort()
					throw error
				}
			}
			return this.transactionAsync(callback, true)
		},
		transactionAsync(callback, asChild) {
			// TODO: strict ordering
			let txnIndex
			let txnCallbacks
			if (!lastQueuedTxnCallbacks) {
				txnCallbacks = lastQueuedTxnCallbacks = [asChild ? { callback, asChild } : callback]
				txnIndex = 0
				lastQueuedTxnCallbacks.results = writeInstructions(8, this)()
			} else {
				txnCallbacks = lastQueuedTxnCallbacks
				txnIndex = lastQueuedTxnCallbacks.push(asChild ? { callback, asChild } : callback) - 1
			}
			if (!nextTxnCallbacks)
				nextTxnCallbacks = txnCallbacks
			return lastQueuedTxnCallbacks.results.then((results) => {
				let result = txnCallbacks[txnIndex]
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
				let result = callback() // else just run in current transaction
				if (result == ABORT && !abortedNonChildTransactionWarn) {
					console.warn('Can not abort a transaction inside another transaction with ' + (this.cache ? 'caching enabled' : 'useWritemap enabled'))
					abortedNonChildTransactionWarn = true
				}
				return result
			}
			let txn
			try {
				this.transactions++
				let flags = 0
				if (!(options && options.abortable === false))
					flags = 1
				if (!(options && options.synchronousCommit === false))
					flags &= 2
				txn = writeTxn = env.writeTxn = env.beginTxn(flags)
				return when(callback(), (result) => {
					try {
						if (result === ABORT)
							txn.abort()
						else {
							txn.commit()
							resetReadTxn()
						}

						return result
					} finally {
						env.writeTxn = writeTxn = null
					}
				}, (error) => {
					try { txn.abort() } catch(e) {}
					env.writeTxn = writeTxn = null
					throw error
				})
			} catch(error) {
				try { txn.abort() } catch(e) {}
				env.writeTxn = writeTxn = null
				throw error
			}
		}
	})
}
