import { getAddress } from './native.mjs'
import { when } from './util/when.mjs'
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
export const ABORT = {}
const CALLBACK_THREW = {}
const IMMEDIATE = -1
SYNC_PROMISE_SUCCESS.isSync = true
SYNC_PROMISE_FAIL.isSync = true

var log = []
export function addWriteMethods(LMDBStore, { env, fixedBuffer, resetReadTxn, useWritemap }) {
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
	var nextTxnCallbacks = []
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
				Atomics.wait(backpressureArray, 0, 0, 1)
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
					commitDelay == 0 ? setImmediate(startWriting) : setTimeout(startWriting, commitDelay)
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
			if (unwrittenResolution.callbacks) {
				nextTxnCallbacks.push(unwrittenResolution.callbacks)
				unwrittenResolution.callbacks = null
			}
			unwrittenResolution.valueBuffer = null
			if (instructionStatus & TXN_DELIMITER) {
				let position = unwrittenResolution.flag
				unwrittenResolution.flag = instructionStatus & 0x1000000f
				if (instructionStatus & 0x80000000)
					rejectCommit()
				else if (instructionStatus & TXN_COMMITTED) {
					resolveCommit(async)
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
		env.beginTxn(0)
		env.writeTxn = writeTxn = {}
		let promises
		let txnCallbacks
		for (let i = 0, l = nextTxnCallbacks.length; i < l; i++) {
			txnCallbacks = nextTxnCallbacks[i]
			for (let i = 0, l = txnCallbacks.length; i < l; i++) {
				let userTxnCallback = txnCallbacks[i]
				let asChild = userTxnCallback.asChild
				if (asChild) {
					if (promises) {
						// must complete any outstanding transactions before proceeding
						await Promise.all(promises)
						promises = null
					}
					env.beginTxn(1) // abortable
					
					try {
						let result = userTxnCallback.callback()
						if (result && result.then) {
							await result
						}
						if (result === ABORT)
							env.abortTxn()
						else
							env.commitTxn()
							txnCallbacks[i] = result
					} catch(error) {
						env.abortTxn()
						txnError(error, i)
					}
				} else {
					try {
						let result = userTxnCallback()
						txnCallbacks[i] = result
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
		}
		nextTxnCallbacks = []
		if (promises) { // finish any outstanding commit functions
			await Promise.all(promises)
		}
		env.writeTxn = writeTxn = false
		console.log('async callback resume write trhead')
		lastQueuedTxnCallbacks = null
		return env.commitTxn()
		function txnError(error, i) {
			(txnCallbacks.errors || (txnCallbacks.errors = []))[i] = error
			txnCallbacks[i] = CALLBACK_THREW
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
		ifNoExists(key, callback) {
			return this.ifVersion(key, null, callback)
		},

		ifVersion(key, version, callback) {
			if (!callback) {
				return new Batch((operations, callback) => {
					let promise = this.ifVersion(key, version, operations)
					if (callback)
						promise.then(callback)
					return promise
				})
			}
			if (writeTxn) {
				if (this.doesExist(key, version)) {
					callback()
					return SYNC_PROMISE_SUCCESS
				}
				return SYNC_PROMISE_FAIL
			}
			let finishWrite = writeInstructions(typeof key === 'undefined' ? 1 : 4, this, key, undefined, undefined, version)
			let promise
			console.log('wrote start of ifVersion', this.path)
			try {
				if (typeof callback === 'function') {
					promise = finishWrite() // commit to writing the whole block in the current transaction
					callback()
				} else {
					for (let i = 0, l = callback.length; i < l; i++) {
						let operation = callback[i]
						this[operation.type](operation.key, operation.value)
					}
					promise = finishWrite() // finish write once all the operations have been written
				}
			} finally {
				console.log('writing end of ifVersion', this.path, (dynamicBytes.buffer.address + ((dynamicBytes.position + 1) << 3)).toString(16))
				dynamicBytes.uint32[(dynamicBytes.position + 1) << 1] = 0 // clear out the next slot
				let writeStatus = atomicStatus(dynamicBytes.uint32, (dynamicBytes.position++) << 1, 2) // atomically write the end block
				if (writeStatus & WAITING_OPERATION) {
					console.log('ifVersion resume write thread')
					env.startWriting(0)
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
				env.beginTxn(1) // abortable
				try {
					return when(callback(), (result) => {
						if (result === ABORT)
							env.abortTxn()
						else
							env.commitTxn()
						return result
					}, (error) => {
						env.abortTxn()
						throw error
					})
				} catch(error) {
					env.abortTxn()
					throw error
				}
			}
			return this.transactionAsync(callback, true)
		},
		transactionAsync(callback, asChild) {
			// TODO: strict ordering
			let txnIndex
			let txnCallbacks
			if (!lastQueuedResolution || !lastQueuedResolution.callbacks) {
				txnCallbacks = [asChild ? { callback, asChild } : callback]
				txnCallbacks.results = writeInstructions(8, this)()
				lastQueuedResolution.callbacks = txnCallbacks
				txnIndex = 0
			} else {
				txnCallbacks = lastQueuedResolution.callbacks
				txnIndex = txnCallbacks.push(asChild ? { callback, asChild } : callback) - 1
			}
			return txnCallbacks.results.then((results) => {
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
			try {
				this.transactions++
				let flags = 0
				if (!(options && options.abortable === false))
					flags = 1
				if (!(options && options.synchronousCommit === false))
					flags |= 2
				env.beginTxn(flags)
				writeTxn = env.writeTxn = {}
				return when(callback(), (result) => {
					try {
						if (result === ABORT)
							env.abortTxn()
						else {
							env.commitTxn()
							resetReadTxn()
						}

						return result
					} finally {
						env.writeTxn = writeTxn = null
					}
				}, (error) => {
					try { env.abortTxn() } catch(e) {}
					env.writeTxn = writeTxn = null
					throw error
				})
			} catch(error) {
				try { env.abortTxn() } catch(e) {}
				env.writeTxn = writeTxn = null
				throw error
			}
		}
	})
	LMDBStore.prototype.del = LMDBStore.prototype.remove
}

class Batch extends Array {
	constructor(callback) {
		this.callback = callback
	}
	put(key, value) {
		this.push({ type: 'put', key, value })
	}
	del(key) {
		this.push({ type: 'del', key })
	}
	clear() {
		this.splice(0, this.length)
	}
	write(callback) {
		this.callback(this, callback)
	}
}
