import { getAddress } from './native.js'
import { when } from './util/when.js'
var backpressureArray

const MAX_KEY_SIZE = 1978
const PROCESSING = 0x20000000
const STATUS_LOCKED = 0x200000;
const WAITING_OPERATION = 0x400000;
const BACKPRESSURE_THRESHOLD = 5000000
const TXN_DELIMITER = 0x20000000
const TXN_COMMITTED = 0x40000000
const BATCH_DELIMITER = 0x8000000
const FAILED_CONDITION = 0x200000

const SYNC_PROMISE_SUCCESS = Promise.resolve(true)
const SYNC_PROMISE_FAIL = Promise.resolve(false)
export const ABORT = {}
const CALLBACK_THREW = {}
SYNC_PROMISE_SUCCESS.isSync = true
SYNC_PROMISE_FAIL.isSync = true

var log = []
export function addWriteMethods(LMDBStore, { env, fixedBuffer, resetReadTxn, useWritemap, eventTurnBatching, txnStartThreshold, batchStartThreshold, commitDelay }) {
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
	commitDelay = commitDelay || 0
	eventTurnBatching = eventTurnBatching === false ? false : true
	var enqueuedCommit
	var afterCommitCallbacks = []
	var beforeCommitCallbacks = []
	var enqueuedEventTurnBatch
	var batchDepth = 0
	var writeBatchStart, outstandingBatchCount
	txnStartThreshold = txnStartThreshold || 5
	batchStartThreshold = batchStartThreshold || 1000

	allocateInstructionBuffer()
	dynamicBytes.uint32[0] = TXN_DELIMITER | TXN_COMMITTED
	var txnResolution, lastQueuedResolution, nextResolution = { uint32: dynamicBytes.uint32, flagPosition: 0, }
	var uncommittedResolution = { next: nextResolution }
	var unwrittenResolution = nextResolution
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
			if (eventTurnBatching && !enqueuedEventTurnBatch && batchDepth == 0) {
				enqueuedEventTurnBatch = setImmediate(() => {
					try {
						for (let i = 0, l = beforeCommitCallbacks.length; i < l; i++) {
							beforeCommitCallbacks[i]()
						}
					} catch(error) {
						console.error(error)
					}
					enqueuedEventTurnBatch = null
					finishBatch()
					batchDepth--
					if (writeBatchStart)
						writeBatchStart() // TODO: When we support delay start of batch, optionally don't delay this
				})
				commitPromise = null // reset the commit promise, can't know if it is really a new transaction prior to finishWrite being called
				writeBatchStart = writeInstructions(1, store)
				outstandingBatchCount = 0
				batchDepth++
			}
			targetBytes = dynamicBytes
			position = targetBytes.position
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
				let start = valueBuffer.start
				let size
				if (start > -1) { // if we have buffers with start/end position
					size = valueBuffer.end - start // size
					valueBuffer.size = size
					// record pointer to value buffer
					float64[position] = (valueBuffer.address ||
						(valueBuffer.address = getAddress(valueBuffer.buffer) + valueBuffer.byteOffset)) + start
				} else {
					size = valueBuffer.length
					let valueArrayBuffer = valueBuffer.buffer
					// record pointer to value buffer
					float64[position] = (valueArrayBuffer.address ||
						(valueArrayBuffer.address = getAddress(valueArrayBuffer))) + valueBuffer.byteOffset
				}
				uint32[(position++ << 1) - 1] = size
				if (store.compression && size >= store.compression.threshold) {
					flags |= 0x100000;
					float64[position] = store.compression.address
					if (!writeTxn)
						env.compress(targetBytes.address + (position << 3))
					position++
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
			env.write(targetBytes.address)
			return () => (uint32[0] & FAILED_CONDITION) ? SYNC_PROMISE_FAIL : SYNC_PROMISE_SUCCESS
		}
		uint32[position << 1] = 0 // clear out the next slot
		let nextUint32
		if (position > 0x1e00) { // 61440 bytes
			// make new buffer and make pointer to it
			let lastBuffer = targetBytes
			let lastPosition = position
			let lastFloat64 = targetBytes.float64
			let lastUint32 = targetBytes.uint32
			targetBytes = allocateInstructionBuffer()
			position = targetBytes.position
			lastFloat64[lastPosition + 1] = targetBytes.address + position
			lastUint32[lastPosition << 1] = 3 // pointer instruction
			//console.log('pointer from ', (lastFloat64.buffer.address + (lastPosition << 3)).toString(16), 'to', (targetBytes.buffer.address + position).toString(16), 'flag position', (uint32.buffer.address + (flagPosition << 2)).toString(16))
			nextUint32 = targetBytes.uint32
		} else
			nextUint32 = uint32
		let newResolution = store.cache ?
		{
			uint32: nextUint32,
			flagPosition: position << 1,
			flag: 0, // TODO: eventually eliminate this, as we can probably signify success by zeroing the flagPosition
			valueBuffer,
			next: null,
			key,
			store,
			valueSize: 0,
		} :
		{
			uint32: nextUint32,
			flagPosition: position << 1,
			flag: 0, // TODO: eventually eliminate this, as we can probably signify success by zeroing the flagPosition
			valueBuffer,
			next: null,
		}
		let resolution = nextResolution
		resolution.next = newResolution
		nextResolution = newResolution
		let writtenBatchDepth = batchDepth

		return () => {
			if (writtenBatchDepth) {
				// if we are in a batch, the transaction can't close, so we do the faster,
				// but non-deterministic updates, knowing that the write thread can
				// just poll for the status change if we miss a status update
				writeStatus = uint32[flagPosition]
				uint32[flagPosition] = flags
				if (writeBatchStart && !writeStatus) {
					outstandingBatchCount++
					if (outstandingBatchCount > batchStartThreshold) {
						outstandingBatchCount = 0
						writeBatchStart()
						writeBatchStart = null
					}
				}
			} else // otherwise the transaction could end at any time and we need to know the
				// deterministically if it is ending, so we can reset the commit promise
				// so we use the slower atomic operation
				writeStatus = Atomics.or(uint32, flagPosition, flags)
	
			outstandingWriteCount++
			if (writeStatus & TXN_DELIMITER) {
				commitPromise = null
				queueCommitResolution(resolution)
				if (!startAddress)
					startAddress = targetBytes.address + (flagPosition << 2)
			}
			if (writeStatus & WAITING_OPERATION) { // write thread is waiting
				//console.log('resume batch thread', uint32.buffer.address + (flagPosition << 2))
				env.startWriting(0)
			}
			if (outstandingWriteCount > BACKPRESSURE_THRESHOLD) {
				console.log('backpressure')
				if (!backpressureArray)
					backpressureArray = new Int8Array(new SharedArrayBuffer(4), 0, 1)
				Atomics.wait(backpressureArray, 0, 0, 1)
			}
			if (startAddress) {
				if (!enqueuedCommit && txnStartThreshold) {
					enqueuedCommit = commitDelay == 0 ? setImmediate(startWriting) : setTimeout(startWriting, commitDelay)
				} else if (outstandingWriteCount > txnStartThreshold)
					startWriting()
			}

			if ((outstandingWriteCount & 7) === 0)
				resolveWrites()
			
			if (store.cache) {
				resolution.key = key
				resolution.store = store
				resolution.valueSize = valueBuffer ? valueBuffer.length : 0
			}
			resolution.valueBuffer = valueBuffer
			lastQueuedResolution = resolution
				
			if (ifVersion === undefined) {
				if (writtenBatchDepth > 1)
					return SYNC_PROMISE_SUCCESS // or return undefined?
				if (!commitPromise) {
					commitPromise = new Promise((resolve, reject) => {
						resolution.resolve = resolve
						resolution.reject = reject
					})
				}
				return commitPromise
			}
			return new Promise((resolve, reject) => {
				resolution.resolve = resolve
				resolution.reject = reject
			})
		}
	}
	function startWriting() {
		//console.log('start address ' + startAddress.toString(16), store.name)
		if (enqueuedCommit) {
			clearImmediate(enqueuedCommit)
			enqueuedCommit = null
		}
		env.startWriting(startAddress, (status) => {
			//console.log('finished batch', store.name)
			if (dynamicBytes.uint32[dynamicBytes.position << 1] & TXN_DELIMITER)
				queueCommitResolution(nextResolution)

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

	function queueCommitResolution(resolution) {
		if (!resolution.isTxn) {
			resolution.isTxn = true
			if (txnResolution) {
				txnResolution.nextTxn = resolution
				outstandingWriteCount = 0
			}
			else
				txnResolution = resolution
		}
	}
	function resolveWrites(async) {
		// clean up finished instructions
		let instructionStatus
		while ((instructionStatus = unwrittenResolution.uint32[unwrittenResolution.flagPosition])
				& 0x10000000) {
			//console.log('instructionStatus: ' + instructionStatus.toString(16))
			if (unwrittenResolution.callbacks) {
				nextTxnCallbacks.push(unwrittenResolution.callbacks)
				unwrittenResolution.callbacks = null
			}
			if (!unwrittenResolution.isTxn)
				unwrittenResolution.uint32 = null
			unwrittenResolution.valueBuffer = null
			unwrittenResolution.flag = instructionStatus
			outstandingWriteCount--
			unwrittenResolution = unwrittenResolution.next
		}
		while (txnResolution &&
			(instructionStatus = txnResolution.uint32[txnResolution.flagPosition] & 0xc0000000)) {
			if (instructionStatus & 0x80000000)
				rejectCommit()
			else if (instructionStatus & TXN_COMMITTED)
				resolveCommit(async)
		}
	}

	function resolveCommit(async) {
		afterCommit()
		if (async)
			resetReadTxn()
		else
			queueMicrotask(resetReadTxn) // TODO: only do this if there are actually committed writes?
		do {
			if (uncommittedResolution.resolve) {
				let flag = uncommittedResolution.flag
				if (flag < 0)
					uncommittedResolution.reject(new Error("Error occurred in write"))
				else if (flag & FAILED_CONDITION) {
					uncommittedResolution.resolve(false)
				} else
					uncommittedResolution.resolve(true)
			}
		} while((uncommittedResolution = uncommittedResolution.next) && uncommittedResolution != txnResolution)
		txnResolution = txnResolution.nextTxn
	}
	var commitRejectPromise
	function rejectCommit() {
		afterCommit()
		if (!commitRejectPromise) {
			let rejectFunction
			commitRejectPromise = new Promise((resolve, reject) => rejectFunction = reject)
			commitRejectPromise.reject = rejectFunction
		}
		do {
			let flag = uncommittedResolution.flag & 0xf
			let error = new Error("Commit failed (see commitError for details)")
			error.commitError = commitRejectPromise
			uncommittedResolution.reject(error)
		} while(uncommittedResolution = uncommittedResolution.next && uncommittedResolution != txnResolution)
		txnResolution = txnResolution.nextTxn
	}
	function atomicStatus(uint32, flagPosition, newStatus) {
		if (batchDepth) {
			// if we are in a batch, the transaction can't close, so we do the faster,
			// but non-deterministic updates, knowing that the write thread can
			// just poll for the status change if we miss a status update
			let writeStatus = uint32[flagPosition]
			uint32[flagPosition] = newStatus
			return writeStatus
		} else // otherwise the transaction could end at any time and we need to know the
			// deterministically if it is ending, so we can reset the commit promise
			// so we use the slower atomic operation
			return Atomics.or(uint32, flagPosition, newStatus)
	}
	function afterCommit() {
		for (let i = 0, l = afterCommitCallbacks.length; i < l; i++) {
			afterCommitCallbacks[i]({ next: uncommittedResolution, last: unwrittenResolution})
		}
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
		//console.log('async callback resume write trhead')
		lastQueuedTxnCallbacks = null
		return env.commitTxn()
		function txnError(error, i) {
			(txnCallbacks.errors || (txnCallbacks.errors = []))[i] = error
			txnCallbacks[i] = CALLBACK_THREW
		}
	}
	function finishBatch() {
		dynamicBytes.uint32[(dynamicBytes.position + 1) << 1] = 0 // clear out the next slot
		let writeStatus = atomicStatus(dynamicBytes.uint32, (dynamicBytes.position++) << 1, 2) // atomically write the end block
		nextResolution.flagPosition += 2
		if (writeStatus & WAITING_OPERATION) {
			env.startWriting(0)
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
			let finishStartWrite = writeInstructions(typeof key === 'undefined' ? 1 : 4, this, key, undefined, undefined, version)
			let promise
			batchDepth += 2
			if (batchDepth > 2)
				promise = finishStartWrite()
			else {
				writeBatchStart = () => {
					promise = finishStartWrite()
				}
				outstandingBatchCount = 0
			}
			//console.warn('wrote start of ifVersion', this.path)
			try {
				if (typeof callback === 'function') {
					callback()
				} else {
					for (let i = 0, l = callback.length; i < l; i++) {
						let operation = callback[i]
						this[operation.type](operation.key, operation.value)
					}
				}
			} finally {
				//console.warn('writing end of ifVersion', this.path, (dynamicBytes.buffer.address + ((dynamicBytes.position + 1) << 3)).toString(16))
				if (!promise) {
					finishBatch()
					batchDepth -= 2
					promise = finishStartWrite() // finish write once all the operations have been written (and it hasn't been written prematurely)
					writeBatchStart = null
				} else {
					batchDepth -= 2
					finishBatch()
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
			let txnIndex
			let txnCallbacks
			if (!lastQueuedResolution || !lastQueuedResolution.callbacks) {
				txnCallbacks = [asChild ? { callback, asChild } : callback]
				txnCallbacks.results = writeInstructions(8 | (this.strictAsyncOrder ? 0x100000 : 0), this)()
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
		},
		on(event, callback) {
			if (event == 'beforecommit') {
				eventTurnBatching = true
				beforeCommitCallbacks.push(callback)
			} else if (event == 'aftercommit')
				afterCommitCallbacks.push(callback)
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
