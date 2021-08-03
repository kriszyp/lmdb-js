const { getAddress } = require('./native')
const when  = require('./util/when')
var backpressureArray

const MAX_KEY_SIZE = 1978
const PROCESSING = 0x20000000
const BACKPRESSURE_THRESHOLD = 5000000
const TXN_DELIMITER = 0x40000000
const SYNC_PROMISE_RESULT = Promise.resolve(true)
const SYNC_PROMISE_FAIL = Promise.resolve(false)
const ABORT = {}
exports.ABORT = ABORT
SYNC_PROMISE_RESULT.isSync = true
SYNC_PROMISE_FAIL.isSync = true

var log = []
exports.addWriteMethods = function(LMDBStore, { env, fixedBuffer, resetReadTxn, useWritemap }) {
	var unwrittenResolution, lastQueuedResolution = {}, uncommittedResolution 
	//  stands for write instructions
	var dynamicBytes
	function allocateInstructionBuffer() {
		dynamicBytes = Buffer.allocUnsafeSlow(8192)
		dynamicBytes.uint32 = new Uint32Array(dynamicBytes.buffer, 0, 2048)
		dynamicBytes.float64 = new Float64Array(dynamicBytes.buffer, 0, 1024)
		dynamicBytes.buffer.address = getAddress(dynamicBytes.buffer)
		dynamicBytes.address = dynamicBytes.buffer.address + dynamicBytes.byteOffset
		dynamicBytes.position = 0
		return dynamicBytes
	}
	var lastCompressibleFloat64 = new Float64Array(1)
	var lastCompressiblePosition = 0
	var compressionCount = 0
	var outstandingWriteCount = 0
	var writeTxn = null
	var abortedNonChildTransactionWarn

	allocateInstructionBuffer()
	dynamicBytes.uint32[0] = TXN_DELIMITER
	function writeInstructions(flags, store, key, value, version, ifVersion) {
		let writeStatus, compressionStatus
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
			} else if (!(value instanceof Uint8Array))
				throw new Error('Invalid value to put in database ' + value + ' (' + (typeof value) +'), consider using encoder')
		}
		if (writeTxn) {
			targetBytes = fixedBuffer
			position = 0
		} else {
			targetBytes = dynamicBytes
			position = targetBytes.position
			if (position > 750) { // 6000 bytes
				// make new buffer and make pointer to it
				let lastBuffer = targetBytes
				let lastPosition = targetBytes.position
				let lastFloat64 = targetBytes.float64
				let lastUint32 = targetBytes.uint32
				targetBytes = allocateInstructionBuffer()
				position = targetBytes.position
				lastFloat64[lastPosition + 1] = targetBytes.buffer.address + position
				writeStatus = Atomics.or(lastUint32, lastPosition << 1, 3) // pointer instruction
			}
		}
		let uint32 = targetBytes.uint32, float64 = targetBytes.float64
		let flagPosition = position << 1 // flagPosition is the 32-bit word starting position

		// don't increment Position until we are sure we don't have any key writing errors
		uint32[flagPosition + 1] = store.db.dbi
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
			let nextCompressible
			if (this.compression) {
				flags |= 0x100000;
				nextCompressible = dataAddress + (Position << 3)
				compressionStatus = Atomics.exchange(lastCompressibleFloat64, lastCompressiblePosition, nextCompressible)
				float64[position] = 0
				position++
				float64[position++] = this.compression.address
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
		targetBytes.position = position
		//console.log('js write', (targetBytes.buffer.address + (flagPosition << 2)).toString(16), flags.toString(16))
		if (writeTxn) {
			uint32[0] = flags
			env.writeSync(targetBytes.buffer.address)
			return () => (uint32[0] & 1) ? SYNC_PROMISE_FAIL : SYNC_PROMISE_RESULT
		}
		uint32[position << 1] = 0 // clear out the next slot
		return (forceCompression) => {
			writeStatus = Atomics.or(uint32, flagPosition, flags) // write flags at the end so the writer never processes mid-stream, and do so th an atomic exchanges
			outstandingWriteCount++
			if (writeStatus) {
				if (writeStatus & 0x20000000) { // write thread is waiting
					env.continueBatch(0)
				} else {
					let startAddress = targetBytes.buffer.address + (flagPosition << 2)
					function startWriting() {
						env.startWriting(startAddress, compressionStatus ? nextCompressible : 0, (status) => {
							console.log('finished batch', status)
							resolveWrites(true)
							switch (status) {
								case 0: case 1:
								break;
								case 2:
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
					}
					if (true || commitDelay == IMMEDIATE)
						startWriting()
					else
						setImmediate(startWriting)
				}
			} else if (compressionStatus) {
				env.compress(nextCompressible)
			} else if (outstandingWriteCount > BACKPRESSURE_THRESHOLD) {
				if (!backpressureArray)
					backpressureArray = new Int8Array(new SharedArrayBuffer(4), 0, 1)
				Atomics.wait(backpressure, 0, 0, 1)
			}
			resolveWrites()
			return new Promise((resolve, reject) => {
				let newResolution = {
					uint32,
					flag: flagPosition,
					resolve,
					reject,
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
			})
		}
	}
	function resolveWrites(async) {
		// clean up finished instructions
		let instructionStatus
		while (unwrittenResolution && (instructionStatus = unwrittenResolution.uint32[unwrittenResolution.flag]) & 0x10000000) {
			if (instructionStatus & 0x40000000) {
				if (instructionStatus & 0x80000000)
					rejectCommit()
				else {
					instructionStatus = instructionStatus & 0x1000000f
					resolveCommit(async)
				}
			}
			outstandingWriteCount--
			log.push(['resolution', unwrittenResolution.flag, instructionStatus])
			unwrittenResolution.debuggingPosition = unwrittenResolution.flag
			unwrittenResolution.flag = instructionStatus
			unwrittenResolution.valueBuffer = null
			unwrittenResolution.uint32 = null
			unwrittenResolution = unwrittenResolution.nextResolution
		}
		if (!unwrittenResolution) {
			if ((instructionStatus = dynamicBytes.uint32[dynamicBytes.position << 1]) & 0x40000000) {
				if (instructionStatus & 0x80000000)
					rejectCommit()
				else
					resolveCommit(async)
			}
			return
		}
	}
	function resolveCommit(async) {
		if (async)
			resetReadTxn()
		else
			queueMicrotask(resetReadTxn) // TODO: only do this if there are actually committed writes?
		while (uncommittedResolution != unwrittenResolution && uncommittedResolution) {
			let flag = uncommittedResolution.flag
			log.push(['committed', uncommittedResolution.debuggingPosition, !!uncommittedResolution.nextResolution])
			if (flag == 0x10000000)
				uncommittedResolution.resolve(true)
			else if (flag == 0x10000001)
				uncommittedResolution.resolve(false)
			else
				uncommittedResolution.reject(new Error("Error occurred in write"))
			uncommittedResolution = uncommittedResolution.nextResolution
		}
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
	Object.assign(LMDBStore.prototype, {
		put(key, value, versionOrOptions, ifVersion) {
			let sync, flags = 10
			if (typeof versionOrOptions == 'object') {
				if (versionOrOptions.noOverwrite)
					flags |= 0x10
				if (versionOrOptions.noDupData)
					flags |= 0x20
				if (versionOrOptions.append)
					flags |= 0x20000
				if (versionsOrOptions.ifVersion != undefined)
					ifVersion = versionsOrOptions.ifVersion
				versionOrOptions = versionOrOptions.version
			}
			return writeInstructions(flags, this, key, value, this.useVersions ? versionOrOptions || 0 : undefined, ifVersion)()
		},
		remove(key, ifVersionOrValue) {
			let flags = 9
			let ifVersion, value
			if (ifVersionOrValue !== undefined) {
				if (this.useVersions)
					ifVersion = ifVersionOrValue
				else {
					flags = 11
					value = ifVersionOrValue
				}
			}
			return writeInstructions(flags, this, key, value, undefined, ifVersion)()
		},
		ifVersion(key, version, callback) {
			if (writeTxn) {

			}
			let finishWrite = writeInstructions(5, this, key, undefined, undefined, version)
			if (callback) {
				let promise = finishWrite() // commit to writing the whole block in the current transaction
				console.log('wrote start of ifVersion')
				try {
					callback()
				} catch(error) {
					// TODO: Restore state
					throw error
				}
				console.log('writing end of ifVersion', (dynamicBytes.buffer.address + ((dynamicBytes.position + 1) << 3)).toString(16))
				dynamicBytes.uint32[(dynamicBytes.position + 1) << 1] = 0 // no instruction yet for the next instruction
				writeStatus = Atomics.or(dynamicBytes.uint32, (dynamicBytes.position++) << 1, 2) // atomically write the end block
				if (writeStatus)
					env.continueBatch(0)
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
				return this.transactionSync(() => this.put(key, value, versionOrOptions, ifVersion) == SYNC_PROMISE_RESULT)
		},
		transactionSync(callback, abort) {
			if (writeTxn) {
				if (!useWritemap && !this.cache)
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
				txn = writeTxn = env.beginTxn()
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
						writeTxn = null
					}
				}, (error) => {
					writeTxn = null
					throw error
				})
			} catch(error) {
				writeTxn = null
				throw error
			}
		}
	})
}
