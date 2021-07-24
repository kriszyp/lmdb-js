const { getAddress } = require('./native')
let backpressureArray

const MAX_KEY_SIZE = 1978
const PROCESSING = 0x20000000
const BACKPRESSURE_THRESHOLD = 5000000
const TXN_DELIMITER = 0x80000000
exports.addWriteMethods = function(LMDBStore, { env, resetReadTxn }) {
	let unwrittenResolution, lastQueuedResolution, uncommittedResolution 
	// wi stands for write instructions
	let wiBytes, wiDataAddress, uint32Wi, float64Wi
	let wiPosition // write instruction position in 64-bit word increments
	function allocateInstructionBuffer() {
		wiBytes = Buffer.alloc(8192)
		uint32Wi = wiBytes.uint32Wi = new Uint32Array(wiBytes.buffer, 0, 2048)
		float64Wi = wiBytes.float64Wi = new Float64Array(wiBytes.buffer, 0, 1024)
		wiBytes.buffer.address = getAddress(wiBytes.buffer)
		wiDataAddress = wiBytes.buffer.address + wiBytes.byteOffset
		wiPosition = 0
	}
	let lastCompressibleFloat64 = new Float64Array(1)
	let lastCompressiblePosition = 0
	let outstandingWriteCount = 0
	allocateInstructionBuffer()
	uint32Wi[0] = TXN_DELIMITER
	function writeInstructions(flags, store, id, valueBuffer, version, ifVersion) {
		let writeStatus
		if (wiPosition > 750) { // 6000 bytes
			// make new buffer and make pointer to it
			let lastBuffer = wiBytes
			let lastPosition = wiPosition
			let lastFloat64 = float64Wi
			let lastUint32 = uint32Wi
			allocateInstructionBuffer()
			lastFloat64[lastPosition + 1] = wiDataAddress
			writeStatus = Atomics.or(lastUint32, lastPosition << 1, 15) // pointer instruction
		}
		let flagPosition = wiPosition << 1 // flagPosition is the 32-bit word starting position

		// don't increment wiPosition until we are sure we don't have any key writing errors
		uint32Wi[flagPosition + 1] = store.db.dbi
		let keyStartPosition = (wiPosition << 3) + 12
		let endPosition = store.writeKey(id, wiBytes, keyStartPosition)
		let keySize = endPosition - keyStartPosition
		if (keySize > MAX_KEY_SIZE)
			throw new Error('Key size is too large')

		uint32Wi[flagPosition + 2] = keySize
		wiPosition = (endPosition + 15) >> 3
		uint32Wi[(wiPosition << 1) - 1] = valueBuffer.length
		let valueArrayBuffer = valueBuffer.buffer
		// record pointer to value buffer
		float64Wi[wiPosition++] = (valueArrayBuffer.address || (valueArrayBuffer.address = getAddress(valueArrayBuffer))) + valueBuffer.byteOffset
		let nextCompressible, compressionStatus
		if (this.compression) {
			nextCompressible = wiDataAddress + (wiPosition << 3)
			compressionStatus = Atomics.exchange(lastCompressibleFloat64, lastCompressiblePosition, nextCompressible)
			float64Wi[wiPosition] = 0
			wiPosition++
			float64Wi[wiPosition++] = this.compression.address
		}
		if (ifVersion != undefined) {
			flags |= 0x100
			float64Wi[wiPosition++] = ifVersion
		}
		if (version != undefined) {
			flags |= 0x200
			float64Wi[wiPosition++] = version || 0
		}


		uint32Wi[wiPosition << 1] = 0 // clear out next so there is a stop signal
		writeStatus = Atomics.or(uint32Wi, flagPosition, flags) || writeStatus // write flags at the end so the writer never processes mid-stream, and do so with an atomic exchanges
		outstandingWriteCount++
		if (writeStatus) {
			let startAddress = wiBytes.buffer.address + (flagPosition << 2)
			function startWriting() {
				env.startWriting(startAddress, nextCompressible || 0, (status) => {
					if (status === true) {
						// user callback?
						console.log('user callback')
					} if (status) {
						console.error(status)
					} else {
						resolveWrites()
					}
				})
			}
			if (true || commitDelay == IMMEDIATE)
				startWriting()
			else
				setImmediate(startWriting)
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
				uint32Wi,
				flag: flagPosition,
				resolve,
				reject,
				valueBuffer,
				nextResolution: null,
			}
			if (unwrittenResolution)
				lastQueuedResolution.nextResolution = newResolution
			else
				unwrittenResolution = uncommittedResolution = newResolution
			lastQueuedResolution = newResolution
		})
	}
	function resolveWrites() {
		// clean up finished instructions
		let instructionStatus
		while (unwrittenResolution && (instructionStatus = unwrittenResolution.uint32Wi[unwrittenResolution.flag]) & 0x40000000) {
			if (instructionStatus & 0x80000000) {
				instructionStatus = instructionStatus & 0x7fffffff
				resolveCommit()
			}
			outstandingWriteCount--
			unwrittenResolution.flag = instructionStatus
			unwrittenResolution.valueBuffer = null
			unwrittenResolution.uint32Wi = null
			unwrittenResolution = unwrittenResolution.nextResolution
		}
		if (!unwrittenResolution) {
			if (uint32Wi[wiPosition << 1] & 0x80000000) {
				resolveCommit()
			}
			return
		}
	}
	function resolveCommit() {
		queueMicrotask(resetReadTxn) // TODO: only do this if there are actually committed writes, and do this synchronously if we are running in the async callback
		while(uncommittedResolution != unwrittenResolution && uncommittedResolution) {
			let flag = uncommittedResolution.flag
			if (flag == 0x40000000)
				uncommittedResolution.resolve(true)
			else if (flag == 0x40000001)
				uncommittedResolution.resolve(false)
			else
				uncommittedResolution.reject(new Error("Error occurred in write"))
			uncommittedResolution = uncommittedResolution.nextResolution
		}
	}
	Object.assign(LMDBStore.prototype, {
		put(id, value, versionOrOptions, ifVersion) {
			let flags = 2
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
			if (this.encoder) {
				//if (!(value instanceof Uint8Array)) TODO: in a future version, directly store buffers that are provided
				value = this.encoder.encode(value)
			} else if (typeof value == 'string') {
				value = Buffer.from(value) // TODO: Would be nice to write strings inline in the instructions
			} else if (!(value instanceof Uint8Array))
				throw new Error('Invalid value to put in database ' + value + ' (' + (typeof value) +'), consider using encoder')

			return writeInstructions(flags, this, id, value, this.useVersions ? versionOrOptions || 0 : undefined, ifVersion)
		}
	})
}
