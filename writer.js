const { getAddress } = require('./native')
let backpressureArray

const MAX_KEY_SIZE = 1978
const PROCESSING = 0x20000000
const BACKPRESSURE_THRESHOLD = 5000000
const TXN_DELIMITER = 0xffffffff
exports.addWriteMethods = function(LMDBStore, { env }) {
	let resolution
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
			writeStatus = Atomics.exchange(lastUint32, lastPosition << 1, 15) // pointer instruction
		}
		let flagPosition = wiPosition << 1 // flagPosition is the 32-bit word starting position

		// don't increment wiPosition until we are sure we don't have any key writing errors
		uint32Wi[flagPosition + 1] = store.db.dbi
		let keySize = store.writeKey(id, wiBytes, (wiPosition << 3) + 12)
		if (keySize > MAX_KEY_SIZE)
			throw new Error('Key size is too large')

		uint32Wi[flagPosition + 2] = keySize
		wiPosition += (keySize + 27) >> 3
		if (ifVersion != undefined) {
			flags |= 0x100
			float64Wi[wiPosition++] = ifVersion
		}
		if (version != undefined) {
			flags |= 0x200
			float64Wi[wiPosition++] = versionOrOptions
		}
		let nextCompressible, compressionStatus
		if (this.compression) {
			nextCompressible = wiDataAddress + (wiPosition << 3)
			compressionStatus = Atomics.exchange(lastCompressibleFloat64, lastCompressiblePosition, nextCompressible)
			float64Wi[wiPosition] = 0
			wiPosition++
			float64Wi[wiPosition++] = this.compression.address
		}
		let valueArrayBuffer = valueBuffer.buffer
		// record pointer to value buffer
		float64Wi[wiPosition++] = (valueArrayBuffer.address || (valueArrayBuffer.address = getAddress(valueArrayBuffer))) + valueBuffer.byteOffset
		uint32Wi[wiPosition << 1] = 0 // clear out next so there is a stop signal
		writeStatus = Atomics.exchange(uint32Wi, flagPosition, flags) || writeStatus // write flags at the end so the writer never processes mid-stream, and do so with an atomic exchanges
		outstandingWriteCount++
		resolveWrites()
		if (writeStatus == TXN_DELIMITER) {
			let startAddress = wiBytes.buffer.address + (flagPosition << 2)
			function startWriting() {
				env.startWriting(startAddress, nextCompressible || 0, (committedCount) => {
					console.log('finished a write')
					if (committedCount > 0) {
						resolveWrites()
					} else {
						// user callback?
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
		return new Promise((resolve, reject) => {
			let newResolution = {
				uint32Wi,
				flagPosition,
				resolve,
				reject,
				valueBuffer,
				nextResolution: null,
			}
			if (resolution)
				nextResolution.nextResolution = newResolution
			else
				resolution = newResolution
			
			nextResolution = newResolution
		})
	}
	function resolveWrites() {
		// clean up finished instructions
		let instructionStatus
		while(resolution && (instructionStatus = resolution.uint32Wi[resolution.flagPosition]) & 0xf0000000) {
			outstandingWriteCount--
			if (instructionStatus)
				resolution.reject(new Error())
			else
				resolution.resolve(true)
			resolution = resolution.nextResolution
		}
	}
	Object.assign(LMDBStore.prototype, {
		put(id, value, versionOrOptions, ifVersion) {
			let flags = 0
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

			return writeInstructions(flags, this, id, value, versionOrOptions, ifVersion)
		}
	})
	function commitQueued() {
		scheduleCommitStartBuffer.dataView.setFloat64(scheduleCommitStartPosition, lastCompressible, true)
		write(scheduleCommitStartBuffer.address + scheduleCommitStartPosition)

		}
}
