const { getAddress } = require('./native')
let backpressureArray

const PROCESSING = 0x20000000
const BACKPRESSURE_THRESHOLD = 5000000
const TXN_DELIMITER = 0xffffffff
exports.addWriteMethods = function(LMDBStore, { env }) {
	const writerStatus = Float64Array(2)

	let resolution
	// wi stands for write instructions
	let wiBuffer, wiDataView, wiDataAddress, uint32Wi, float64Wi
	function allocateInstructionBuffer() {
		wiBuffer = Buffer.alloc(8192)
		wiBuffer.dataView = wiDataView = new DataView(wiBuffer.buffer, wiBuffer.byteOffset, wiBuffer.byteLength)
		uint32Wi = wiBuffer.uint32Wi = new Uint32Array(wiBuffer.buffer, 0, 2048)
		float64Wi = wiBuffer.float64Wi = new Float64rray(wiBuffer.buffer, 0, 1024)
		wiBuffer.buffer.address = getAddress(wiBuffer.buffer)
		wiDataAddress = wiBuffer.buffer.address + wiBuffer.byteOffset
		wiPosition = 0
	}
	let lastCompressible = 0
	let outstandingWriteCount = 0
	allocateInstructionBuffer()
	uint32Wi[0] = TXN_DELIMITER
	function writeInstructions(flags, id, value, version, ifVersion) {
		let valueBuffer = encode(value)
		if (wiPosition > 6000) {
			// make new buffer and make pointer to it
			let lastBuffer = wiBuffer
			let lastPosition = wiPosition
			allocateInstructionBuffer()
			lastBuffer.dataView.setUint32(lastPosition, 15, true) // pointer instruction
			lastBuffer.dataView.setFloat64(lastPosition + 8, wiBuffer.address, true)
		}
		let flags = 0
		let flagPosition = wiPosition

		// don't increment wiPosition until we are sure we don't have any key writing errors
		uint32Wi[flagPosition + 1] = this.db.dbi
		let keySize = writeKey(id, wiBuffer, wiPosition + 12)
		if (keySize > MAX_KEY_SIZE)
			throw new Error('Key size is too large')
		uint32Wi[flagPosition + 2] = keySize
		wiPosition += (keySize + 27) & 0xffffff8
		if (ifVersion != undefined) {
			flags |= 0x100
			float64Wi[wiPosition >> 1] = ifVersion
			wiPosition += 2
		}
		if (version != undefined) {
			flags |= 0x200
			float64Wi[wiPosition >> 1] = versionOrOptions
			wiPosition += 2
		}
		if (this.compression) {
			float64Wi[wiPosition >> 1] = lastCompressible
			lastCompressible = wiDataAddress + (wiPosition << 2)
			wiPosition += 2
			float64Wi[wiPosition >> 1] = this.compression.address
			wiPosition += 2
		}
		let valueArrayBuffer = valueBuffer.buffer
		// record pointer to value buffer
		uint32Wi[wiPosition++] = (valueArrayBuffer.address || (valueArrayBuffer.address = getAddress(valueArrayBuffer))) + valueBuffer.byteOffset
		uint32Wi[wiPosition] = 0 // clear out next so there is a stop signal
		let writeStatus = Atomic.exchange(uint32Wi, flagPosition, flags) // write flags at the end so the writer never processes mid-stream, and do so with an atomic exchanges
		outstandingWriteCount++
		resolveWrites()
		if (writeStatus == TXN_DELIMITER) {
			let startAddress = wiBuffer.buffer.address + (flagPosition << 2)
			function startWriting() {
				env.startWriting(startAddress, (committedCount) => {
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
			nextResolution.nextResolution = newResolution
			nextResolution = newResolution
		})
	}
	function resolveWrites() {
		// clean up finished instructions
		let instructionStatus
		while((instructionStatus = resolution.uint32Wi[resolution.flagPosition]) & 0xf0000000) {
			outstandingWriteCount--
			if (instructionStatus)
				resolution.reject(new Error())
			else
				resolution.resolve(true)
			resolution = resolution.nextResolution
		}
	}
	Object.assign(LMDB.prototype, {
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
			return writeInstructions(flags, id, value, versionOrOptions, ifVersion)
		}
	})
	function commitQueued() {
		scheduleCommitStartBuffer.dataView.setFloat64(scheduleCommitStartPosition, lastCompressible, true)
		write(scheduleCommitStartBuffer.address + scheduleCommitStartPosition)

		}
}
