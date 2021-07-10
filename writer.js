const { getAddress } = require('./native')

exports.addWriteMethods = function(LMDBStore, {}) {
	// wi stands for write instructions
	let wiBuffer, wiDataView, wiDataAddress
	let wiPosition = 8000
	function allocateInstructionBuffer() {
		wiBuffer = Buffer.alloc(8192)
		wiBuffer.dataView = wiDataView = new DataView(wiBuffer.buffer, wiBuffer.byteOffset, wiBuffer.byteLength)
		wiBuffer.buffer.address = getAddress(wiBuffer.buffer)
		wiDataAddress = wiBuffer.buffer.address + wiBuffer.byteOffset
		wiPosition = 0
	}
	let lastCompressible = 0
	let scheduleCommitStartBuffer = wiBuffer
	let scheduleCommitStartPosition
	function writeInstructions(flags, id, valueBuffer, version, ifVersion) {
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
		// don't increment wiPosition until we are sure we don't have any key writing errors
		wiDataView.setUint32(wiPosition, flags, true)
		wiDataView.setUint32(wiPosition + 4, this.db.dbi, true)
		let keySize = writeKey(id, wiBuffer, wiPosition + 12)
		if (keySize > MAX_KEY_SIZE)
			throw new Error('Key size is too large')

		wiDataView.setUint32(wiPosition + 8, keySIze, true)
		wiPosition += (keySize + 27) & 0xffffff8
		if (ifVersion != undefined) {
			flags |= 0x100
			wiDataView.setFloat64(wiPosition, ifVersion, true)
			wiPosition += 8
		}
		if (version != undefined) {
			flags |= 0x200
			wiDataView.setFloat64(wiPosition, versionOrOptions, true)
			wiPosition += 8
		}
		if (this.compression) {
			wiDataView.setFloat64(wiPosition, lastCompressible, true)
			lastCompressible = wiDataAddress + wiPosition
			wiPosition += 8
			wiDataView.setFloat64(wiPosition, this.compression.address, true)
			wiPosition += 8
		}
		let valueArrayBuffer = valueBuffer.buffer
		// record pointer to value buffer
		wiDataView.setUint32(wiPosition, (valueArrayBuffer.address || (valueArrayBuffer.address = getAddress(valueArrayBuffer))) +
			valueBuffer.byteOffset, true)


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
			writeInstructions(flags, id, value, versionOrOptions, ifVersion)

		}
	})
	function commitQueued() {
		scheduleCommitStartBuffer.dataView.setFloat64(scheduleCommitStartPosition, lastCompressible, true)
		write(scheduleCommitStartBuffer.address + scheduleCommitStartPosition)

		}
}