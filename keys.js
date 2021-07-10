const { getAddress } = require('./native')
const keyBuffer = Buffer.allocUnsafeSlow(2048)
const keyBufferView = new DataView(keyBuffer.buffer, 0, 2048) // max key size is actually 1978

const writeUint32Key = (key, target, start) => {
	(target.dataView || (target.dataView = new DataView(target.buffer, 0, target.length))).setUint32(start, key, true)
	return start + 4
}
const readUint32Key = (target, start) => {
	return (target.dataView || (target.dataView = new DataView(target.buffer, 0, target.length))).getUint32(start, true)
}
const writeBufferKey = (key, target, start) => {
	if (key.length > 1978)
		throw new Error('Key buffer is too long')
	target.set(key, start)
	return key.length + start
}
const readBufferKey = (target, start, end) => {
	return Uint8ArraySlice.call(target, start, end)
}

exports.applyKeyHandling = function(store) {
 	if (store.encoding == 'ordered-binary') {
		store.encoder = store.decoder = {
			encode(value) {
				if (savePosition > 6200)
					allocateSaveBuffer()
				let start = savePosition
				savePosition = writeKey(value, saveBuffer, start)
				let buffer = saveBuffer.subarray(start, savePosition)
				savePosition = (savePosition + 7) & 0xfffff8
				return buffer
			},
			decode(buffer, end) { return readKey(buffer, 0, end) },
			writeKey,
			readKey,
		}
	}
	if (store.keyIsUint32) {
		store.writeKey = writeUint32Key
		store.readKey = readUint32Key
	} else if (store.keyIsBuffer) {
		store.writeKey = writeBufferKey
		store.readKey = readBufferKey
	}	else {
		store.writeKey = writeKey
		store.readKey = readKey
	}
}

let saveBuffer, saveDataView, saveDataAddress
let savePosition = 8000
function allocateSaveBuffer() {
	saveBuffer = Buffer.alloc(8192)
	saveBuffer.dataView = saveDataView = new DataView(saveBuffer.buffer, saveBuffer.byteOffset, saveBuffer.byteLength)
	saveBuffer.buffer.address = getAddress(saveBuffer.buffer)
	saveDataAddress = saveBuffer.buffer.address + saveBuffer.byteOffset
	savePosition = 0

}
function saveKey(key, writeKey, saveTo) {
	if (savePosition > 6200) {
		allocateSaveBuffer()
	}
	let start = savePosition
	savePosition = writeKey(key, saveBuffer, start + 4)
	saveDataView.setUint32(start, savePosition - start - 4, true)
	saveTo.saveBuffer = saveBuffer
	savePosition = (savePosition + 7) & 0xfffff8
	return start + saveDataAddress
}
exports.saveKey = saveKey