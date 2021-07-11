const { ArrayLikeIterable } = require('./util/ArrayLikeIterable')
const { saveKey } = require('./keys')
const ITERATOR_DONE = { done: true, value: undefined }

exports.addQueryMethods = function(LMDBStore, {
	getReadTxn, getWriteTxn, Cursor, keyBuffer, keyBufferView, getLastVersion
}) {
	let renewId = 1
	LMDBStore.onReadReset = () => renewId++
	Object.assign(LMDBStore.prototype, {
		getValues(key, options) {
			let defaultOptions = {
				key,
				valuesForKey: true
			}
			if (options && options.snapshot === false)
				throw new Error('Can not disable snapshots for getValues')
			return this.getRange(options ? Object.assign(defaultOptions, options) : defaultOptions)
		},
		getKeys(options) {
			if (!options)
				options = {}
			options.values = false
			return this.getRange(options)
		},
		getCount(options) {
			if (!options)
				options = {}
			options.onlyCount = true
			return this.getRange(options)[Symbol.iterator]()
		},
		getKeysCount(options) {
			if (!options)
				options = {}
			options.onlyCount = true
			options.values = false
			return this.getRange(options)[Symbol.iterator]()
		},
		getValuesCount(key, options) {
			if (!options)
				options = {}
			options.key = key
			options.valuesForKey = true
			options.onlyCount = true
			return this.getRange(options)[Symbol.iterator]()
		},
		getRange(options) {
			let iterable = new ArrayLikeIterable()
			if (!options)
				options = {}
			let includeValues = options.values !== false
			let includeVersions = options.versions
			let valuesForKey = options.valuesForKey
			let limit = options.limit
			let db = this.db
			let snapshot = options.snapshot
			iterable[Symbol.iterator] = () => {
				let currentKey = valuesForKey ? options.key : options.start
				const reverse = options.reverse
				let count = 0
				let cursor, cursorRenewId
				let txn
				let flags = (includeValues ? 0x100 : 0) | (reverse ? 0x400 : 0) | (valuesForKey ? 0x800 : 0)
				function resetCursor() {
					try {
						if (cursor)
							finishCursor()
						let writeTxn = getWriteTxn()
						txn = writeTxn || getReadTxn()
						cursor = !writeTxn && db.availableCursor
						if (cursor) {
							db.availableCursor = null
							if (db.cursorTxn != txn)
								cursor.renew(txn)
							else// if (db.currentRenewId != renewId)
								flags |= 0x2000
						} else {
							cursor = new Cursor(txn, db)
						}
						txn.cursorCount = (txn.cursorCount || 0) + 1 // track transaction so we always use the same one
						if (snapshot === false) {
							cursorRenewId = renewId // use shared read transaction
							txn.renewingCursorCount = (txn.renewingCursorCount || 0) + 1 // need to know how many are renewing cursors
						}
					} catch(error) {
						if (cursor) {
							try {
								cursor.close()
							} catch(error) { }
						}
						return handleError(error, this, txn, resetCursor)
					}
				}
				resetCursor()
				let store = this
				if (options.onlyCount) {
					flags |= 0x1000
					let count = position(options.offset)
					finishCursor()
					return count
				}
				function position(offset) {
					let keySize = store.writeKey(currentKey, keyBuffer, 0)
					let endAddress
					if (valuesForKey) {
						if (options.start === undefined && options.end === undefined)
							endAddress = 0
						else {
							let startAddress
							if (store.encoder.writeKey) {
								startAddress = BigInt(saveKey(options.start, store.encoder.writeKey, iterable))
								keyBufferView.setBigUint64(2000, startAddress, true)
								endAddress = saveKey(options.end, store.encoder.writeKey, iterable)
							} else {
								throw new Error('Only key-based encoding is supported for start/end values')
								let encoded = store.encoder.encode(options.start)
								let bufferAddress = encoded.buffer.address || (encoded.buffer.address = getAddress(encoded) - encoded.byteOffset)
								startAddress = bufferAddress + encoded.byteOffset
							}
						}
					} else
						endAddress = saveKey(options.end, store.writeKey, iterable)
					return cursor.position(flags, offset || 0, keySize, endAddress)
				}

				function finishCursor() {
					if (txn.isAborted)
						return
					if (cursorRenewId)
						txn.renewingCursorCount--
					if (--txn.cursorCount <= 0 && txn.onlyCursor) {
						cursor.close()
						txn.abort() // this is no longer main read txn, abort it now that we are done
						txn.isAborted = true
					} else {
						if (db.availableCursor || txn != getReadTxn())
							cursor.close()
						else { // try to reuse it
							db.availableCursor = cursor
							db.cursorTxn = txn
						}
					}
				}
				return {
					next() {
						let keySize
						if (cursorRenewId && cursorRenewId != renewId) {
							resetCursor()
							keySize = position(0)
						}
						if (count === 0) { // && includeValues) // on first entry, get current value if we need to
							keySize = position(options.offset)
						} else
							keySize = cursor.iterate()
						if (keySize === 0 ||
								(count++ >= limit)) {
							finishCursor()
							return ITERATOR_DONE
						}
						if (!valuesForKey || snapshot === false)
							currentKey = store.readKey(keyBuffer, 32, keySize + 32)
						if (includeValues) {
							let value
							lastSize = keyBufferView.getUint32(0, true)
							if (store.decoder) {
								value = store.decoder.decode(db.unsafeBuffer, lastSize)
							} else if (store.encoding == 'binary')
								value = Uint8ArraySlice.call(db.unsafeBuffer, 0, lastSize)
							else {
								value = store.db.unsafeBuffer.toString('utf8', 0, lastSize)
								if (store.encoding == 'json' && value)
									value = JSON.parse(value)
							}
							if (includeVersions)
								return {
									value: {
										key: currentKey,
										value,
										version: getLastVersion()
									}
								}
 							else if (valuesForKey)
								return {
									value
								}
							else
								return {
									value: {
										key: currentKey,
										value,
									}
								}
						} else if (includeVersions) {
							return {
								value: {
									key: currentKey,
									version: getLastVersion()
								}
							}
						} else {
							return {
								value: currentKey
							}
						}
					},
					return() {
						finishCursor()
						return ITERATOR_DONE
					},
					throw() {
						finishCursor()
						return ITERATOR_DONE
					}
				}
			}
			return iterable
		}

	})
}