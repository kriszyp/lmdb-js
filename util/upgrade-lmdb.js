const { renameSync, unlinkSync } = require('fs')
const { extname } = require('path')

exports.upgrade =  function(path, options, open) {
	let { open: legacyOpen, Cursor: legacyCursor } = require('lmdb-store-0.9')
	let filePath = extname(path) ? path : path + '/data.mdb'
	console.log('Upgrading', filePath, 'to LMDB 1.0 format')
	let tempPath = filePath.replace(/([^\\\/]+)$/, 'temp-$1')
	let maxDbs = options.maxDbs || 20
	let sourceStore = legacyOpen(path, { maxDbs, encoding: 'binary' })
	let targetStore = open(tempPath, { maxDbs, encoding: 'binary', mapSize: sourceStore.env.info().mapSize })
	let targetTxn = targetStore.transaction(() => {
		copyDB(sourceStore, targetStore)
		function copyDB(sourceStore, targetStore) {
			let sourceTxn = sourceStore.env.beginTxn({ readOnly: true })
			let sourceDb = sourceStore.db
			let cursor = new legacyCursor(sourceTxn, sourceDb)
			let currentKey = cursor.goToFirst()
			while(currentKey) {
				let size = cursor.getCurrentBinaryUnsafe()
				if (cursor.getCurrentIsDatabase()) {
					copyDB(sourceStore.openDB(currentKey, {}), targetStore.openDB(currentKey))
				} else {
					targetStore.putSync(currentKey, sourceDb.unsafeBuffer.slice(0, size))
				}
				currentKey = cursor.goToNext()
			}
			cursor.close()
			sourceTxn.abort()
		}
	})
	sourceStore.close()
	targetStore.close()
	unlinkSync(filePath)
	renameSync(tempPath, filePath)
	console.log('Finished upgrading', filePath)
}