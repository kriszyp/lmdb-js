function upgrade(path, options, open) {
	let { open: legacyOpen } = require('lmdb')//require('lmdb-store-0-9')
	fs.renameSync(path, tempPath)
	let sourceRootDB = legacyOpen(path, options)
	let targetStore = open(path, options)
	let sourceTxn = sourceRootDB.env.beginTxn({ readOnly: true })
	let targetTxn = targetStore.transaction(() => {
		copyDB(sourceStore)
		function copyDB(sourceStore, targetStore) {
			cursor = new Cursor(sourceTxn, sourceStore.db)
			let currentKey = cursor.goToFirst()
			while(currentKey) {
				let value = cursor.getCurrentBinaryUnsafe()
				if (cursor.getCurrentIsDatabase()) {
					copyDB(sourceStore.open(value.toString()), targetStore.open(value.toString()))
				} else {
					targetStore.putSync(currentKey, value)
				}
				currentKey = cursor.goToNext()
			}
			cursor.close()
		}
	})
}