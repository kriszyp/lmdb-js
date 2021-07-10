try {
	Object.assign(exports, require('node-gyp-build')(__dirname))
	if (process.versions.modules == 93)
		v8.setFlagsFromString('--turbo-fast-api-calls')
} catch(error) {
	if (process.versions.modules == 93) {
		// use this abi version as the backup version without turbo-fast-api-calls enabled
		Object.defineProperty(process.versions, 'modules', { value: '92' })
		try {
			Object.assign(exports, require('node-gyp-build')(__dirname))
		} catch(secondError) {
			throw error
		} finally {
			Object.defineProperty(process.versions, 'modules', { value: '93' })
		}
	} else
		throw error
}
