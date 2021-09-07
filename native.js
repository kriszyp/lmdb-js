import { createRequire } from 'module';
const require = createRequire(import.meta.url)
import { fileURLToPath } from 'url'
import { dirname } from 'path'
let nativeMethods, dirName = dirname(fileURLToPath(import.meta.url)).replace(/dist$/, '')
try {
	console.log(dirName)
	nativeMethods = require('node-gyp-build')(dirName)
	if (process.versions.modules == 93)
		require('v8').setFlagsFromString('--turbo-fast-api-calls')
} catch(error) {
	if (process.versions.modules == 93) {
		// use this abi version as the backup version without turbo-fast-api-calls enabled
		Object.defineProperty(process.versions, 'modules', { value: '92' })
		try {
			nativeMethods = require('node-gyp-build')(dirName)
		} catch(secondError) {
			throw error
		} finally {
			Object.defineProperty(process.versions, 'modules', { value: '93' })
		}
	} else
		throw error
}
export const { Env, Cursor, Compression, getBufferForAddress, getAddress } = nativeMethods