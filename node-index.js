import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { setNativeFunctions } from './native.js';
import fs from 'fs';
import { arch } from 'os';
let nativeFunctions, dirName = dirname(fileURLToPath(import.meta.url)).replace(/dist$/, '');
try {
	console.log(dirName);
	nativeFunctions = require('node-gyp-build')(dirName);
	if (process.versions.modules == 93)
		require('v8').setFlagsFromString('--turbo-fast-api-calls');
} catch(error) {
	if (process.versions.modules == 93) {
		// use this abi version as the backup version without turbo-fast-api-calls enabled
		Object.defineProperty(process.versions, 'modules', { value: '92' });
		try {
			nativeFunctions = require('node-gyp-build')(dirName);
		} catch(secondError) {
			throw error;
		} finally {
			Object.defineProperty(process.versions, 'modules', { value: '93' });
		}
	} else
		throw error;
}
nativeFunctions.require = require;
nativeFunctions.arch = arch;
nativeFunctions.fs = fs;
setNativeFunctions(nativeFunctions);
export { toBufferKey as keyValueToBuffer, compareKeys, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary/index.js';
export { ABORT, asBinary } from './write.js';
export { levelup } from './level.js';
export { open, getLastVersion, getLastEntrySize, setLastVersion, allDbs } from './index.js';
import { toBufferKey as keyValueToBuffer, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary/index.js';
import { open, getLastVersion } from './index.js';
export default {
	open, getLastVersion, compareKey, keyValueToBuffer, bufferToKeyValue
};