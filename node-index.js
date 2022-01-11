import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { fileURLToPath } from 'url';
import { dirname, default as path } from 'path';
import EventEmitter from 'events';
import { setExternals, setNativeFunctions } from './external.js';
import { arch } from 'os';
import fs from 'fs';
import { Encoder as MsgpackrEncoder } from 'msgpackr';
import { WeakLRUCache } from 'weak-lru-cache';
import * as orderedBinary from 'ordered-binary';
orderedBinary.enableNullTermination();

let nativeFunctions, dirName = dirname(fileURLToPath(import.meta.url)).replace(/dist$/, '');
try {
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

setNativeFunctions(nativeFunctions);
setExternals({
	require, arch, fs, path, MsgpackrEncoder, WeakLRUCache, orderedBinary, EventEmitter
});
export { toBufferKey as keyValueToBuffer, compareKeys, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary';
export { ABORT, IF_EXISTS, asBinary } from './write.js';
export { levelup } from './level.js';
export { open, getLastVersion, getLastEntrySize, setLastVersion, allDbs } from './open.js';
import { toBufferKey as keyValueToBuffer, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary';
import { open, getLastVersion } from './open.js';
export default {
	open, getLastVersion, compareKey, keyValueToBuffer, bufferToKeyValue, path, EventEmitter
};
