import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { fileURLToPath } from 'url';
import { dirname, default as path } from 'path';
import EventEmitter from 'events';
import { setExternals, setNativeFunctions, Dbi } from './external.js';
import { arch, tmpdir, platform } from 'os';
import fs from 'fs';
import { Encoder as MsgpackrEncoder } from 'msgpackr';
import { WeakLRUCache } from 'weak-lru-cache';
import * as orderedBinary from 'ordered-binary';

orderedBinary.enableNullTermination();

let dirName = dirname(fileURLToPath(import.meta.url)).replace(/dist$/, '');

let nativeAddon = require('node-gyp-build')(dirName);

if (process.versions.v8.includes('node') && parseFloat(process.versions.v8) == parseFloat(nativeAddon.version.v8Major + '.' + nativeAddon.version.v8Minor)) {
	console.log('v8 enabled')
	let v8Funcs = {}
	nativeAddon.enableDirectV8(v8Funcs);
	Object.assign(nativeAddon, v8Funcs);
}
setNativeFunctions(nativeAddon);
setExternals({
	require, arch, fs, tmpdir, path, MsgpackrEncoder, WeakLRUCache, orderedBinary,
	EventEmitter, os: platform(), onExit(callback) {
		if (process.getMaxListeners() < process.listenerCount('exit') + 8)
			process.setMaxListeners(process.listenerCount('exit') + 8);
		process.on('exit', callback);
	},
});
export { toBufferKey as keyValueToBuffer, compareKeys, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary';
export { ABORT, IF_EXISTS, asBinary } from './write.js';
export { levelup } from './level.js';
export { clearKeptObjects } from './external.js';
export { open, getLastVersion, getLastEntrySize, setLastVersion, allDbs } from './open.js';
import { toBufferKey as keyValueToBuffer, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary';
import { open, getLastVersion } from './open.js';
export default {
	open, getLastVersion, compareKey, keyValueToBuffer, bufferToKeyValue, path, EventEmitter
};
