import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { fileURLToPath } from 'url';
import { dirname, default as path } from 'path';
import EventEmitter from 'events';
import { setExternals, setNativeFunctions } from './external.js';
import { arch, tmpdir, platform } from 'os';
import fs from 'fs';
import { Encoder as MsgpackrEncoder } from 'msgpackr';
import { WeakLRUCache } from 'weak-lru-cache';
import * as orderedBinary from 'ordered-binary';
import { isMainThread } from 'worker_threads';
orderedBinary.enableNullTermination();

let dirName = dirname(fileURLToPath(import.meta.url)).replace(/dist$/, '');

setNativeFunctions(require('node-gyp-build')(dirName));
setExternals({
	require, arch, fs, tmpdir, path, MsgpackrEncoder, WeakLRUCache, orderedBinary,
	EventEmitter, os: platform(), onExit(callback) {
		if (process.getMaxListeners() < process.listenerCount('exit') + 8)
			process.setMaxListeners(process.listenerCount('exit') + 8);
		process.on('exit', callback);
	},
	isWorkerThread: !isMainThread,
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
