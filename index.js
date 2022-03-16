import EventEmitter from 'events';
import { setExternals, setNativeFunctions, Dbi } from './external.js';
import { arch, tmpdir, platform } from 'os';
import fs from 'fs';
import { Encoder as MsgpackrEncoder } from 'msgpackr';
import { WeakLRUCache } from 'weak-lru-cache';
import * as orderedBinary from 'ordered-binary';

orderedBinary.enableNullTermination();
setExternals({
	arch, fs, tmpdir, MsgpackrEncoder, WeakLRUCache, orderedBinary,
	EventEmitter, os: platform(), onExit(callback) {
		if (process.getMaxListeners() < process.listenerCount('exit') + 8)
			process.setMaxListeners(process.listenerCount('exit') + 8);
		process.on('exit', callback);
	},
});
export { toBufferKey as keyValueToBuffer, compareKeys, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary';
export { ABORT, IF_EXISTS, asBinary } from './write.js';
export { levelup } from './level.js';
export { clearKeptObjects, v8AccelerationEnabled } from './external.js';
export { open, getLastVersion, getLastEntrySize, setLastVersion, allDbs } from './open.js';
import { toBufferKey as keyValueToBuffer, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary';
import { open, getLastVersion } from './open.js';
export const ABORTABLE = 1;
export const SYNCHRONOUS_COMMIT = 2;
export const NO_SYNC_FLUSH = 0x10000;
export default {
	open, getLastVersion, compareKey, keyValueToBuffer, bufferToKeyValue, EventEmitter
};
