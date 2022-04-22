import { dirname, default as pathModule } from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

export let Env, Txn, Dbi, Compression, Cursor, getAddress, createBufferForAddress, clearKeptObjects, setGlobalBuffer,
	require, arch, fs, os, onExit, tmpdir, lmdbError, path, EventEmitter, orderedBinary, MsgpackrEncoder, WeakLRUCache, setEnvMap, getEnvMap, getByBinary, detachBuffer, write, position, iterate, native, v8AccelerationEnabled = false;

require = createRequire(import.meta.url);
path = pathModule;

let dirName = dirname(fileURLToPath(import.meta.url)).replace(/dist$/, '');

let nativeAddon = require('node-gyp-build-optional-packages')(dirName);

let [ majorVersion, minorVersion ] = process.versions.node.split('.')
if (process.versions.v8.includes('node') && +majorVersion == nativeAddon.version.nodeCompiledVersion) {
	let v8Funcs = {};
	let fastApiCalls = (majorVersion == 17 || majorVersion == 18 || majorVersion == 16 && minorVersion > 6) && !process.env.DISABLE_TURBO_CALLS;
	if (fastApiCalls)
		require('v8').setFlagsFromString('--turbo-fast-api-calls')
	nativeAddon.enableDirectV8(v8Funcs, fastApiCalls);
	Object.assign(nativeAddon, v8Funcs);
	v8AccelerationEnabled = true;
} else if (majorVersion == 14) {
	// node v14 only has ABI compatibility with node v16 for zero-arg clearKeptObjects
	let v8Funcs = {};
	nativeAddon.enableDirectV8(v8Funcs, false);
	nativeAddon.clearKeptObjects = v8Funcs.clearKeptObjects;
}
setNativeFunctions(nativeAddon);
	
export function setNativeFunctions(externals) {
	native = externals;
	Env = externals.Env;
	Txn = externals.Txn;
	Dbi = externals.Dbi;
	Compression = externals.Compression;
	getAddress = externals.getAddress;
	createBufferForAddress = externals.createBufferForAddress;
	clearKeptObjects = externals.clearKeptObjects || function() {};
	Cursor = externals.Cursor;
	lmdbError = externals.lmdbError;
	if (externals.tmpdir)
        tmpdir = externals.tmpdir
}
export function setExternals(externals) {
	arch = externals.arch;
	fs = externals.fs;
	EventEmitter = externals.EventEmitter;
	orderedBinary = externals.orderedBinary;
	MsgpackrEncoder = externals.MsgpackrEncoder;
	WeakLRUCache = externals.WeakLRUCache;
	tmpdir = externals.tmpdir;
   os = externals.os;
	onExit = externals.onExit;
}
