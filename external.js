export let Env, Compression, Cursor, getAddress, clearKeptObjects, setGlobalBuffer,
    require, arch, fs, lmdbError, path, EventEmitter, orderedBinary, MsgpackrEncoder, WeakLRUCache;
export function setNativeFunctions(externals) {
	Env = externals.Env;
	Compression = externals.Compression;
	getAddress = externals.getAddress;
    clearKeptObjects = externals.clearKeptObjects;
    setGlobalBuffer = externals.setGlobalBuffer;
    Cursor = externals.Cursor;
    lmdbError = externals.lmdbError;
}
export function setExternals(externals) {
    require = externals.require;
    arch = externals.arch;
    fs = externals.fs;
    path = externals.path;
    EventEmitter = externals.EventEmitter;
    orderedBinary = externals.orderedBinary;
    MsgpackrEncoder = externals.MsgpackrEncoder;
    WeakLRUCache = externals.WeakLRUCache;
}
