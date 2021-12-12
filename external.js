export let Env, Compression, Cursor, getAddress, getAddressShared, setGlobalBuffer,
    require, arch, fs, lmdbError, path, EventEmitter, orderedBinary, MsgpackrEncoder, WeakLRUCache;
export function setNativeFunctions(externals) {
	Env = externals.Env;
	Compression = externals.Compression;
	getAddress = externals.getAddress;
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
export function instrument(symbols) {
    for (let key in symbols) {
        let func = symbols[key];
        symbols[key] = function() {
            console.log('start', key);
            return func.apply(this, arguments);
        }
    }
    
}