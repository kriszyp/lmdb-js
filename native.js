export let Env, Compression, Cursor, getAddress, getAddressShared, setGlobalBuffer, require, arch, fs;
export function setNativeFunctions(nativeInterface) {
	Env = nativeInterface.Env;
	Compression = nativeInterface.Compression;
	getAddress = nativeInterface.getAddress;
    setGlobalBuffer = nativeInterface.setGlobalBuffer;
    Cursor = nativeInterface.Cursor;
    require = nativeInterface.require;
    arch = nativeInterface.arch;
    fs = nativeInterface.fs;
}
