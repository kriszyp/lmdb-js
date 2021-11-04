export let Env, Compression, Cursor, getAddress, getAddressShared, require, arch, fs
export function setNativeFunctions(nativeInterface) {
	Env = nativeInterface.Env
	Compression = nativeInterface.Compression
	getAddress = nativeInterface.getAddress
    getAddressShared = nativeInterface.getAddressShared
    Cursor = nativeInterface.Cursor
    require = nativeInterface.require
    arch = nativeInterface.arch
    fs = nativeInterface.fs
}
