export let Env, Compression, Cursor, getAddress, getAddressShared, require, os, fs
export function setNativeFunctions(nativeInterface) {
	Env = nativeInterface.Env
	Compression = nativeInterface.Compression
	getAddress = nativeInterface.getAddress
    getAddressShared = nativeInterface.getAddressShared
    Cursor = nativeInterface.Cursor
    require = nativeInterface.require
    os = nativeInterface.os
    fs = nativeInterface.fs
}
