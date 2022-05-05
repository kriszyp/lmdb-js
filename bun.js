import { dlopen, FFIType, suffix } from "bun:ffi";
import { orderedBinary, setNativeFunctions } from './external.js';
orderedBinary.enableNullTermination();
// probably use Deno.build.os
let libPath = './build/Release/lmdb.node'// import.meta.url.startsWith('file:') && fileURLToPath(new URL('build/Release/lmdb.node', import.meta.url));
/*if (!libPath || !exists(libPath)) {
	//console.log({ libPath }, 'does not exist')
	libPath = (Deno.env.get('LMDB_LIB_PATH') || (tmpdir() + '/lmdb-js-' + (version || '') + '.lib')) as string;
	const ARCH = { x86_64: 'x64', aarch64: 'arm64' }
	if (!exists(libPath)) {
		let os = Deno.build.os;
		os = os == 'windows' ? 'win32' : os;
		os += '-' + ARCH[Deno.build.arch];
		let libraryUrl = 'https://cdn.jsdelivr.net/npm/lmdb@' + (version || 'latest') +
			'/prebuilds/' + os + '/node.abi93' + (os == 'win32' ? '' : '.glibc') + '.node';
		console.log('Download', libraryUrl);
		let response = await fetch(libraryUrl);
		if (response.status == 200) {
			let binaryLibraryBuffer = await response.arrayBuffer();
			Deno.writeFileSync(libPath, new Uint8Array(binaryLibraryBuffer));			
		} else {
			throw new Error('Unable to fetch ' + libraryUrl + ', HTTP response: ' + response.status);
		}
	}
}*/
console.log('first test', dlopen(libPath, {
	readerCheck: { args: [FFIType.f64], returns: FFIType.i32},
}))

let lmdbLib = dlopen(libPath, {
	// const char* path, char* keyBuffer, Compression* compression, int jsFlags, int flags, int maxDbs,
	// int maxReaders, mdb_size_t mapSize, int pageSize, char* encryptionKey
	envOpen: { args: [FFIType.u32, FFIType.u32, FFIType.ptr, FFIType.ptr, FFIType.f64, FFIType.u32, FFIType.u32, FFIType.f64, FFIType.u32, FFIType.ptr], returns: FFIType.i64},
	closeEnv: { args: [FFIType.f64], returns: FFIType.u8},
	freeData: { args: [FFIType.f64], returns: FFIType.u8},
	getAddress: { args: [FFIType.ptr], returns: 'usize'},
	getMaxKeySize: { args: [FFIType.f64], returns: FFIType.u32},
	openDbi: { args: [FFIType.f64, FFIType.u32, FFIType.ptr, FFIType.u32, FFIType.f64], returns: FFIType.i64},
	getDbi: { args: [FFIType.f64], returns: FFIType.u32},
	readerCheck: { args: [FFIType.f64], returns: FFIType.i32},
	beginTxn: { args: [FFIType.f64, FFIType.u32], returns: FFIType.i64},
	resetTxn: { args: [FFIType.f64], returns: FFIType.u8},
	renewTxn: { args: [FFIType.f64], returns: FFIType.i32},
	abortTxn: { args: [FFIType.f64], returns: FFIType.u8},
	commitTxn: { args: [FFIType.f64], returns: FFIType.i32},
	commitEnvTxn: { args: [FFIType.f64], returns: FFIType.i32},
	abortEnvTxn: { args: [FFIType.f64], returns: FFIType.u8},
	getError: { args: [FFIType.i32, FFIType.ptr], returns: FFIType.u8},
	dbiGetByBinary: { args: [FFIType.f64, FFIType.u32], returns: FFIType.u32},	
	openCursor: { args: [FFIType.f64], returns: FFIType.i64},
	cursorRenew: { args: [FFIType.f64], returns: FFIType.i32},
	cursorClose: { args: [FFIType.f64], returns: FFIType.i32},
	cursorIterate: { args: [FFIType.f64], returns: FFIType.i32},
	cursorPosition: { args: [FFIType.f64, FFIType.u32, FFIType.u32, FFIType.u32, FFIType.f64], returns: FFIType.i32},
	cursorCurrentValue: { args: [FFIType.f64], returns: FFIType.i32},
	startWriting: { args: [FFIType.f64, FFIType.f64], nonblocking: true, returns: FFIType.i32},
	compress: { args: [FFIType.f64, FFIType.f64], nonblocking: true, returns: FFIType.u8},
	envWrite: { args: [FFIType.f64, FFIType.f64], returns: FFIType.i32},
	setGlobalBuffer: { args: [FFIType.ptr, 'usize'], returns: FFIType.u8},
	setCompressionBuffer: { args: [FFIType.f64, FFIType.ptr, FFIType.u32, FFIType.ptr, FFIType.u32], returns: FFIType.u8},
	newCompression: { args: [FFIType.ptr, 'usize', FFIType.u32], returns: FFIType.u64},
	prefetch: { args: [FFIType.f64, FFIType.f64], nonblocking: true, returns: FFIType.i32},
    envSync: { args: [FFIType.f64], nonblocking: true, returns: FFIType.i32},
});
console.log('second test', lmdbLib.symbols)


let { envOpen, closeEnv, getAddress, freeData, getMaxKeySize, openDbi, getDbi, readerCheck,
	commitEnvTxn, abortEnvTxn, beginTxn, resetTxn, renewTxn, abortTxn, commitTxn, dbiGetByBinary, startWriting, compress, envWrite, openCursor, cursorRenew, cursorClose, cursorIterate, cursorPosition, cursorCurrentValue, setGlobalBuffer: setGlobalBuffer2, setCompressionBuffer, getError, newCompression, prefetch,envSync } = lmdbLib.symbols;
let registry = new FinalizationRegistry(address => {
	// when an object is GC'ed, free it in C.
	freeData(address);
});

class CBridge {
	address;
	constructor(address) {
		this.address = address || 0;
		if (address) {
			registry.register(this, address);
		}
	}
}
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const MAX_ERROR = 1000;
function checkError(rc) {
	if (rc && rc < MAX_ERROR) {
		// TODO: Look up error and throw
		lmdbError(rc);
	}
	return rc;
}
function lmdbError(rc) {
	getError(rc, keyBytes);
	let message = textDecoder.decode(keyBytes.subarray(0, keyBytes.indexOf(0))) || ('Error code: ' + rc);
	throw new Error(message);
}
let keyBytes;
class Env extends CBridge {
	open(options, flags, jsFlags) {
		let rc = envOpen(flags, jsFlags, toCString(options.path), keyBytes = options.keyBytes, 0,
			options.maxDbs || 12, options.maxReaders || 126, options.mapSize, options.pageSize, new Uint8Array(0));
		this.address = checkError(rc);
		registry.register(this, this.address);
		return 0;
	}
	openDbi(flags, name, keyType, compression) {
		let rc = openDbi(this.address, flags, toCString(name), keyType, compression?.address || 0);
		if (rc == -30798) { // MDB_NOTFOUND
			return;
		}
		return new Dbi(checkError(rc),
			getDbi(rc));
	}
	close() {
		closeEnv(this.address);
	}
	getMaxKeySize() {
		return getMaxKeySize(this.address);
	}
	readerCheck() {
		return readerCheck(this.address);
	}
	beginTxn(flags) {
		let rc = beginTxn(this.address, flags);
		return new Transaction(checkError(rc), flags);
	}
	commitTxn() {
		checkError(commitEnvTxn(this.address));
	}
	abortTxn() {
		abortEnvTxn(this.address);
	}
	startWriting(instructions, callback) {
		startWriting(this.address, instructions).then(callback);
	}
	compress(compressionPointer, callback) {
		return compress(this.address, compressionPointer).then(callback);
	}
	write(instructions) {
		return checkError(envWrite(this.address, instructions));
	}
    sync(callback) {
        return envSync(this.address).then((returns) => {
            try {
                checkError(result);
                callback(null);
            } catch(error) {
                callback(error);
            }
        });
    }
}
//Env.addMethods('startWriting', 'write', 'openDB');
class Dbi extends CBridge {
	dbi;
	constructor(address, dbi) {
		super(address);
		this.dbi = dbi;
	}
	getByBinary(keySize) {
		return dbiGetByBinary(this.address, keySize);
	}
	prefetch(keys, callback) {
		prefetch(this.address, keys).then(() => callback());
	}
}
class Transaction extends CBridge {
	flags;
	constructor(address, flags) {
		super(address);
		this.flags = flags;
	}
	reset() {
		resetTxn(this.address);
	}
	renew() {
		let rc = renewTxn(this.address);
		if (rc)
			lmdbError(rc);
	}
	abort() {
		abortTxn(this.address);
	}
	commit() {
		commitTxn(this.address);
	}
}


class Compression extends CBridge {
	constructor(options) {
		let dictionary = options.dictionary || new Uint8Array(0);
		super(newCompression(dictionary, dictionary.length, options.threshold || 1000));
	}
	setBuffer(target, targetLength, dictionary, dictLength) {
		setCompressionBuffer(this.address, target, targetLength, dictionary, dictLength);
	}
}
class Cursor extends CBridge {
	constructor(dbi) {
		super(openCursor(dbi.address));
	}
	renew() {
		cursorRenew(this.address);
	}
	position(flags, offset, keySize, endKeyAddress) {
		return cursorPosition(this.address, flags, offset, keySize, endKeyAddress);
	}
	iterate() {
		return cursorIterate(this.address);
	}
	getCurrentValue() {
		return cursorCurrentValue(this.address);
	}
	close() {
		return cursorClose(this.address);
	}
}
function toCString(str) {
	return str == null ? new Uint8Array(0) : textEncoder.encode(str + '\x00');
}
function setGlobalBuffer(buffer) {
	setGlobalBuffer2(buffer, buffer.length);
}

setNativeFunctions({ Env, Compression, Cursor, getAddress, tmpdir, lmdbError, setGlobalBuffer });
export const { toBufferKey: keyValueToBuffer, compareKeys, compareKeys: compareKey, fromBufferKey: bufferToKeyValue } = orderedBinary;
export { ABORT, asBinary, IF_EXISTS } from './write.js';
export { levelup } from './level.js';
export { open, getLastVersion } from './open.js';

// inlined from https://github.com/denoland/deno_std/blob/main/node/os.ts
function tmpdir() {
	/* This follows the node js implementation, but has a few
	   differences:
	   * On windows, if none of the environment variables are defined,
		 we return null.
	   * On unix we use a plain Deno.env.get, instead of safeGetenv,
		 which special cases setuid binaries.
	   * Node removes a single trailing / or \, we remove all.
	*/
	if (Deno.build.os == 'windows') {
	  const temp = Deno.env.get("TEMP") || Deno.env.get("TMP");
	  if (temp) {
		return temp.replace(/(\?\<\!\:)[/\\]*$/, "");
	  }
	  const base = Deno.env.get("SYSTEMROOT") || Deno.env.get("WINDIR");
	  if (base) {
		return base + "\\temp";
	  }
	  return null;
	} else { // !isWindows
	  const temp = Deno.env.get("TMPDIR") || Deno.env.get("TMP") ||
		Deno.env.get("TEMP") || "/tmp";
	  return temp.replace(/(\?\<\!\^)\/*$/, "");
	}
}
function exists(path) {
	try {
		return Boolean(Deno.statSync(path));
	} catch (error) {
		if (error.name == 'NotFound')
			return false
		throw error
	}
}
