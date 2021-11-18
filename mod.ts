import { setNativeFunctions } from './native.js';
// probably use Deno.build.os
import { arch } from 'https://deno.land/std/node/os.ts';
let lmdbLib = Deno.dlopen('./build/Release/lmdb-js.node', {
	envOpen: { parameters: ['u32', 'buffer', 'usize'], result: 'usize'},/*
    free: { parameters: ['buffer', 'usize'], result: 'void'},
    getAddress: { parameters: ['buffer', 'usize'], result: 'usize'},
    startWriting: { parameters: ['buffer', 'usize'], nonblocking: true, result: 'u32'},
    write: { parameters: ['buffer', 'usize'], result: 'u32'},
    getBinary: { parameters: ['buffer', 'usize'], result: 'u32'},
    */
});
let b = new Uint8Array([1,2]);
console.log(lmdbLib.symbols.envOpen(0, b, 2));
let { envOpen, getAddress, free } = lmdbLib.symbols;

let registry = new FinalizationRegistry(address => {
    // when an object is GC'ed, free it in C.
    free(address, 1);
});

class CBridge {
    constructor(address) {
        this.address = address;
        registry.register(this, address);
    }
    static addMethods(...methods) {
        for (let method of methods) {
            this.prototype[method] = function() {
                return symbols[method](this.address, ...arguments);
            };
        }
    }
}
class Env extends CBridge {
    constructor() {
        super(symbols.Env());
    }
    open(flags, path) {
        return envOpen(this.address, flags, path);
    }
}
Env.addMethods('startWriting', 'write', 'openDB');

class Dbi extends CBridge {

}

class Compression extends CBridge {

}
class Cursor extends CBridge {

}

setNativeFunctions({ Env, Compression, Cursor, fs: Deno, arch, getAddress, getAddressShared: getAddress });
export { toBufferKey as keyValueToBuffer, compareKeys, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary/index.js';
export { ABORT, asBinary } from './write.js';
export { levelup } from './level.js';
export { open, getLastVersion } from './index.js';
import { toBufferKey as keyValueToBuffer, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } from 'ordered-binary/index.js';
import { open, getLastVersion } from './index.js';
export default {
	open, getLastVersion, compareKey, keyValueToBuffer, bufferToKeyValue
};