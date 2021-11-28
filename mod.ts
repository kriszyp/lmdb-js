import { orderedBinary, setNativeFunctions } from './external.js';
import './deps.ts';
orderedBinary.enableNullTermination();
// probably use Deno.build.os
let lmdbLib = Deno.dlopen('./lmdb-store/build/Release/lmdb.node', {
    // const char* path, char* keyBuffer, Compression* compression, int jsFlags, int flags, int maxDbs,
    // int maxReaders, mdb_size_t mapSize, int pageSize, char* encryptionKey
	//envOpen: { parameters: ['buffer', 'usize', 'usize', 'u32', 'u32', 'u32', 'u32', 'usize', 'u32', 'buffer', 'usize'], result: 'usize'},
    freeData: { parameters: ['buffer', 'usize'], result: 'void'},
    getAddress: { parameters: ['buffer'], result: 'usize'},/*
    startWriting: { parameters: ['buffer', 'usize'], nonblocking: true, result: 'u32'},
    write: { parameters: ['buffer', 'usize'], result: 'u32'},
    getBinary: { parameters: ['buffer', 'usize'], result: 'u32'},
    */
});
let b = new Uint8Array([1,2]);
//console.log(lmdbLib.symbols.envOpen(0, b, 2));
let { /*envOpen, */getAddress, freeData } = lmdbLib.symbols;

let registry = new FinalizationRegistry(address => {
    // when an object is GC'ed, free it in C.
    //freeData(address, 1);
});

class CBridge {
    address: number;
    constructor(address: number) {
        this.address = address;
        registry.register(this, address);
    }
  /*  static addMethods(...methods: ) {
        for (let method of methods) {
            this.prototype[method] = function() {
                return symbols[method](this.address, ...arguments);
            };
        }
    }*/
}
class Env extends CBridge {
    open(flags: number, path: string) {
        //this.address = envOpen(flags, path) as number;
    }
}
//Env.addMethods('startWriting', 'write', 'openDB');
function envOpen() {

}
class Dbi extends CBridge {

}

class Compression extends CBridge {

}
class Cursor extends CBridge {

}

setNativeFunctions({ envOpen, Compression, Cursor, getAddress, getAddressShared: getAddress });
export const { toBufferKey: keyValueToBuffer, compareKeys, compareKeys: compareKey, fromBufferKey: bufferToKeyValue } = orderedBinary;
export { ABORT, asBinary } from './write.js';
export { levelup } from './level.js';
export { open, getLastVersion } from './index.js';
import { open, getLastVersion } from './index.js';
export default {
	open, getLastVersion, compareKey, keyValueToBuffer, bufferToKeyValue
};