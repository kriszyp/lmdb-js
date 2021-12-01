import { orderedBinary, setNativeFunctions } from './external.js';
import './deps.ts';
orderedBinary.enableNullTermination();
// probably use Deno.build.os
// https://cdn.jsdelivr.net/npm/lmdb@latest/prebuilds/win32-x64/node.abi102.node
let lmdbLib = Deno.dlopen('./lmdb-store/build/Release/lmdb.node', {
    // const char* path, char* keyBuffer, Compression* compression, int jsFlags, int flags, int maxDbs,
    // int maxReaders, mdb_size_t mapSize, int pageSize, char* encryptionKey
	envOpen: { parameters: ['u32', 'u32', 'buffer', 'buffer', 'f64', 'u32', 'u32', 'usize', 'u32', 'buffer'], result: 'usize'},
    freeData: { parameters: ['buffer', 'usize'], result: 'void'},
    getAddress: { parameters: ['buffer'], result: 'usize'},
    getMaxKeySize: { parameters: ['f64'], result: 'u32'},
    /*
    startWriting: { parameters: ['buffer', 'usize'], nonblocking: true, result: 'u32'},
    write: { parameters: ['buffer', 'usize'], result: 'u32'},
    getBinary: { parameters: ['buffer', 'usize'], result: 'u32'},
    */
});
let b = new Uint8Array([1,2]);
//console.log(lmdbLib.symbols.envOpen(0, b, 2));
let { envOpen, getAddress, freeData, getMaxKeySize } = lmdbLib.symbols;

let registry = new FinalizationRegistry(address => {
    // when an object is GC'ed, free it in C.
    freeData(address, 1);
});

class CBridge {
    address: number;
    constructor(address: number) {
        this.address = address || 0;
        if (address) {
            registry.register(this, address);
        }
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
    open(options: any, flags: number, jsFlags: number) {
        let te = new TextEncoder();
        let rc = envOpen(flags, jsFlags, te.encode(options.path + '\x00'), options.keyBytes, 0,
            options.maxDbs || 12, options.maxReaders || 126, options.mapSize, options.pageSize, new Uint8Array(0)) as number;
        console.log('open rc', rc);
        if (rc < 0)
            return rc;
        this.address = rc;
        registry.register(this, this.address);
        return 0;
    }
    getMaxKeySize() {
        console.log('getMax', this.address)
        return getMaxKeySize(this.address);
    }
}
//Env.addMethods('startWriting', 'write', 'openDB');
class Dbi extends CBridge {

}

class Compression extends CBridge {

}
class Cursor extends CBridge {

}

setNativeFunctions({ Env, Compression, Cursor, getAddress, getAddressShared: getAddress });
export const { toBufferKey: keyValueToBuffer, compareKeys, compareKeys: compareKey, fromBufferKey: bufferToKeyValue } = orderedBinary;
export { ABORT, asBinary } from './write.js';
export { levelup } from './level.js';
export { open, getLastVersion } from './open.js';
