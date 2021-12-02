import { orderedBinary, setNativeFunctions } from './external.js';
import './deps.ts';
orderedBinary.enableNullTermination();
// probably use Deno.build.os
// https://cdn.jsdelivr.net/npm/lmdb@latest/prebuilds/win32-x64/node.abi102.node
let lmdbLib = Deno.dlopen('./lmdb-store/build/Release/lmdb.node', {
    // const char* path, char* keyBuffer, Compression* compression, int jsFlags, int flags, int maxDbs,
    // int maxReaders, mdb_size_t mapSize, int pageSize, char* encryptionKey
	envOpen: { parameters: ['u32', 'u32', 'buffer', 'buffer', 'f64', 'u32', 'u32', 'usize', 'u32', 'buffer'], result: 'i64'},
    freeData: { parameters: ['buffer', 'usize'], result: 'void'},
    getAddress: { parameters: ['buffer'], result: 'usize'},
    getMaxKeySize: { parameters: ['f64'], result: 'u32'},
    openDbi: { parameters: ['f64', 'u32', 'buffer', 'u32', 'f64'], result: 'i64'},
    getDbi: { parameters: ['f64'], result: 'u32'},
    readerCheck: { parameters: ['f64'], result: 'i32'},
    /*
    startWriting: { parameters: ['buffer', 'usize'], nonblocking: true, result: 'u32'},
    write: { parameters: ['buffer', 'usize'], result: 'u32'},
    getBinary: { parameters: ['buffer', 'usize'], result: 'u32'},
    */
});
let { envOpen, getAddress, freeData, getMaxKeySize, openDbi, getDbi, readerCheck } = lmdbLib.symbols;

let registry = new FinalizationRegistry(address => {
    // when an object is GC'ed, free it in C.
    freeData(address, 1);
});
console.log(import.meta)

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
const textEncoder = new TextEncoder();
const MAX_ERROR = 1000;
function checkError(rc: number): number {
    if (rc < MAX_ERROR) {
        // TODO: Look up error and throw
        console.log("error", rc);
    }
    return rc;
}
class Env extends CBridge {
    open(options: any, flags: number, jsFlags: number) {
        let rc = envOpen(flags, jsFlags, textEncoder.encode(options.path + '\x00'), options.keyBytes, 0,
            options.maxDbs || 12, options.maxReaders || 126, options.mapSize, options.pageSize, new Uint8Array(0)) as number;
        console.log('open rc', rc);
        this.address = checkError(rc);
        registry.register(this, this.address);
        return 0;
    }
    openDbi(options: any) {
        let flags = (options.reverseKey ? 0x02 : 0) |
            (options.dupSort ? 0x04 : 0) |
            (options.dupFixed ? 0x08 : 0) |
            (options.integerDup ? 0x20 : 0) |
            (options.reverseDup ? 0x40 : 0) |
            (options.create ? 0x40000 : 0) |
            (options.useVersions ? 0x1000 : 0);
        let keyType = (options.keyIsUint32 || options.keyEncoding == 'uint32') ? 2 :
            (options.keyIsBuffer || options.keyEncoding == 'binary') ? 3 : 0;
        let rc: number = openDbi(this.address, flags, textEncoder.encode(options.name + '\x00'), options.compression || 0) as number;
        if (rc == -30798) { // MDB_NOTFOUND
            console.log('dbi not found, need to try again with write txn');
        }
        return new Dbi(checkError(rc),
            getDbi(rc) as number);
    }
    getMaxKeySize() {
        return getMaxKeySize(this.address);
    }
    readerCheck() {
        return readerCheck(this.address);
    }
    beginTxn(flags: number) {

    }
}
//Env.addMethods('startWriting', 'write', 'openDB');
class Dbi extends CBridge {
    dbi: number;
    constructor(address: number, dbi: number) {
        super(address);
        this.dbi = dbi;
    }
}
class Transaction extends CBridge {
    constructor(address: number) {
        super(address);
    }
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
