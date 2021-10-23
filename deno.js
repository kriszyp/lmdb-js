let lmdbLib = Deno.dlopen('./build/Release/lmdb-store.node', {
	envOpen: { parameters: ['u32', 'buffer', 'usize'], result: 'usize'}
})
let b = new Uint8Array([1,2])
console.log(symbols.envOpen(0, b, 2))
let { Env, open } = lmdbLib.symbols

let registry = new FinalizationRegistry(address => {
    // when an object is GC'ed, free it in C.
    free(address)
})

class CBridge {
    constructor(address) {
        this.address = address
        registry.register(this, address)
    }
    static addMethods(...methods) {
        for (let method of methods) {
            this.prototype[method] = function() {
                return symbols[method](this.address, ...arguments)
            }
        }
    }
}
class Env extends CBridge {
    constructor() {
        super(symbols.Env())
    }
    open(flags, path) {
        return open(this.address, flags, path)
    }
}
Env.addMethods('startWriting', 'write', 'openDB')
