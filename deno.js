let lmdbLib = Deno.dlopen('./build/Release/lmdb-store.node', {
	envOpen: { parameters: ['u32', 'buffer', 'usize'], result: 'usize'}
})
let b = new Uint8Array([1,2])
console.log(lmdbLib.symbols.envOpen(0, b, 2))
