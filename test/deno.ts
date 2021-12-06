import { open } from '../mod.ts';
setTimeout(() => {
	let db = open('test-deno');
}, 1000);