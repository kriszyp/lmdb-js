import { open } from '../mod.ts';
setTimeout(async () => {
	let db = open('test-deno');
	await db.put('key', 'test')
	console.log(db.get('key'));
}, 1);