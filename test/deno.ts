import { open } from '../mod.ts';
import chai from "https://cdn.skypack.dev/chai@4.3.4?dts";
const { assert, should } = chai;
should();
try {
	Deno.removeSync('test/testdata', { recursive: true });
} catch(error) {
	if (error.name != 'NotFound')
		throw error
}
let db = open('test/testdata');
let tests: { name: string, test: Function }[] = [];
let test = (name: string, test: Function) => {
	tests.push({ name, test });
};
test('query of keys', async function() {
	let keys = [
		Symbol.for('test'),
		false,
		true,
		-33,
		-1.1,
		3.3,
		5,
		[5,4],
		[5,55],
		[5, 'words after number'],
		[6, 'abc'],
		[ 'Test', null, 1 ],
		[ 'Test', Symbol.for('test'), 2 ],
		[ 'Test', 'not null', 3 ],
		'hello',
		['hello', 3],
		['hello', 'world'],
		[ 'uid', 'I-7l9ySkD-wAOULIjOEnb', 'Rwsu6gqOw8cqdCZG5_YNF' ],
		'z'
	]
	for (let key of keys) {
		await db.put(key, 3);
	}
	let returnedKeys = []
	for (let { key, value } of db.getRange({
		start: Symbol.for('A')
	})) {
		returnedKeys.push(key)
		value.should.equal(db.get(key))
	}
	keys.should.deep.equal(returnedKeys)

	returnedKeys = []
	for (let { key, value } of db.getRange({
		reverse: true,
	})) {
		returnedKeys.unshift(key)
		value.should.equal(db.get(key))
	}
	keys.should.deep.equal(returnedKeys)
});
test('reverse query range', async function() {
	const keys = [
		[ 'Test', 100, 1 ],
		[ 'Test', 10010, 2 ],
		[ 'Test', 10010, 3 ]
	]
	for (let key of keys)
		await db.put(key, 3);
	for (let { key, value } of db.getRange({
		start: ['Test', null],
		end: ['Test', null],
		reverse: true
	})) {
		throw new Error('Should not return any results')
	}
})
test('more reverse query range', async function() {
	db.putSync('0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdtsud6g8YGhPwUK04fRVKhuTywhnx8', 1, 1, null);
	db.putSync('0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdu0mnkm8lS38yIZa4Xte3Q3JUoD84V', 1, 1, null);
	const options =
	{
		start: '0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0SdvKaMkMNPoydWV6HxZbFtKeQm5sqz3',
		end: '0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/00000000dKZzSn03pte5dWbaYfrZl4hG',
		reverse: true
	};
	let returnedKeys = Array.from(db.getKeys(options))
	returnedKeys.should.deep.equal(['0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdu0mnkm8lS38yIZa4Xte3Q3JUoD84V', '0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdtsud6g8YGhPwUK04fRVKhuTywhnx8'])
});
test('clear between puts', async function() {
	db.put('key0', 'zero')
	db.clearAsync()
	await db.put('key1', 'one')
	assert.equal(db.get('key0'), undefined)
	assert.equal(db.get('hello'), undefined)
	assert.equal(db.get('key1'), 'one')
});
let hasErrors
for (let { name, test } of tests) {
	try {
		await test();
		console.log('Passed:', name);
	} catch (error) {
		hasErrors = true;
		console.error('Failed:', name, error);
	}
}
if (hasErrors)
	throw new Error('Unit tests failed');