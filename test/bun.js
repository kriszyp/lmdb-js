import { open, IF_EXISTS, asBinary } from '../node-index.js';
import { assert, should as shouldLoad } from 'chai';
//const { assert, should: shouldLoad } = chai;
const should = shouldLoad();
let db = open('test/testdata', {
	name: 'deno-db1',
	useVersions: true,
	overlappingSync: true,
	maxReaders: 100,
	compression: {
		threshold: 128,
	},
});
let db2 = db.openDB({
	name: 'deno-db4',
	create: true,
	dupSort: true,
});
let tests = [];
let test = (name, test) => {
	tests.push({ name, test });
};
test('async txn', async function () {
	await db.transaction(() => {
		db.put('key1', 'Hello world!');
	});
});
test('query of keys', async function () {
	let keys = [
		Symbol.for('test'),
		false,
		true,
		-33,
		-1.1,
		3.3,
		5,
		[5, 4],
		[5, 55],
		[5, 'words after number'],
		[6, 'abc'],
		['Test', null, 1],
		['Test', Symbol.for('test'), 2],
		['Test', 'not null', 3],
		'hello',
		['hello', 3],
		['hello', 'world'],
		['uid', 'I-7l9ySkD-wAOULIjOEnb', 'Rwsu6gqOw8cqdCZG5_YNF'],
		'z',
	];
	for (let key of keys) {
		await db.put(key, 3);
	}
	let returnedKeys = [];
	for (let { key, value } of db.getRange({
		start: Symbol.for('A'),
	})) {
		returnedKeys.push(key);
		should.equal(db.get(key), value);
	}
	keys.should.deep.equal(returnedKeys);

	returnedKeys = [];
	for (let { key, value } of db.getRange({
		reverse: true,
	})) {
		returnedKeys.unshift(key);
		should.equal(db.get(key), value);
	}
	keys.should.deep.equal(returnedKeys);
});
test('reverse query range', async function () {
	const keys = [
		['Test', 100, 1],
		['Test', 10010, 2],
		['Test', 10010, 3],
	];
	for (let key of keys) await db.put(key, 3);
	for (let { key, value } of db.getRange({
		start: ['Test', null],
		end: ['Test', null],
		reverse: true,
	})) {
		throw new Error('Should not return any results');
	}
});
test('more reverse query range', async function () {
	db.putSync(
		'0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdtsud6g8YGhPwUK04fRVKhuTywhnx8',
		1,
		1,
		null,
	);
	db.putSync(
		'0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdu0mnkm8lS38yIZa4Xte3Q3JUoD84V',
		1,
		1,
		null,
	);
	const options = {
		start: '0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0SdvKaMkMNPoydWV6HxZbFtKeQm5sqz3',
		end: '0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/00000000dKZzSn03pte5dWbaYfrZl4hG',
		reverse: true,
	};
	let returnedKeys = Array.from(db.getKeys(options));
	returnedKeys.should.deep.equal([
		'0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdu0mnkm8lS38yIZa4Xte3Q3JUoD84V',
		'0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdtsud6g8YGhPwUK04fRVKhuTywhnx8',
	]);
});
test('clear between puts', async function () {
	db.put('key0', 'zero');
	db.clearAsync();
	await db.put('key1', 'one');
	assert.equal(db.get('key0'), undefined);
	assert.equal(db.get('hello'), undefined);
	assert.equal(db.get('key1'), 'one');
});

test('string', async function () {
	await db.put('key1', 'Hello world!');
	let data = db.get('key1');
	data.should.equal('Hello world!');
	await db.remove('key1');
	let data2 = db.get('key1');
	assert.equal(data2, undefined);
});
test('string with version', async function () {
	await db.put('key1', 'Hello world!', 53252);
	let entry = db.getEntry('key1');
	entry.value.should.equal('Hello world!');
	entry.version.should.equal(53252);
	(await db.remove('key1', 33)).should.equal(false);
	entry = db.getEntry('key1');
	entry.value.should.equal('Hello world!');
	entry.version.should.equal(53252);
	(await db.remove('key1', 53252)).should.equal(true);
	entry = db.getEntry('key1');
	assert.equal(entry, undefined);
});
test('string with version branching', async function () {
	await db.put('key1', 'Hello world!', 53252);
	let entry = db.getEntry('key1');
	entry.value.should.equal('Hello world!');
	entry.version.should.equal(53252);
	(
		await db.ifVersion('key1', 777, () => {
			db.put('newKey', 'test', 6);
			db2.put('keyB', 'test', 6);
		})
	).should.equal(false);
	assert.equal(db.get('newKey'), undefined);
	assert.equal(db2.get('keyB'), undefined);
	let result = await db.ifVersion('key1', 53252, () => {
		db.put('newKey', 'test', 6);
		db2.put('keyB', 'test', 6);
	});
	assert.equal(db.get('newKey'), 'test');
	assert.equal(db2.get('keyB'), 'test');
	assert.equal(result, true);
	result = await db.ifNoExists('key1', () => {
		db.put('newKey', 'changed', 7);
	});
	assert.equal(db.get('newKey'), 'test');
	assert.equal(result, false);
	result = await db.ifNoExists('key-no-exist', () => {
		db.put('newKey', 'changed', 7);
	});
	assert.equal(db.get('newKey'), 'changed');
	assert.equal(result, true);

	result = await db2.ifVersion('key-no-exist', IF_EXISTS, () => {
		db.put('newKey', 'changed again', 7);
	});
	assert.equal(db.get('newKey'), 'changed');
	assert.equal(result, false);

	result = await db2.ifVersion('keyB', IF_EXISTS, () => {
		db.put('newKey', 'changed again', 7);
	});
	assert.equal(db.get('newKey'), 'changed again');
	assert.equal(result, true);

	result = await db2.remove('key-no-exists');
	assert.equal(result, true);
	result = await db2.remove('key-no-exists', IF_EXISTS);
	assert.equal(result, false);
});
test('string with compression and versions', async function () {
	let str = expand('Hello world!');
	await db.put('key1', str, 53252);
	let entry = db.getEntry('key1');
	entry.value.should.equal(str);
	entry.version.should.equal(53252);
	(await db.remove('key1', 33)).should.equal(false);
	let data = db.get('key1');
	data.should.equal(str);
	(await db.remove('key1', 53252)).should.equal(true);
	data = db.get('key1');
	assert.equal(data, undefined);
});
test('repeated compressions', async function () {
	let str = expand('Hello world!');
	db.put('key1', str, 53252);
	db.put('key1', str, 53253);
	db.put('key1', str, 53254);
	await db.put('key1', str, 53255);
	let entry = db.getEntry('key1');
	entry.value.should.equal(str);
	entry.version.should.equal(53255);
	(await db.remove('key1')).should.equal(true);
});

test('forced compression due to starting with 255', async function () {
	await db.put('key1', asBinary(new Uint8Array([255])));
	let entry = db.getBinary('key1');
	entry.length.should.equal(1);
	entry[0].should.equal(255);
	(await db.remove('key1')).should.equal(true);
});
/*test('store objects', async function() {
	let dataIn = {foo: 3, bar: true}
	await db.put('key1',  dataIn);
	let dataOut = db.get('key1');
	assert.equal(JSON.stringify(dataIn),JSON.stringify(dataOut));
	db.removeSync('not-there').should.equal(false);
});*/

function expand(str) {
	str = '(' + str + ')';
	str = str + str;
	str = str + str;
	str = str + str;
	str = str + str;
	str = str + str;
	return str;
}

let hasErrors;
for (let { name, test } of tests) {
	try {
		await test();
		console.log('Passed:', name);
	} catch (error) {
		hasErrors = true;
		console.error('Failed:', name, error);
	}
}
if (hasErrors) throw new Error('Unit tests failed');
