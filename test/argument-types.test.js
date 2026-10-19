import chai from 'chai';
import path from 'node:path';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { open } from '../node-index.js';
import { nativeAddon } from '../native.js';

chai.should();
let expect = chai.expect;

describe('argument types', function () {
	let dir;
	before(function () {
		dir = mkdtempSync(path.join(tmpdir(), 'lmdb-argument-types-'));
	});

	it('rejects an encryptionKey that is neither a string nor a Buffer', function () {
		expect(() =>
			open({ path: path.join(dir, 'enc'), encryptionKey: 42 }),
		).to.throw();
	});

	it('accepts a Buffer encryptionKey with the same bytes as a string key', async function () {
		let key = 'Use this key to encrypt the data';
		let encPath = path.join(dir, 'enc-buffer');
		let db = open({ path: encPath, encryptionKey: key });
		await db.put('a', 'secret');
		await db.close();
		db = open({ path: encPath, encryptionKey: Buffer.from(key) });
		expect(db.get('a')).to.equal('secret');
		await db.close();
	});

	it('closes an environment that never finished opening', function () {
		let env = new nativeAddon.Env();
		let options = {
			path: path.join(dir, 'never'),
			keyBytes: Buffer.alloc(16),
			encryptionKey: 42,
		};
		expect(() => env.open(options, 0, 0)).to.throw();
		env.close();
		env = new nativeAddon.Env();
		options = {
			path: path.join(dir, 'missing', 'db'),
			keyBytes: Buffer.alloc(16),
		};
		expect(() => env.open(options, 0, 0)).to.throw();
	});

	it('rejects a non-ArrayBuffer default buffer', function () {
		let db = open({ path: path.join(dir, 'usb') });
		expect(() => db.getUserSharedBuffer('key', {})).to.throw();
		db.close();
	});

	it('rejects an unwrappable environment', function () {
		expect(() => new nativeAddon.Txn({}, 0)).to.throw();
		expect(() => new nativeAddon.Dbi({}, 0, 'name', 0)).to.throw();
		expect(() => new nativeAddon.Cursor({}, 0)).to.throw();
	});

	it('rejects non-numeric open flags', function () {
		let env = new nativeAddon.Env();
		expect(() => env.open({ path: path.join(dir, 'flags') }, {}, 0)).to.throw();
		expect(() => env.open({ path: path.join(dir, 'flags') }, 0, {})).to.throw();
	});

	it('rejects a non-function copy callback', function () {
		let db = open({ path: path.join(dir, 'copy') });
		expect(() =>
			db.env.copy(path.join(dir, 'copy-dest'), true, {}, () => {}),
		).to.throw();
		db.close();
	});
});
