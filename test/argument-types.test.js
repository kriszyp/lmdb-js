import chai from 'chai';
import path, { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { open } from '../node-index.js';
import { nativeAddon } from '../native.js';

chai.should();
let expect = chai.expect;
let dirName = dirname(fileURLToPath(import.meta.url));

describe('argument types', function () {
	let dir;
	before(function () {
		dir = mkdtempSync(path.join(tmpdir(), 'lmdb-argument-types-'));
	});

	it('rejects a non-string encryptionKey', function () {
		expect(() => open({ path: path.join(dir, 'enc'), encryptionKey: 42 })).to.throw();
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
		expect(() => db.env.copy(path.join(dir, 'copy-dest'), true, {}, () => {})).to.throw();
		db.close();
	});
});
