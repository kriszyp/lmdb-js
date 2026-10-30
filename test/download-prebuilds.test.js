import chai from 'chai';
import { spawnSync } from 'node:child_process';
import {
	chmodSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const expect = chai.expect;
const lmdbDir = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(import.meta.url);

describe('download-lmdb-prebuilds', function () {
	let binDir;
	before(function () {
		binDir = mkdtempSync(join(tmpdir(), 'lmdb-download-prebuilds-'));
		// stand-in for prebuildify-ci that records the directory it was run in
		const fake = join(binDir, 'fake-prebuildify-ci.cjs');
		writeFileSync(
			fake,
			"require('fs').appendFileSync(process.env.LMDB_TEST_CALLS_LOG, process.cwd() + '\\n');\n",
		);
		writeFileSync(
			join(binDir, 'prebuildify-ci'),
			`#!/bin/sh\nexec "${process.execPath}" "${fake}" "$@"\n`,
		);
		chmodSync(join(binDir, 'prebuildify-ci'), 0o755);
		writeFileSync(
			join(binDir, 'prebuildify-ci.cmd'),
			`@"${process.execPath}" "${fake}" %*\r\n`,
		);
	});
	after(function () {
		rmSync(binDir, { recursive: true, force: true });
	});

	it('runs the msgpackr-extract download without its bin on PATH', function () {
		// only prebuildify-ci is on PATH, like a pnpm install where the bin of
		// the transitive msgpackr-extract dependency is not linked
		const env = {};
		for (const key in process.env)
			if (key.toUpperCase() !== 'PATH') env[key] = process.env[key];
		env.PATH = binDir + delimiter + dirname(process.execPath);
		env.LMDB_TEST_CALLS_LOG = join(binDir, 'calls.log');
		const result = spawnSync(
			process.execPath,
			[join(lmdbDir, 'bin', 'download-prebuilds.js')],
			{ env, encoding: 'utf8' },
		);
		expect(result.status, result.stderr).to.equal(0);
		const requireFromMsgpackr = createRequire(require.resolve('msgpackr'));
		const extractDir = dirname(
			requireFromMsgpackr.resolve('msgpackr-extract/package.json'),
		);
		const calls = readFileSync(env.LMDB_TEST_CALLS_LOG, 'utf8')
			.trim()
			.split('\n')
			.map((dir) => realpathSync(dir));
		expect(calls).to.have.members([
			realpathSync(extractDir),
			realpathSync(lmdbDir),
		]);
	});
});
