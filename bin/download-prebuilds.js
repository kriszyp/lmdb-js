#!/usr/bin/env node

import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { exec, execFile } from 'child_process';

// msgpackr-extract is a dependency of msgpackr, not of lmdb, so its bin is not
// always linked on PATH (pnpm only links the bins of direct dependencies).
// Resolve it from msgpackr's location and run it with the current node instead.
const requireFromMsgpackr = createRequire(
	createRequire(import.meta.url).resolve('msgpackr'),
);
const extractPackagePath = requireFromMsgpackr.resolve(
	'msgpackr-extract/package.json',
);
const extractBin = join(
	dirname(extractPackagePath),
	requireFromMsgpackr(extractPackagePath).bin['download-msgpackr-prebuilds'],
);
execFile(process.execPath, [extractBin], propagateOutput);
process.chdir(fileURLToPath(dirname(dirname(import.meta.url))));
exec('prebuildify-ci download', propagateOutput);
function propagateOutput(error, stdout, stderr) {
	console.error(stderr);
	console.log(stdout);
	if (error?.code)
		process.exit(error.code);
}
