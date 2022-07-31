#!/usr/bin/env node

import { dirname } from 'path';
import { fileURLToPath } from 'url';
import { exec } from 'child_process';

exec('download-msgpackr-prebuilds', (error, stdout, stderr) => {
	console.error(stderr);
});
process.chdir(fileURLToPath(dirname(dirname(import.meta.url))));
process.argv[2] = 'download';
import('prebuildify-ci');