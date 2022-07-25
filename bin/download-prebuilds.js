#!/usr/bin/env node

import { dirname } from 'path';
import { fileURLToPath } from 'url';
process.chdir(fileURLToPath(dirname(dirname(import.meta.url))));
process.argv[2] = 'download';
import('prebuildify-ci');