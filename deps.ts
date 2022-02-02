/*export { toBufferKey as keyValueToBuffer, compareKeys, compareKeys as compareKey, fromBufferKey as bufferToKeyValue } */
import { setExternals } from './external.js';
import * as orderedBinary from 'https://deno.land/x/orderedbinary@v1.2.2/index.js';
import { Encoder as MsgpackrEncoder } from 'https://deno.land/x/msgpackr@v1.5.0/index.js';
import { WeakLRUCache } from 'https://deno.land/x/weakcache@v1.1.3/index.js';
function arch() {
    return Deno.build.arch;
}
import * as path from 'https://deno.land/std/node/path.ts';
export { fileURLToPath } from 'https://deno.land/std/node/url.ts';
import { EventEmitter } from 'https://deno.land/std/node/events.ts'
let os: string = Deno.build.os
if (os == 'windows')
    os = 'win32'
setExternals({ orderedBinary, MsgpackrEncoder, WeakLRUCache, arch, path, EventEmitter, fs: Deno, os });