var assert = require('assert');
const {
	Worker,
	isMainThread,
	parentPort,
	threadId,
} = require('worker_threads');
var path = require('path');
var numCPUs = require('os').cpus().length;
const { setFlagsFromString } = require('v8');
const { runInNewContext } = require('vm');

setFlagsFromString('--expose_gc');
const gc = runInNewContext('gc');

const { open } = require('../dist/index.cjs');
const MAX_DB_SIZE = 256 * 1024 * 1024;
if (isMainThread) {
	var inspector = require('inspector');
	//  inspector.open(9331, null, true);debugger

	// The main thread

	let db = open({
		path: path.resolve(__dirname, './testdata'),
		maxDbs: 10,
		mapSize: MAX_DB_SIZE,
		maxReaders: 126,
		overlappingSync: true,
	});

	let incrementer = new BigInt64Array(1);
	let incrementerBuffer = db.getUserSharedBuffer('test', incrementer.buffer);
	incrementer = new BigInt64Array(incrementerBuffer);
	incrementer[0] = 10000n;

	var workerCount = Math.min(numCPUs * 2, 20);
	var value = { test: '48656c6c6f2c20776f726c6421' };
	var str =
		'this is supposed to be bigger than 16KB threshold for shared memory buffers';
	for (let i = 0; i < 9; i++) {
		str += str;
	}
	var bigValue = { test: str };
	// This will start as many workers as there are CPUs available.
	var workers = [];
	for (var i = 0; i < workerCount; i++) {
		var worker = new Worker(__filename);
		workers.push(worker);
	}

	var messages = [];
	workers.forEach(function (worker) {
		worker.on('message', function (msg) {
			messages.push(msg);
			// Once every worker has replied with a response for the value
			// we can exit the test.

			setTimeout(() => {
				worker.terminate();
			}, 100);
			if (messages.length === workerCount) {
				db.close();
				for (var i = 0; i < messages.length; i++) {
					assert(messages[i] === value.toString('hex'));
				}
				assert(incrementer[0] === 10000n + BigInt(workerCount) * 10n);
				console.log('done', threadId, incrementer[0]);
				//setTimeout(() =>
				//process.exit(0), 200);
			}
		});
	});

	let last;
	for (var i = 0; i < workers.length; i++) {
		last = db.put('key' + i, i % 2 === 1 ? bigValue : value);
	}

	last.then(() => {
		for (var i = 0; i < workers.length; i++) {
			var worker = workers[i];
			worker.postMessage({ key: 'key' + i });
		}
	});
} else {
	// The worker process
	let db = open({
		path: path.resolve(__dirname, './testdata'),
		maxDbs: 10,
		mapSize: MAX_DB_SIZE,
		maxReaders: 126,
		overlappingSync: true,
	});

	parentPort.on('message', async function (msg) {
		if (msg.key) {
			for (let i = 0; i < 10; i++) {
				let incrementer = new BigInt64Array(1);
				incrementer[0] = 1n; // should be ignored
				let incrementerBuffer = db.getUserSharedBuffer(
					'test',
					incrementer.buffer,
				);
				incrementer = new BigInt64Array(incrementerBuffer);
				Atomics.add(incrementer, 0, 1n);
				gc();
				await new Promise((resolve) => setTimeout(resolve, 100));
			}

			var value = db.get(msg.key);
			if (msg.key == 'key1' || msg.key == 'key3') {
				await db.put(msg.key, 'updated');
			}
			if (value === null) {
				parentPort.postMessage('');
			} else {
				parentPort.postMessage(value.toString('hex'));
			}
		}
	});
}