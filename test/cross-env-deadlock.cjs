// Two threads, two environments. Each thread queues an async transaction callback on one environment, so its native
// writer holds that environment's write lock while waiting for the thread, and then the thread synchronously writes to
// the other environment.
const {
	Worker,
	isMainThread,
	workerData,
	parentPort,
} = require('worker_threads');
const path = require('path');
const { open } = require('../dist/index.cjs');

const dir = isMainThread
	? path.resolve(__dirname, './testdata-cross-env', String(process.pid))
	: workerData.dir;
const barrier = isMainThread
	? new Int32Array(new SharedArrayBuffer(8))
	: workerData.barrier;
const role = isMainThread ? 0 : 1;

function arriveAndWait(index) {
	Atomics.add(barrier, index, 1);
	while (Atomics.load(barrier, index) < 2)
		Atomics.wait(barrier, index, Atomics.load(barrier, index), 10);
}

async function run() {
	const envs = [0, 1].map((i) =>
		open({
			path: path.join(dir, 'env' + i),
			overlappingSync: process.env.OVERLAPPING_SYNC === 'true',
		}),
	);
	const own = envs[role];
	const other = envs[1 - role];
	arriveAndWait(0);
	const asyncResult = own.transaction(() => {
		own.put('async', role);
		return 'async-' + role;
	});
	setImmediate(() => {
		// the writer started in the preceding immediate; give it time to take the lock and reach the callback
		Atomics.wait(barrier, 1, 0, 200);
		arriveAndWait(1);
		other.transactionSync(() => other.put('sync-' + role, role));
	});
	if ((await asyncResult) !== 'async-' + role)
		throw new Error('Wrong async result');
	await other.committed;
	if (own.get('async') !== role) throw new Error('Async write missing');
	if (other.get('sync-' + role) !== role) throw new Error('Sync write missing');
	await Promise.all(envs.map((env) => env.close()));
}

if (isMainThread) {
	const worker = new Worker(__filename, { workerData: { dir, barrier } });
	const workerDone = new Promise((resolve, reject) => {
		worker.on('message', resolve);
		worker.on('error', reject);
	});
	Promise.all([run(), workerDone]).then(
		() => {
			require('fs').rmSync(dir, { recursive: true, force: true });
			console.log('done');
		},
		(error) => {
			console.error(error);
			process.exit(1);
		},
	);
} else {
	run().then(() => parentPort.postMessage('done'));
}
