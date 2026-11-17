// A commit listener reads a range from every database while the next batch has a transaction callback pending, and
// the environment is then closed. A cursor opened on the writer's transaction there is freed when that transaction
// commits, so closing it with the environment crashes the process.
const path = require('path');
const { open } = require('../dist/index.cjs');

const dir = path.resolve(
	__dirname,
	'./testdata-commit-listener',
	String(process.pid),
);
const hold = new Int32Array(new SharedArrayBuffer(4));

async function run() {
	const root = open({ path: dir, maxDbs: 40 });
	const dbs = [];
	for (let i = 0; i < 24; i++) {
		const db = root.openDB('db' + i);
		for (let key = 0; key < 5; key++) db.put(key, key);
		dbs.push(db);
	}
	await root.committed;
	let listening = true;
	const counts = [];
	root.on('aftercommit', () => {
		if (!listening) return;
		listening = false;
		for (const db of dbs) counts.push(Array.from(db.getRange({})).length);
	});
	const committed = root.put('committed', 1);
	await new Promise((resolve) => setImmediate(resolve)); // the put's batch has started
	const transacted = root.transaction(() => root.put('transacted', 1));
	Atomics.wait(hold, 0, 0, 50); // the put commits before this thread serves its writer
	await Promise.all([committed, transacted]);
	for (let i = 0; i < 20; i++) await root.put('later' + i, i);
	if (counts.length !== dbs.length || counts.some((count) => count !== 5))
		throw new Error('Listener read ' + counts);
	await root.close();
}

run().then(
	() => {
		require('fs').rmSync(dir, { recursive: true, force: true });
		console.log('done');
	},
	(error) => {
		console.error(error);
		process.exit(1);
	},
);
