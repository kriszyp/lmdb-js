import { open } from '../node-index.js';
import { parentPort, workerData } from 'worker_threads';
let db = open({
	name: 'mydb1',
	useVersions: true,
	path: workerData.path,
});
function getLock() {
	if (db.attemptLock(4, 1, getLock))
		parentPort.postMessage({ locked: true });
}
getLock();

parentPort.on('message', (event) => {
	if (event.unlock) {
		db.unlock(4, 1);
		parentPort.postMessage({ unlocked: true });
	}
	if (event.lock) getLock();
});
parentPort.postMessage({ started: true, hasLock: db.hasLock(4, 1) });
