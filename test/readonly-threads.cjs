var assert = require('assert');
const { Worker, isMainThread, parentPort, threadId } = require('worker_threads');
var path = require('path');
var numCPUs = require('os').cpus().length;

const { open } = require('../dist/index.cjs');
if (isMainThread) {
	var inspector = require('inspector')
//	inspector.open(9331, null, true);debugger

	// The main thread

	var workerCount = Math.min(numCPUs * 2, 20);
	console.log({workerCount})
	var value = {test: '48656c6c6f2c20776f726c6421'};

	// This will start as many workers as there are CPUs available.
	let messages = [];
	let iterations = 100;
	function startWorker() {
		if (iterations-- <= 0)
			return;
		var worker = new Worker(__filename);
		worker.on('message', function(msg) {
			messages.push(msg);
			// Once every worker has replied with a response for the value
			// we can exit the test.

			setTimeout(() => {
				worker.terminate();
				startWorker();
			}, 20);
			if (messages.length === iterations) {
				console.log("done", threadId)
			}
		});
		worker.postMessage({key: 'key' + i});
	}
	for (var i = 0; i < workerCount; i++) {
		startWorker();
	}

} else {
	// The worker process
	let db = open({
		path: path.resolve(__dirname, './testdata/' + Math.round(Math.random() * 10) + '.mdb'),
		maxDbs: 10,
		maxReaders: 126,
		overlappingSync: true,
	});

	parentPort.on('message', async function(msg) {
		if (msg.key) {
			var value = db.get(msg.key);
		let lastIterate = db.getRange().iterate()
		let interval = setInterval(() => {
			db.get(msg.key);
			let iterate = db.getRange().iterate();
			while(!lastIterate.next().done){}
			lastIterate = iterate;
		}, 1);
		setTimeout(() => {
			clearInterval(interval)
			db.close();
			parentPort.postMessage("");
		}, 10);
			
		}
	});
}
