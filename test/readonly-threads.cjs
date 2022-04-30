var assert = require('assert');
const { Worker, isMainThread, parentPort, threadId } = require('worker_threads');
var path = require('path');
var numCPUs = require('os').cpus().length;

const { open } = require('../dist/index.cjs');
const MAX_DB_SIZE = 256 * 1024 * 1024;
if (isMainThread) {
  var inspector = require('inspector')
//  inspector.open(9331, null, true);debugger

  // The main thread

  let db = open({
    path: path.resolve(__dirname, './testdata'),
    maxDbs: 10,
    mapSize: MAX_DB_SIZE,
    maxReaders: 126,
    overlappingSync: true,
  });

  var workerCount = Math.min(numCPUs * 2, 20);
  var value = {test: '48656c6c6f2c20776f726c6421'};

  // This will start as many workers as there are CPUs available.
  var workers = [];
  for (var i = 0; i < workerCount; i++) {
    var worker = new Worker(__filename);
    workers.push(worker);
  }

  var messages = [];
  workers.forEach(function(worker) {
    worker.on('message', function(msg) {
      messages.push(msg);
      // Once every worker has replied with a response for the value
      // we can exit the test.

      setTimeout(() => {
        worker.terminate()
      }, 8000);
      if (messages.length === workerCount) {
        db.close();
        for (var i = 0; i < messages.length; i ++) {
          assert(messages[i] === value.toString('hex'));
        }
        console.log("done", threadId)
        //setTimeout(() =>
          //process.exit(0), 200);
      }
    });
  });

	for (var i = 0; i < workers.length; i++) {
		var worker = workers[i];
		worker.postMessage({key: 'key' + i});
	};
  

} else {
  // The worker process
  let db = open({
    path: path.resolve(__dirname, './testdata'),
    maxDbs: 10,
    mapSize: MAX_DB_SIZE,
    maxReaders: 126,
    overlappingSync: true,
  });


  parentPort.on('message', async function(msg) {
    if (msg.key) {
      var value = db.get(msg.key);
		let lastIterate = db.getRange().iterate()
		setInterval(() => {
			db.get(msg.key);
			let iterate = db.getRange().iterate();
			while(!lastIterate.next().done){}
			lastIterate = iterate;
		}, 1);
		setTimeout(() => {
			if (value === null) {
			parentPort.postMessage("");
			} else {
			parentPort.postMessage(value.toString('hex'));
			}
		}, 10000);
      
    }
  });
}
