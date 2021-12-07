var assert = require('assert');
const { Worker, isMainThread, parentPort } = require('worker_threads');
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
    encoding: 'binary',
  });

  var workerCount = Math.min(numCPUs * 2, 20);
  var value = Buffer.from('48656c6c6f2c20776f726c6421', 'hex');

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
      if (messages.length === workerCount) {
        db.close();
        for (var i = 0; i < messages.length; i ++) {
          assert(messages[i] === value.toString('hex'));
        }
        process.exit(0);
      }
    });
  });

  let last
  for (var i = 0; i < workers.length; i++) {
    last = db.put('key' + i, value);
  }

  last.then(() => {
    for (var i = 0; i < workers.length; i++) {
      var worker = workers[i];
      worker.postMessage({key: 'key' + i});
    };
  });

} else {

  // The worker process
  let db = open({
    path: path.resolve(__dirname, './testdata'),
    maxDbs: 10,
    mapSize: MAX_DB_SIZE,
    maxReaders: 126
  });


  process.on('message', async function(msg) {
    if (msg.key) {
      var value = db.get(msg.key);
      if (msg.key == 'key1')
        await db.put(msg.key, 'updated');
      if (value === null) {
        parentPort.postMessage("");
      } else {
        parentPort.postMessage(value.toString('hex'));
      }
      
    }
  });

}
