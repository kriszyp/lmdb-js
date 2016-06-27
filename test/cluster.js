'use strict';

var assert = require('assert');
var cluster = require('cluster');
var path = require('path');
var numCPUs = require('os').cpus().length;

var async = require('async');
var lmdb = require('..');

if (cluster.isMaster) {

  // The master process

  var env = new lmdb.Env();
  env.open({
    path: path.resolve(__dirname, './testdata'),
    maxDbs: 10,
    mapSize: 268435456 * 4096,
    maxReaders: 126
  });

  var dbi = env.openDbi({
    name: 'cluster',
    create: true
  });

  var value = new Buffer('48656c6c6f2c20776f726c6421', 'hex');

  // This will start as many workers as there are CPUs available.
  var workers = [];
  for (var i = 0; i < numCPUs; i++) {
    var worker = cluster.fork();
    workers.push(worker);
  }

  var messages = [];

  // Because `openDbi` uses a write transaction and only one can be open in an
  // environment we need to start each worker individually. Each worker
  // can then simultaneously open read only transactions.
  var c = 0;
  function loadWorker(worker, next) {
    var txn = env.beginTxn();

    worker.on('message', function(msg) {
      messages.push(msg);
      // Once every worker has replied with a response for the value
      // we can exit the test.
      if (messages.length === numCPUs) {
        done();
      }
    });

    worker.send({start: true}, function() {
      // We will write at the same time that each worker has a read-only
      // transaction open.
      txn.putBinary(dbi, 'key' + c, value);
      txn.commit();
      worker.send({key: 'key' + c});
      next();
    });

    c++;
  }

  async.eachSeries(workers, loadWorker, function(err) {
    if (err) {
      throw err;
    }
  });

  function done() {
    dbi.close();
    env.close();
    for (var i = 0; i < messages.length; i ++) {
      assert(messages[i] === value.toString('hex'));
    }
    process.exit(0);
  }

} else {

  // The worker process

  var env = new lmdb.Env();
  env.open({
    path: path.resolve(__dirname, './testdata'),
    maxDbs: 10,
    mapSize: 268435456 * 4096,
    maxReaders: 126
  });
  var txn;
  var dbx;

  function start() {
    dbi = env.openDbi({
      name: 'cluster'
    });
    txn = env.beginTxn({readOnly: true});
  }

  function get(key) {
    var value = txn.getBinary(dbi, key);
    process.send(value.toString('hex'));
  }

  process.on('message', function(msg) {
    if (msg.start) {
      start();
    } else if (msg.key) {
      get(msg.key);
    }
  });

}
