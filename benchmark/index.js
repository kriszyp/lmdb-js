'use strict';

var crypto = require('crypto');
var path = require('path');
var testDirPath = path.resolve(__dirname, './benchdata');

var rimraf = require('rimraf');
var mkdirp = require('mkdirp');
var benchmark = require('benchmark');
var suite = new benchmark.Suite();

var lmdb = require('..');

var env;
var dbi;
var keys = [];
var total = 1000000;

function cleanup(done) {
  // cleanup previous test directory
  rimraf(testDirPath, function(err) {
    if (err) {
      return done(err);
    }
    // setup clean directory
    mkdirp(testDirPath, function(err) {
      if (err) {
        return done(err);
      }
      done();
    });
  });
}

function setup() {
  env = new lmdb.Env();
  env.open({
    path: testDirPath,
    maxDbs: 10,
    mapSize: 16 * 1024 * 1024 * 1024
  });
  dbi = env.openDbi({
    name: 'benchmarks',
    create: true
  });

  var txn = env.beginTxn();
  var c = 0;
  while(c < total) {
    var key = new Buffer(new Array(8));
    key.writeDoubleBE(c);
    keys.push(key.toString('hex'));
    txn.putBinary(dbi, key.toString('hex'), crypto.randomBytes(32));
    c++;
  }
  txn.commit();
}

var txn;
var c = 0;

function getIndex() {
  if (c < total - 1) {
    c++;
  } else {
    c = 0;
  }
  return c;
}

function getBinary() {
  var data = txn.getBinary(dbi, keys[getIndex()]);
}

function getBinaryUnsafe() {
  var data = txn.getBinaryUnsafe(dbi, keys[getIndex()]);
}

function getString() {
  var data = txn.getString(dbi, keys[getIndex()]);
}

function getStringUnsafe() {
  var data = txn.getStringUnsafe(dbi, keys[getIndex()]);
}

cleanup(function(err) {
  if (err) {
    throw err;
  }

  setup();

  suite.add('getBinary', getBinary);
  suite.add('getBinaryUnsafe', getBinaryUnsafe);
  suite.add('getString', getString);
  suite.add('getStringUnsafe', getStringUnsafe);

  suite.on('start', function() {
    txn = env.beginTxn();
  });

  suite.on('cycle', function(event) {
    txn.abort();
    txn = env.beginTxn();
    console.log(String(event.target));
  });

  suite.on('complete', function () {
    txn.abort();
    dbi.close();
    env.close();
    console.log('Fastest is ' + this.filter('fastest').map('name'));
  });

  suite.run();

});
