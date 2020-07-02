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
var total = 100000;

function cleanup(done) {
  // cleanup previous test directory
  rimraf(testDirPath, function(err) {
    if (err) {
      return done(err);
    }
    // setup clean directory
    mkdirp(testDirPath).then(() => {
      done();
    }, error => done(error));
  });
}

function setup() {
  env = new lmdb.Env();
  env.open({
    path: testDirPath,
    maxDbs: 10,
    mapSize: 1024 * 1024 * 1024
  });
  dbi = env.openDbi({
    name: 'benchmarks',
    create: true,
//    compressionThreshold: 1000,
  });

  var txn = env.beginTxn();
  var c = 0;
  let value = 'hello world!'
  for (let i = 0; i < 6; i++) {
    value += value
  }
  while(c < total) {
    var key = new Buffer(new Array(8));
    key.writeDoubleBE(c);
    keys.push(key.toString('hex'));
    txn.putUtf8(dbi, key.toString('hex'), 'hello world!');
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
  var data = txn.getUtf8(dbi, keys[getIndex()]);
}

function getStringUnsafe() {
  var data = txn.getStringUnsafe(dbi, keys[getIndex()]);
}

let cursor;

function cursorGoToNext() {
    let readed = 0;

    return () => {
        let c = cursor.goToNext();
        readed++;
        if (readed >= total) {
            c = cursor.goToRange(keys[0]);
            readed = 0; // reset to prevent goToRange on every loop
        }
    }
}

function cursorGoToNextgetCurrentString() {
    let readed = 0;
    return () => {
        const c = cursor.goToNext();
        readed++;
        if (readed >= total) {
            cursor.goToRange(keys[0]);
            readed = 0; // reset to prevent goToRange on every loop
        }
        const v = cursor.getCurrentUtf8();
    }
}
let b = Buffer.from('Hi there!');
function bufferToKeyValue() {
  if (lmdb.bufferToKeyValue(b) != 'Hi there!')
    throw new Error('wrong string')

}
function keyValueToBuffer() {
  if (!lmdb.keyValueToBuffer('Hi there!').equals(b))
    throw new Error('wrong string')

}

cleanup(function (err) {
    if (err) {
        throw err;
    }

    setup();

 //   suite.add('getBinary', getBinary);
    //suite.add('getBinaryUnsafe', getBinaryUnsafe);
    //suite.add('bufferToKeyValue', bufferToKeyValue)
    //suite.add('keyValueToBuffer', keyValueToBuffer)
    suite.add('getString', getString);
    //suite.add('getStringUnsafe', getStringUnsafe);
    //suite.add('cursorGoToNext', cursorGoToNext());
    suite.add('cursorGoToNextgetCurrentString', cursorGoToNextgetCurrentString());

    suite.on('start', function () {
        txn = env.beginTxn();
    });

    suite.on('cycle', function (event) {
        txn.abort();
        txn = env.beginTxn();
        if (cursor) cursor.close();
        cursor = new lmdb.Cursor(txn, dbi);
        console.log(String(event.target));
    });

    suite.on('complete', function () {
        txn.abort();
        dbi.close();
        env.close();
        if (cursor)
            cursor.close();
        console.log('Fastest is ' + this.filter('fastest').map('name'));
    });

    suite.run();

});