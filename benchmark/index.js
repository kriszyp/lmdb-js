'use strict';
var inspector = require('inspector')
//inspector.open(9330, null, true)

var crypto = require('crypto');
var path = require('path');
var testDirPath = path.resolve(__dirname, './benchdata');

var fs =require('fs');
var rimraf = require('rimraf');
var mkdirp = require('mkdirp');
var benchmark = require('benchmark');
var suite = new benchmark.Suite();

const { open } = require('..');

var env;
var dbi;
var keys = [];
var total = 10000;
var store;

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
  store = open(testDirPath, {
    sharedStructuresKey: Buffer.from([ 2 ]),
    compressed: true,
  })
  let lastPromise
  for (let i = 0; i < total; i++) {
    lastPromise = store.put(i, {
      name: 'test',
      something: 'test2',
      flag: true,
      foo: 32,
      bar: 55
    })
  }
  return lastPromise.then(() => {
    console.log('all committed');
  })
}

var txn;
var c = 0;
var k = Buffer.from([2,3])
let result

function getIndex() {
  if (c < total - 1) {
    c++;
  } else {
    c = 0;
  }
  return c;
}

function getData() {
  
  result = store.get(getIndex())
}

cleanup(async function (err) {
    if (err) {
        throw err;
    }

    await setup();

    suite.add('get', getData);
    suite.on('cycle', function (event) {
      console.log('last result', result)
      console.log(String(event.target));
    });
    suite.on('complete', function () {
        console.log('Fastest is ' + this.filter('fastest').map('name'));
    });

    suite.run();

});