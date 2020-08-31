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
let data = {
  name: 'test',
  greeting: 'Hello, World!',
  flag: true,
  littleNum: 3,
  biggerNum: 32254435,
  decimal:1.332232,
  bigDecimal: 3.5522E102,
  negative: -54,
  aNull: null,
  more: 'another string',
}
function setup() {
  store = open(testDirPath, {
    sharedStructuresKey: Symbol.for('structures'),
  })
  let lastPromise
  for (let i = 0; i < total; i++) {
    lastPromise = store.put(i, data)
  }
  return lastPromise.then(() => {
    console.log('all committed');
  })
}

var txn;
var c = 0;
var k = Buffer.from([2,3])
let result

function setData(deferred) {
  result = store.put((c += 357) % total, data)
  if (c % 1500 == 0) {
      setImmediate(() => deferred.resolve(), 0)
  } else
    deferred.resolve()
}


function getData() {
  result = store.get((c += 357) % total)
}
let jsonBuffer = JSON.stringify(data)
function plainJSON() {
  result = JSON.parse(jsonBuffer)
}


cleanup(async function (err) {
    if (err) {
        throw err;
    }
debugger
    await setup();
    suite.add('put', {
      defer: true,
      fn: setData
    });
    suite.add('get', getData);
    suite.add('plainJSON', plainJSON);
    suite.on('cycle', function (event) {
      console.log('last result', result)
      if (result.then) {
        let start = Date.now()
        result.then(() => {
          console.log('last commit took ' + (Date.now() - start) + 'ms')
        })
      }
      console.log(String(event.target));
    });
    suite.on('complete', function () {
        console.log('Fastest is ' + this.filter('fastest').map('name'));
    });

    suite.run({ async: true });

});
