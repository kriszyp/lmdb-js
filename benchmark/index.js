'use strict';
import { Worker, isMainThread, parentPort, threadId } from'worker_threads';
import { isMaster, fork } from 'cluster';
import inspector from 'inspector'

var testDirPath = new URL('./benchdata', import.meta.url).toString().slice(8);
import fs from 'fs';
import rimraf from 'rimraf';
import benchmark from 'benchmark';
var suite = new benchmark.Suite();

import { open } from '../node-index.js';
var env;
var dbi;
var keys = [];
var total = 100;
var store
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
  more: 'string',
}
let bigString = 'big'
for (let i = 0; i < 10; i++) {
  bigString += bigString
}
//data.more = bigString
var c = 0
let result

let outstanding = 0
let iteration = 1
function setData(deferred) {
/*  result = store.transactionAsync(() => {
    for (let j = 0;j<100; j++)
      store.put((c += 357) % total, data)
  })*/
  let key = (c += 357)
  result = store.put(key, data)
  /*if (key % 2 == 0)
    result = store.put(key, data)
  else
    result = store.transactionAsync(() => store.put(key, data))*/
  if (iteration++ % 1000 == 0) {
    setImmediate(() => lastResult.then(() => {
      deferred.resolve()
    }))
    lastResult = result
  } else
    deferred.resolve()
}
function batchData(deferred) {
  result = store.batch(() => {
    for (let i = 0; i < 10; i++) {
      let key = (c += 357) % total
      store.put(key, data)
    }
  })
}
let lastResult
function batchDataAdd(deferred) {
  outstanding++
  result = store.batch(() => {
    for (let i = 0; i < 10; i++) {
      let key = (c += 357)
      store.put(key, data)
    }
  }).then(() => {
    outstanding--
  })
  if (outstanding < 500) {
    deferred.resolve()
  } else if (outstanding < 10000) {
      setImmediate(() => {
        deferred.resolve()
      })
  } else {
    console.log('delaying')
    setTimeout(() => deferred.resolve(), outstanding >> 3)
  }
}

function syncTxn() {
  store.transactionSync(() => {
    for (let j = 0;j<100; j++)
      store.put((c += 357), bigString)
  })
}
  
function getData() {
  result = store.get((c += 357) % total)
}
function getBinary() {
  result = store.getBinary((c += 357) % total)
}
function getBinaryFast() {
  result = store.getBinaryFast((c += 357) % total)
}
let a = Buffer.from('this id\0\0\0\0\0')
let b = Buffer.from('mmmmmmore text')
//b = b.subarray(2,b.length)
let b2 = Buffer.from('the similar key')
let b3 = Buffer.from('this is very similar')
function keyComparison() {
  try {
  result = store.db.compareKeys(a, b2)
}catch(error) { console.log(error)}
}
function getRange() {
  let start = (c += 357) % total
  let i = 0
  for (let entry of store.getRange({
    start,  
    end: start + 10
  })) {
    i++
  }
}
let jsonBuffer = JSON.stringify(data)
function plainJSON() {
  result = JSON.parse(jsonBuffer)
}

if (isMainThread && isMaster) {
try{
  //inspector.open(9330, null, true); //debugger
  //debugger
} catch(error) {}

function cleanup(done) {
  // cleanup previous test directory
  rimraf(testDirPath, function(err) {
    if (err) {
      return done(err);
    }
    // setup clean directory
    fs.mkdirSync(testDirPath, { recursive: true });
    done();
  });
}
function setup() {
  console.log('opening', testDirPath)
  let rootStore = open(testDirPath, {
    noMemInit: true,
    //noSync: true,
    //winMemoryPriority: 4,
    //eventTurnBatching: false,
    //overlappingSync: true,
  })
  store = rootStore.openDB('testing', {
    create: true,
    sharedStructuresKey: 100000000,
    keyIsUint32: true,
  })
  let lastPromise
  for (let i = 0; i < total; i++) {
    lastPromise = store.put(i, data)
  }
  return lastPromise?.then(() => {
    console.log('setup completed');
  })
}
var txn;

cleanup(async function (err) {
    if (err) {
        throw err;
    }
    await setup();
    //suite.add('compare keys', keyComparison);
    //suite.add('syncTxn', syncTxn);
    suite.add('getRange', getRange);
    suite.add('setData', {
      defer: true,
      fn: setData
    });
    /*suite.add('put-batch', {
      defer: true,
      fn: batchDataAdd
    });*/
    suite.add('get', getData);/*
    suite.add('plainJSON', plainJSON);
    suite.add('getBinary', getBinary);*/
    suite.add('getBinaryFast', getBinaryFast);
    suite.on('cycle', function (event) {
      console.log({result})
      if (result && result.then) {
        let start = Date.now()
        result.then(() => {
          console.log('last commit took ' + (Date.now() - start) + 'ms')
        })
      }
      console.log(String(event.target));
    });
    suite.on('complete', async function () {
        console.log('Fastest is ' + this.filter('fastest').map('name'));
        return
        var numCPUs = require('os').cpus().length;
        console.log('Test opening/closing threads ' + numCPUs + ' threads');
        for (var i = 0; i < numCPUs; i++) {
          var worker = new Worker(__filename);
          await new Promise(r => setTimeout(r,30));
          worker.terminate();
          if ((i % 2) == 0)
            await new Promise(r => setTimeout(r,30));
          //var worker = fork();
        }
        console.log('Now will run benchmark across ' + numCPUs + ' threads');
        for (var i = 0; i < numCPUs; i++) {
          var worker = new Worker(__filename);

          //var worker = fork();
        }
    });

    suite.run({ async: true });

});
} else {
  let rootStore = open(testDirPath, {
    noMemInit: true,
    //winMemoryPriority: 4,
  })
  store = rootStore.openDB('testing', {
    sharedStructuresKey: 100000000,
    keysUse32LE: true,    
  })

  // other threads
    suite.add('put', {
      defer: true,
      fn: setData
    });
    suite.add('get', getData);
    suite.add('getBinaryFast', getBinaryFast);
    suite.on('cycle', function (event) {
      if (result && result.then) {
        let start = Date.now()
        result.then(() => {
          console.log('last commit took ' + (Date.now() - start) + 'ms')
        })
      }
      console.log(String(event.target));
    });
    suite.run({ async: true });

}
