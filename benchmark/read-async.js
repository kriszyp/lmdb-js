'use strict';
import { Worker, isMainThread, parentPort, threadId } from'worker_threads';
import { isMaster, fork } from 'cluster';
import inspector from 'inspector'
//inspector.open(9229, null, true);
debugger;
var testDirPath = new URL('./benchdata', import.meta.url).toString().slice(8);
import fs from 'fs';
import rimraf from 'rimraf';

import { open } from '../index.js';
import { nativeAddon } from '../native.js';
let { noop } = nativeAddon;
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
for (let i = 0; i < 14; i++) {
  bigString += bigString
}
//data.more = bigString
console.log(bigString.length)
var c = 0
let result

let start;
let outstanding = 0
let iteration = 1
function getAsync() {
  console.log('getAsync');
  outstanding++;
  store.getAsync((c += 357) % total, {}, function() {
    outstanding--;
  });
}

function setup() {
  console.log('opening', testDirPath)
  let rootStore = open(testDirPath, {
    //noMemInit: true,
    //pageSize: 0x4000,
    //compression: true,
    //noSync: true,
    //winMemoryPriority: 4,
    //eventTurnBatching: false,
    //overlappingSync: true,
  })
  store = rootStore.openDB('testing', {
    //create: true,
    sharedStructuresKey: 100000000,
    keyIsUint32: true,
    //compression: true,
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
(async function() {
  await setup();

  start = performance.now();
  for (let i = 0; i < 1000000; i++) {
    outstanding++;
    //if (i % 100 == 0)
      //console.log({outstanding})
    if (i % 1000 == 0)
      await new Promise(r => setImmediate(r));
    store.getAsync((i * 357) % total, {}, function (result) {
      outstanding--;
      //if (i % 100000 == 0)
        //console.log(i, result, outstanding)
      if (i == 999999) {
        console.log('done', outstanding, performance.now() - start)
      }
    });
  }
  console.log('finished enqueuing', outstanding, performance.now() - start)
})();