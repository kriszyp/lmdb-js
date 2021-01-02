'use strict';
//var inspector = require('inspector')
//inspector.open(9330, null, true)

let path = require('path');
let mkdirp = require('mkdirp');
let rimraf = require('rimraf');
let chai = require('chai');
let should = chai.should();
let expect = chai.expect;
let spawn = require('child_process').spawn;

let { open, getLastVersion } = require('..');
import('./module.test.mjs')

describe('lmdb-store', function() {
  let testDirPath = path.resolve(__dirname, './testdata-ls');

  // just to make a reasonable sized chunk of data...
  function expand(str) {
    str = '(' + str + ')';
    str = str + str;
    str = str + str;
    str = str + str;
    str = str + str;
    str = str + str;
    return str;
  }
  before(function(done) {
    // cleanup previous test directory
    rimraf(testDirPath, function(err) {
      if (err) {
        return done(err);
      }
      done();
    });
  });
  let testIteration = 1
  describe.only('Basic use', basicTests({ compression: false }));
  describe('Basic use with encryption', basicTests({ compression: false, encryptionKey: 'Use this key to encrypt the data' }));
  //describe('Check encrypted data', basicTests({ compression: false, checkLast: true }));
  describe('Basic use with JSON', basicTests({ encoding: 'json' }));
  describe('Basic use with caching', basicTests({ cache: true }));
  function basicTests(options) { return function() {
    this.timeout(10000);
    let db, db2;
    before(function() {
      db = open(testDirPath + '/test-' + testIteration + '.mdb', Object.assign({
        name: 'mydb3',
        create: true,
        useVersions: true,
        compression: {
          threshold: 256,
        },
      }, options));
      testIteration++;
      if (!options.checkLast)
        db.clear();
      db2 = db.openDB(Object.assign({
        name: 'mydb4',
        create: true,
        dupSort: true,
      }));
      if (!options.checkLast)
        db2.clear();
    });
    if (options.checkLast) {
      it('encrypted data can not be accessed', function() {
        let data  = db.get('key1');
        console.log({data})
        data.should.deep.equal({foo: 1, bar: true})
      })
      return
    }
    it('query of keys', async function() {
      let keys = [
        Symbol.for('test'),
        false,
        true,
        -33,
        -1.1,
        3.3,
        5,
        [5,4],
        [5,55],
        'hello',
        ['hello', 3],
        ['hello', 'world'],
        [ 'uid', 'I-7l9ySkD-wAOULIjOEnb', 'Rwsu6gqOw8cqdCZG5_YNF' ],
        'z'
      ]
      for (let key of keys)
        await db.put(key, 3);
      let returnedKeys = []
      for (let { key, value } of db.getRange({
        start: Symbol.for('A')
      })) {
        returnedKeys.push(key)
      }
      keys.should.deep.equal(returnedKeys)
    });
    it('string', async function() {
      await db.put('key1', 'Hello world!');
      let data = db.get('key1');
      data.should.equal('Hello world!');
      await db.remove('key1')
      let data2 = db.get('key1');
      should.equal(data2, undefined);
    });
    it('string with version', async function() {
      await db.put('key1', 'Hello world!', 53252);
      let entry = db.getEntry('key1');
      entry.value.should.equal('Hello world!');
      entry.version.should.equal(53252);
      (await db.remove('key1', 33)).should.equal(false);
      entry = db.getEntry('key1');
      entry.value.should.equal('Hello world!');
      entry.version.should.equal(53252);
      (await db.remove('key1', 53252)).should.equal(true);
      entry = db.getEntry('key1');
      should.equal(entry, undefined);
    });
    it('string with version branching', async function() {
      await db.put('key1', 'Hello world!', 53252);
      let entry = db.getEntry('key1');
      entry.value.should.equal('Hello world!');
      entry.version.should.equal(53252);
      (await db.ifVersion('key1', 777, () => {
        db.put('newKey', 'test', 6);
        db2.put('keyB', 'test', 6);
      })).should.equal(false);
      should.equal(db.get('newKey'), undefined);
      should.equal(db2.get('keyB'), undefined);
      let result = (await db.ifVersion('key1', 53252, () => {
        db.put('newKey', 'test', 6);
        db2.put('keyB', 'test', 6);
      }))
      should.equal(db.get('newKey'), 'test')
      should.equal(db2.get('keyB'), 'test')
      should.equal(result, true);
      result = await db.ifNoExists('key1', () => {
        db.put('newKey', 'changed', 7);
      })
      should.equal(db.get('newKey'), 'test');
      should.equal(result, false);
      result = await db.ifNoExists('key-no-exist', () => {
        db.put('newKey', 'changed', 7);
      })
      should.equal(db.get('newKey'), 'changed')
      should.equal(result, true);
    });
    it('string with compression and versions', async function() {
      let str = expand('Hello world!')
      await db.put('key1', str, 53252);
      let entry = db.getEntry('key1');
      entry.value.should.equal(str);
      entry.version.should.equal(53252);
      (await db.remove('key1', 33)).should.equal(false);
      let data = db.get('key1');
      data.should.equal(str);
      (await db.remove('key1', 53252)).should.equal(true);
      data = db.get('key1');
      should.equal(data, undefined);
    });
    it('store objects', async function() {
      let dataIn = {foo: 3, bar: true}
      await db.put('key1',  dataIn);
      let dataOut = db.get('key1');
      dataOut.should.deep.equal(dataIn);
      db.removeSync('not-there').should.equal(false);
    });
    it.skip('trigger sync commit', async function() {
      let dataIn = {foo: 4, bar: false}
      db.immediateBatchThreshold = 1
      db.syncBatchThreshold = 1
      await db.put('key1',  dataIn);
      await db.put('key2',  dataIn);
      db.immediateBatchThreshold = 100000
      db.syncBatchThreshold = 1000000
      let dataOut = db.get('key1');
      dataOut.should.deep.equal(dataIn);
    });
    it('should iterate over query', async function() {
      let data1 = {foo: 1, bar: true}
      let data2 = {foo: 2, bar: false}
      db.put('key1',  data1);
      await db.put('key2',  data2);
      let count = 0
      for (let { key, value } of db.getRange({start:'key', end:'keyz'})) {
        count++
        switch(key) {
          case 'key1': data1.should.deep.equal(value); break;
          case 'key2': data2.should.deep.equal(value); break;
        }
      }
      if (count != 2)
        throw new Error('Not enough entries')
    });
    it('should iterate over dupsort query, with removal', async function() {
      let data1 = {foo: 1, bar: true}
      let data2 = {foo: 2, bar: false}
      let data3 = {foo: 3, bar: true}
      db2.put('key1',  data1);
      db2.put('key1',  data2);
      db2.put('key1',  data3);
      await db2.put('key2',  data3);
      let count = 0;
      for (let value of db2.getValues('key1')) {
        count++
        switch(count) {
          case 1: data1.should.deep.equal(value); break;
          case 2: data2.should.deep.equal(value); break;
          case 3: data3.should.deep.equal(value); break;
        }
      }
      count.should.equal(3);
      await db2.remove('key1',  data2);
      count = 0;
      for (let value of db2.getValues('key1')) {
        count++;
        switch(count) {
          case 1: data1.should.deep.equal(value); break;
          case 2: data3.should.deep.equal(value); break;
        }
      }
      count.should.equal(2)
      count = 0;
      for (let value of db2.getValues('key1', { reverse: true })) {
        count++;
        switch(count) {
          case 1: data3.should.deep.equal(value); break;
          case 2: data1.should.deep.equal(value); break;
        }
      }
      count.should.equal(2);

      count = 0;
      for (let value of db2.getValues('key0')) {
        count++;
      }
      count.should.equal(0);
    });
    it('should iterate over keys without duplicates', async function() {
      let lastKey
      for (let key of db2.getKeys({ start: 'k' })) {
        if (key == lastKey)
          throw new Error('duplicate key returned')
        lastKey = key
      }
    })
    it('invalid key', async function() {
      expect(() => db.get({ foo: 'bar' })).to.throw();
      //expect(() => db.put({ foo: 'bar' }, 'hello')).to.throw();
    });
    after(function(done) {
      db.get('key1');
      let iterator = db.getRange({})[Symbol.iterator]()
      setTimeout(() => {
        db.get('key1');
        // should have open read and cursor transactions
        db2.close();
        db.close();
        done()
      },10);
    });
  }}
  describe('uint32 keys', function() {
    this.timeout(10000);
    let db, db2;
    before(function() {
      db = open(testDirPath, {
        name: 'uint32',
        keyIsUint32: true,
        compression: true,
      });
    });
    it('write and read range', async function() {
      let lastPromise
      for (let i = 0; i < 10; i++) {
        lastPromise = db.put(i, 'value' + i);
      }
      await lastPromise
      let i = 0
      for (let { key, value } of db.getRange()) {
        key.should.equal(i);
        value.should.equal('value' + i);
        i++;
      }
      i = 0
      for (let { key, value } of db.getRange({ start: 0 })) {
        key.should.equal(i);
        value.should.equal('value' + i);
        i++;
      }
    });
    after(function() {
      db.close();
    });
  });
});
