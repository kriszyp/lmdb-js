'use strict';

let path = require('path');
let mkdirp = require('mkdirp');
let rimraf = require('rimraf');
let chai = require('chai');
let should = chai.should();
let expect = chai.expect;
let spawn = require('child_process').spawn;

let { open, getLastVersion } = require('..');

describe('lmdb-store', function() {
  let testDirPath = path.resolve(__dirname, './testdata.mdb');

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
  describe('Basic use', function() {
    this.timeout(10000);
    let db, db2;
    before(function() {
      db = open(testDirPath, {
        name: 'mydb3',
        create: true,
        useVersions: true,
        compression: {
          threshold: 256,
        },
      });
      db2 = db.openDB({
        name: 'mydb4',
        create: true,
        compression: {
          threshold: 256,
        },
      });
    });
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
        'z'
      ]
      for (let key of keys)
        await db.put(key,  3);
      let returnedKeys = []
      for (let { key, value } of db.getRange({
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
      let data = db.get('key1');
      data.should.equal('Hello world!');
      getLastVersion().should.equal(53252);
      (await db.remove('key1', 33)).should.equal(false);
      data = db.get('key1');
      data.should.equal('Hello world!');
      (await db.remove('key1', 53252)).should.equal(true);
      data = db.get('key1');
      should.equal(data, undefined);
    });
    it('string with version branching', async function() {
      await db.put('key1', 'Hello world!', 53252);
      let data = db.get('key1');
      data.should.equal('Hello world!');
      getLastVersion().should.equal(53252);
      (await db.ifVersion('key1', 777, () => {
        db.put('newKey', 'test', 6);
        db2.put('keyB', 'test', 6);
      })).should.equal(false);
      should.equal(db.get('newKey'), undefined)
      should.equal(db2.get('keyB'), undefined)
      let result = (await db.ifVersion('key1', 53252, () => {
        db.put('newKey', 'test', 6);
        db2.put('keyB', 'test', 6);
      }))
      should.equal(db.get('newKey'), 'test')
      should.equal(db2.get('keyB'), 'test')
      should.equal(result, true);
    });
    it('string with compression and versions', async function() {
      let str = expand('Hello world!')
      await db.put('key1', str, 53252);
      let data = db.get('key1');
      data.should.equal(str);
      getLastVersion().should.equal(53252);
      (await db.remove('key1', 33)).should.equal(false);
      data = db.get('key1');
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
    it('invalid key', async function() {
      expect(() => db.get({ foo: 'bar' })).to.throw();
      //expect(() => db.put({ foo: 'bar' }, 'hello')).to.throw();
    });
  });
});
