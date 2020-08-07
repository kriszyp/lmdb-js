'use strict';

let path = require('path');
let mkdirp = require('mkdirp');
let rimraf = require('rimraf');
let chai = require('chai');
let should = chai.should();
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
    let db;
    before(function() {
      db = open(testDirPath, {
        name: 'mydb3',
        create: true,
        useVersions: true,
        compression: {
          threshold: 256,
        },
      });
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
  });
});
