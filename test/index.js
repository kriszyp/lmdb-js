'use strict';

var path = require('path');
var mkdirp = require('mkdirp');
var rimraf = require('rimraf');
var chai = require('chai');
var fastFuture = require('fast-future');
var should = chai.should();

var lmdb = require('..');

describe('Node.js LMDB Bindings', function() {
  var testDirPath = path.resolve(__dirname, './testdata');
  before(function(done) {
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
  });
  it('will construct, open and close an environment', function() {
    var env = new lmdb.Env();
    env.open({
      path: testDirPath,
      maxDbs: 10
    });
    env.close.should.be.a('function');
    env.beginTxn.should.be.a('function');
    env.openDbi.should.be.a('function');
    env.sync.should.be.a('function');
    env.close();
  });
  describe('Basics', function() {
    var env;
    before(function() {
      env = new lmdb.Env();
      env.open({
	path: testDirPath,
	maxDbs: 10
      });
    });
    after(function() {
      env.close();
    });
    it('will open a database, begin a transaction and get/put/delete data', function() {
      var dbi = env.openDbi({
	name: 'mydb1',
	create: true
      });
      var txn = env.beginTxn();
      var data = txn.getString(dbi, 'hello');
      should.equal(data, null);
      txn.putString(dbi, 'hello', 'Hello world!');
      var data2 = txn.getString(dbi, 'hello');
      data2.should.equal('Hello world!');
      txn.del(dbi, 'hello');
      var data3 = txn.getString(dbi, 'hello');
      should.equal(data3, null);
      txn.commit();
      dbi.close();
    });
    it('will get statistics for a database', function() {
      var dbi = env.openDbi({
	name: 'mydb2',
	create: true
      });
      var txn = env.beginTxn();
      var stat = dbi.stat(txn);
      stat.pageSize.should.be.a('number');
      stat.treeDepth.should.be.a('number');
      stat.treeBranchPageCount.should.be.a('number');
      stat.treeLeafPageCount.should.be.a('number');
      stat.entryCount.should.be.a('number');
      txn.abort();
      dbi.close();
    });
  });
  describe('Data types', function() {
    var env;
    var dbi;
    var txn;
    before(function() {
      env = new lmdb.Env();
      env.open({
	path: testDirPath,
	maxDbs: 10
      });
      dbi = env.openDbi({
	name: 'mydb3',
	create: true
      });
      txn = env.beginTxn();
    });
    after(function() {
      txn.commit();
      dbi.close();
      env.close();
    });
    it('string', function() {
      txn.putString(dbi, 'key1', 'Hello world!');
      var data = txn.getString(dbi, 'key1');
      data.should.equal('Hello world!');
      txn.del(dbi, 'key1');
      var data2 = txn.getString(dbi, 'key1');
      should.equal(data2, null);
    });
    it('binary', function() {
      var buffer = new Buffer('48656c6c6f2c20776f726c6421', 'hex');
      txn.putBinary(dbi, 'key2', buffer);
      var data = txn.getBinary(dbi, 'key2');
      data.should.deep.equal(buffer);
      txn.del(dbi, 'key2');
      var data2 = txn.getBinary(dbi, 'key2');
      should.equal(data2, null);
    });
    it('number', function() {
      txn.putNumber(dbi, 'key3', 9007199254740991);
      var data = txn.getNumber(dbi, 'key3');
      data.should.equal(Math.pow(2, 53) - 1);
      txn.del(dbi, 'key3');
      var data2 = txn.getNumber(dbi, 'key3');
      should.equal(data2, null);
    });
    it('boolean', function() {
      txn.putBoolean(dbi, 'key4', true);
      var data = txn.getBoolean(dbi, 'key4');
      data.should.equal(true);
      txn.putBoolean(dbi, 'key5', false);
      var data2 = txn.getBoolean(dbi, 'key5');
      data2.should.equal(false);
      txn.del(dbi, 'key4');
      txn.del(dbi, 'key5');
      var data3 = txn.getBoolean(dbi, 'key4');
      var data4 = txn.getBoolean(dbi, 'key5');
      should.equal(data3, null);
      should.equal(data4, null);
    });
  });
  describe('Multiple transactions', function() {
    var env;
    var dbi;
    before(function() {
      env = new lmdb.Env();
      env.open({
	path: testDirPath,
	maxDbs: 10
      });
      dbi = env.openDbi({
	name: 'mydb4',
	create: true,
	keyIsUint32: true
      });
      var txn = env.beginTxn();
      txn.putString(dbi, 1, 'Hello1');
      txn.putString(dbi, 2, 'Hello2');
      txn.commit();
    });
    after(function() {
      dbi.close();
      env.close();
    });
    it('readonly transaction should not see uncommited changes', function() {
      var readTxn = env.beginTxn({readOnly: true});
      var data = readTxn.getString(dbi, 1);
      should.equal(data, 'Hello1');

      var writeTxn = env.beginTxn();
      writeTxn.putString(dbi, 1, 'Ha ha ha');

      var data2 = writeTxn.getString(dbi, 1);
      data2.should.equal('Ha ha ha');

      var data3 = readTxn.getString(dbi, 1);
      should.equal(data3, 'Hello1');

      writeTxn.commit();
      var data4 = readTxn.getString(dbi, 1);
      should.equal(data4, 'Hello1');

      readTxn.reset();
      readTxn.renew();
      var data5 = readTxn.getString(dbi, 1);
      should.equal(data5, 'Ha ha ha');
      readTxn.abort();
    });
    it('readonly transaction will throw if tries to write', function() {
      var readTxn = env.beginTxn({readOnly: true});
      (function() {
	readTxn.putString(dbi, 2, 'hööhh')
      }).should.throw('Permission denied');
      readTxn.abort();
    });
  });
  describe('Cursors', function() {
    this.timeout(10000);
    var env;
    var dbi;
    var total = 100000;
    before(function() {
      env = new lmdb.Env();
      env.open({
	path: testDirPath,
	maxDbs: 10,
	mapSize: 16 * 1024 * 1024 * 1024
      });
      dbi = env.openDbi({
	name: 'mydb5',
	create: true,
	dupSort: true,
	keyIsUint32: true
      });
      var txn = env.beginTxn();
      var c = 0;
      while(c < total) {
	var buffer = new Buffer(new Array(8));
	buffer.writeDoubleBE(c);
	txn.putBinary(dbi, c, buffer);
	c++;
      }
      txn.commit();
    });
    after(function() {
      dbi.close();
      env.close();
    });
    it('will move cursor over key/values', function() {
      var txn = env.beginTxn();
      var cursor = new lmdb.Cursor(txn, dbi);
      cursor.goToKey(40);
      cursor.getCurrentBinary(function(key, value) {
	key.should.equal(40);
	value.readDoubleBE().should.equal(40);
      });

      var values = [];
      cursor.goToKey(0);
      function iterator() {
	cursor.getCurrentBinary(function(key, value) {
	  value.readDoubleBE().should.equal(values.length);
	  values.push(value);
	});
	cursor.goToNext();
	if (values.length < total) {
	  fastFuture(iterator);
	}
      }
      cursor.close();
      txn.abort();
    });
    it('will first/last key', function() {
      var txn = env.beginTxn();
      var cursor = new lmdb.Cursor(txn, dbi);
      cursor.goToFirst();
      cursor.getCurrentBinary(function(key, value) {
	key.should.equal(0);
	value.readDoubleBE().should.equal(0);
      });
      cursor.goToLast();
      cursor.getCurrentBinary(function(key, value) {
	key.should.equal(total - 1);
	value.readDoubleBE().should.equal(total - 1);
      });
      cursor.close();
      txn.abort();
    });
  });
});
