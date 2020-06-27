'use strict';

var path = require('path');
var mkdirp = require('mkdirp');
var rimraf = require('rimraf');
var chai = require('chai');
var should = chai.should();
var spawn = require('child_process').spawn;

let { open } = require('..');

describe('lmdb-store', function() {
  var testDirPath = path.resolve(__dirname, './testdata.mdb');

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
    var db;
    before(function() {
      db = open(testDirPath, {
        name: 'mydb3',
        create: true,
        useVersions: true,
        compressionThreshold: 256,
      });
    });
    it('string', function(done) {
      db.put('key1', 'Hello world!').then(() => {
        var data = db.get('key1');
        data.should.equal('Hello world!');
        db.remove('key1').then(() => {
          var data2 = db.get('key1');
          should.equal(data2, undefined);
          done();
         });
      });
    });
  });
});
