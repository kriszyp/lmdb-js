
/*
    Example that shows how to use node-lmdb with LARGE databases
*/

// Set things up

var lmdb = require('./build/Release/node-lmdb');
var fs = require('fs');

var env = new lmdb.Env();
env.open({ path: './testdata', mapSize: 16 * 1024 * 1024 * 1024 });
var dbi = env.openDbi({ name: 'test', create: true });

// See how much we can squeeze into the db

try {
    while (true) {
        for (var i = 0; i < 1000; i++) {
            var txn = env.beginTxn();
            txn.putString(dbi, randomString(128), randomString(512));
            txn.commit();
        }
        console.log('database size', getDbSize(), 'MB');
    }
}
catch (error) {
    console.log('database size', getDbSize(), 'MB');
    console.log('error is', error);
}

// Utility functions

function getDbSize () {
    return fs.statSync('./testdata/data.mdb').size / 1024 / 1024;
}

function randomString (length) {
    var result = '';
    while (length-- > 0) {
        result += String.fromCharCode(97 + Math.floor(Math.random() * 26));
    }
    return result;
}

