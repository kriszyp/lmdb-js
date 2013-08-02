
var lmdb = require('./build/Release/node-lmdb');
var env = new lmdb.Env();
env.open({
    // Path to the environment
    path: "./testdata",
    // Maximum number of databases
    maxDbs: 10
});
var dbi = env.openDbi({
   name: "mydb4",
   create: true
});

// Write test values

var txn0 = env.beginTxn();
txn0.putString(dbi, "a", "Hello1");
txn0.putString(dbi, "b", "Hello2");
txn0.putString(dbi, "c", "Hello3");
txn0.putString(dbi, "d", "Hello4");
txn0.putString(dbi, "e", "Hello5");
txn0.putString(dbi, "f", "Hello6");
txn0.commit();
console.log("wrote initial values");

var data;

// Begin transaction
var txn = env.beginTxn();

// Create cursor
var cursor = new lmdb.Cursor(txn, dbi);

console.log("first");
data = cursor.goToFirst();
console.log("-----", data);

console.log("next");
data = cursor.goToNext();
console.log("-----", data);

console.log("next");
data = cursor.goToNext();
console.log("-----", data);

console.log("next");
data = cursor.goToNext();
console.log("-----", data);

console.log("prev");
data = cursor.goToPrev();
console.log("-----", data);

console.log("current");
data = cursor.getCurrent();
console.log("-----", data);

console.log("last");
data = cursor.goToLast();
console.log("-----", data);

console.log("prev");
data = cursor.goToPrev();
console.log("-----", data);

// Close cursor
cursor.close();

// Commit transaction
txn.commit();

dbi.close();
env.close();

