
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
txn0.putString(dbi, "a", "Helló1");
txn0.putString(dbi, "b", "Hello2");
txn0.putNumber(dbi, "c", 43);
txn0.putBinary(dbi, "d", new Buffer("öüóőúéáű"));
txn0.putBoolean(dbi, "e", false);
txn0.putString(dbi, "f", "Hello6");
txn0.commit();
console.log("wrote initial values");

var data;
var printFunc = function(key, data) {
    console.log("-----", key + ":", data);
}

// Begin transaction
var txn = env.beginTxn();

// Create cursor
var cursor = new lmdb.Cursor(txn, dbi);

console.log("first (expected a)");
data = cursor.goToFirst();
console.log("----->", data);
data = cursor.getCurrentString(printFunc);
console.log("----->", data);

console.log("next (expected b)");
data = cursor.goToNext();
console.log("----->", data);
data = cursor.getCurrentString(printFunc);
console.log("----->", data);

console.log("next (expected c)");
data = cursor.goToNext();
console.log("----->", data);
data = cursor.getCurrentNumber(printFunc);
console.log("----->", data);

console.log("next (expected d)");
data = cursor.goToNext();
console.log("----->", data);
data = cursor.getCurrentBinary(printFunc);
console.log("----->", data);

console.log("prev (expected c)");
data = cursor.goToPrev();
console.log("----->", data);
data = cursor.getCurrentNumber(printFunc);
console.log("----->", data);

console.log("last (expected f)");
data = cursor.goToLast();
console.log("----->", data);
data = cursor.getCurrentString(printFunc);
console.log("----->", data);

console.log("prev (expected e)");
data = cursor.goToPrev();
console.log("----->", data);
data = cursor.getCurrentBoolean(printFunc);
console.log("----->", data);

console.log("go to key 'b' (expected b)");
data = cursor.goToKey('b');
console.log("----->", data);
data = cursor.getCurrentString(printFunc);
console.log("----->", data);

// Close cursor
cursor.close();

// Commit transaction
txn.commit();

dbi.close();
env.close();

