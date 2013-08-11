
var lmdb, env, dbi;

lmdb = require('./build/Release/node-lmdb');
env = new lmdb.Env();
env.open({
    // Path to the environment
    path: "./testdata",
    // Maximum number of databases
    maxDbs: 10
});

try {
    // If the database exists, drop it
    dbi = env.openDbi({
       name: "example5-dupsort",
       dupSort: true
    });
    dbi.drop();
}
catch (err) {}
dbi = env.openDbi({
   name: "example5-dupsort",
   create: true,
   dupSort: true,
   dupFixed: true,
   integerDup: true
});

console.log("ensured database is empty");

var printFunc = function(key, data) {
    console.log("---------->  key:", key);
    console.log("----------> data:", data);
}

var txn, cursor;

txn = env.beginTxn();
txn.putNumber(dbi, "hello", 1);
txn.putNumber(dbi, "apple", 2);
txn.putNumber(dbi, "orange", 3);
txn.putNumber(dbi, "apple", 4);
txn.putNumber(dbi, "hello", 5);
txn.putNumber(dbi, "appricot", 6);
txn.putNumber(dbi, "hello", 7);
txn.commit();

console.log("wrote test values");

txn = env.beginTxn({ readOnly: true });
cursor = new lmdb.Cursor(txn, dbi);

console.log("goToRange 'banana'");
cursor.goToRange("banana");
cursor.getCurrentNumber(printFunc);

console.log("goToNext");
cursor.goToNext();
cursor.getCurrentNumber(printFunc);

console.log("goToNext");
cursor.goToNext();
cursor.getCurrentNumber(printFunc);

console.log("goToNext");
cursor.goToNext();
cursor.getCurrentNumber(printFunc);

console.log("goToDup 'apple', 4");
cursor.goToDup("apple", 4);
cursor.getCurrentNumber(printFunc);

console.log("goToDupRange 'hello', 0");
cursor.goToDup("hello", 0);
cursor.getCurrentNumber(printFunc);

console.log("");
console.log("iterating through a duplicate key: if-do-while");

var key = "hello";

if (cursor.goToRange(key) === key) {
    do {
        cursor.getCurrentNumber(function(key, data) {
            // do something with data
            console.log(key, data);
        });
    } while (cursor.goToNextDup());
}

console.log("");
console.log("iterating through a duplicate key: for");

var key = "apple";

for (var found = (cursor.goToRange(key) === key); found; found = cursor.goToNextDup()) {
    cursor.getCurrentNumber(function(key, data) {
        // do something with data
        console.log(key, data);
    });
}

cursor.close();
txn.abort();
dbi.close();
env.close();

