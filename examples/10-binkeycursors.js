
var lmdb = require('..');
var env = new lmdb.Env();
env.open({
    // Path to the environment
    path: "./testdata",
    // Maximum number of databases
    maxDbs: 10
});

// Ensure that the database is empty
var dbi = env.openDbi({
   name: "mydb10",
   create: true
});
dbi.drop();
dbi = env.openDbi({
   name: "mydb10",
   create: true
});

// Write test values

var txn0 = env.beginTxn();
txn0.putString(dbi, Buffer.from("a","utf8"), "Helló1");
txn0.putString(dbi, Buffer.from("b","utf8"), "Hello2");
txn0.putNumber(dbi, Buffer.from("c","utf8"), 43);
/* key 'd' is omitted intentionally */
txn0.putBinary(dbi, "e", Buffer.from("öüóőúéáű"));
txn0.putBoolean(dbi, "f", false);
txn0.putString(dbi, "g", "Hello6");
txn0.commit();
console.log("wrote initial values");

var printFunc = function(key, data) {
    console.log("----->  key:", key.toString(), " : ", JSON.stringify(key));
    console.log("-----> data:", data.toString(), " : ", JSON.stringify(data));
}

// Begin transaction
var txn = env.beginTxn();

// Create cursor
var cursor = new lmdb.Cursor(txn, dbi, { keyIsBuffer: true });

console.log("first (expected a)");
cursor.goToFirst();
cursor.getCurrentString(printFunc);

console.log("next (expected b)");
cursor.goToNext();
cursor.getCurrentString(printFunc);

console.log("next (expected c)");
cursor.goToNext();
cursor.getCurrentNumber(printFunc);


console.log("next (expected e)");
cursor.goToNext();
cursor.getCurrentBinary(printFunc);


console.log("prev (expected c)");
cursor.goToPrev();
cursor.getCurrentNumber(printFunc);


console.log("last (expected g)");
cursor.goToLast();
cursor.getCurrentString(printFunc);


console.log("prev (expected f)");
cursor.goToPrev();
cursor.getCurrentBoolean(printFunc);


console.log("go to key 'b' (expected b)");
cursor.goToKey(Buffer.from('b'));
cursor.getCurrentString(printFunc);


console.log("go to range 'd' (expected e)");
cursor.goToRange('d');
cursor.getCurrentBinary(printFunc);


console.log("del (expected f)");
cursor.del();
cursor.getCurrentBoolean(printFunc);

console.log("");
console.log("now iterating through all the keys");

for (var found = cursor.goToFirst(); found !== null; found = cursor.goToNext()) {
    console.log("-----> key:", found);
}

// Close cursor
cursor.close();

// Commit transaction
txn.commit();

dbi.close();
env.close();

