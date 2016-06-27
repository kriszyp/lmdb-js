var lmdb = require('..');
var env = new lmdb.Env();
env.open({
  // Path to the environment
  path: "./testdata",
  // Maximum number of databases
  maxDbs: 10
});

function createTestDb(dbName) {
  // Ensure that the database is empty
  var dbi = env.openDbi({
    name: dbName,
    create: true
  });
  dbi.drop();
  dbi = env.openDbi({
    name: dbName,
    create: true
  });

  // Write test values

  var txn0 = env.beginTxn();
  txn0.putString(dbi, "a", "Helló1");
  txn0.putString(dbi, "b", "Hello2");
  txn0.putNumber(dbi, "c", 43);
  /* key 'd' is omitted intentionally */
  txn0.putBinary(dbi, "e", new Buffer("öüóőúéáű"));
  txn0.putBoolean(dbi, "f", false);
  txn0.putString(dbi, "g", "Hello6");
  txn0.commit();
  console.log("wrote initial values");
  dbi.close()
}

createTestDb("mydb8.1");
createTestDb("mydb8.2");

var printFunc = function (key, data) {
  console.log("----->  key:", key);
  console.log("-----> data:", data);
}

//Open DB1
var dbi1 = env.openDbi({
  name: "mydb8.1"
});

// Begin shared readOnly transaction
var txn = env.beginTxn({readOnly: true});

// Create cursor for DB1
var cursor1 = new lmdb.Cursor(txn, dbi1);

console.log("cursor1 - first (expected a)");
cursor1.goToFirst();
cursor1.getCurrentString(printFunc);

console.log("cursor1 - next (expected b)");
cursor1.goToNext();
cursor1.getCurrentString(printFunc);


//Open DB2
var dbi2 = env.openDbi({
  name: "mydb8.2"
});

//txn does not know about dbi2 yet, opening a cursor to it will fail with "Error: Invalid argument"

//Reset the transaction to make it aware of dbi2
txn.reset()
//Renew the transaction to keep cursor1 valid, without this calls on cursor1 will fail
txn.renew()

// Create cursor for DB2
var cursor2 = new lmdb.Cursor(txn, dbi2);

console.log("cursor2 - first (expected a)");
cursor2.goToFirst();
cursor2.getCurrentString(printFunc);

console.log("cursor2 - next (expected b)");
cursor2.goToNext();
cursor2.getCurrentString(printFunc);


//cursor1 still is at its old position and reads the expected values 
console.log("cursor1 - next (expected c)");
cursor1.goToNext();
cursor1.getCurrentNumber(printFunc);

console.log("cursor1 - next (expected e)");
cursor1.goToNext();
cursor1.getCurrentBinary(printFunc);

// Randomly reading on different cursors
console.log("cursor2 - next (expected c)");
cursor2.goToNext();
cursor2.getCurrentNumber(printFunc);

console.log("cursor2 - next (expected e)");
cursor2.goToNext();
cursor2.getCurrentBinary(printFunc);

console.log("cursor1 - prev (expected c)");
cursor1.goToPrev();
cursor1.getCurrentNumber(printFunc);

console.log("cursor1 - last (expected g)");
cursor1.goToLast();
cursor1.getCurrentString(printFunc);

console.log("cursor2 - prev (expected c)");
cursor2.goToPrev();
cursor2.getCurrentNumber(printFunc);

console.log("cursor2 - last (expected g)");
cursor2.goToLast();
cursor2.getCurrentString(printFunc);


console.log("");
console.log("cursor1 - now iterating through all the keys");

for (var found = cursor1.goToFirst(); found; found = cursor1.goToNext()) {
  console.log("-----> key:", found);
}

console.log("");
console.log("cursor2 - now iterating through all the keys");

for (var found = cursor2.goToFirst(); found; found = cursor2.goToNext()) {
  console.log("-----> key:", found);
}

// Close cursors
cursor1.close();
cursor2.close();

// Commit transaction
txn.commit();

dbi1.close();
dbi2.close();

env.close();

