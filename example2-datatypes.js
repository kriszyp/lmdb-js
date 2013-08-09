
var lmdb = require('./build/Release/node-lmdb');
var env = new lmdb.Env();
env.open({
    // Path to the environment
    path: "./testdata",
    // Maximum number of databases
    maxDbs: 10
});
var dbi = env.openDbi({
   name: "mydb2",
   create: true
});

// Create transaction
var txn = env.beginTxn();

// Example for getting/putting/deleting string data
// ----------
var stringData = txn.getString(dbi, "key1");
// Print the string
console.log("string data: ", stringData);
// Toggle the value
if (stringData === null)
    txn.putString(dbi, "key1", "Hello world!");
else
    txn.del(dbi, "key1");

// Example for getting/putting/deleting binary data
// ----------
var binaryData = txn.getBinary(dbi, "key2");
// Print the string representation of the binary
console.log("binary data: ", binaryData ? binaryData.toString() : null);
// Toggle the value
if (stringData === null) {
    var buffer = new Buffer("Hey my friend");
    txn.putBinary(dbi, "key2", buffer);
}
else {
    txn.del(dbi, "key2");
}

// Example for getting/putting/deleting number data
// ----------
var numberData = txn.getNumber(dbi, "key3");
// Print the number
console.log("number data: ", numberData);
// Toggle the value
if (numberData === null)
    txn.putNumber(dbi, "key3", 42);
else
    txn.del(dbi, "key3");

// Example for getting/putting/deleting boolean data
// ----------
var booleanData = txn.getBoolean(dbi, "key4");
// Print the boolean
console.log("boolean data: ", booleanData);
// Toggle the value
if (booleanData === null)
    txn.putBoolean(dbi, "key4", true);
else
    txn.del(dbi, "key4");

// Example for using integer key
// ----------
var data = txn.getString(dbi, "key5");
console.log("integer key value: ", data);
if (data === null)
    txn.putString(dbi, "key5", "Hello worllld!");
else
    txn.del(dbi, "key5");

console.log("");
console.log("Run this example again to see the alterations on the database!");

// Commit transaction
txn.commit();

dbi.close();
env.close();

