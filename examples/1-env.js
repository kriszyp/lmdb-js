
// Require the module
var lmdb = require('./build/Release/node-lmdb');
// Now you can use the module

// Print the version
console.log("Current lmdb version is", lmdb.version);
// Create new LMDB environment
var env = new lmdb.Env();
// Open the environment
env.open({
    // Path to the environment
    // IMPORTANT: you will get an error if the directory doesn't exist!
    path: "./testdata",
    // Maximum number of databases
    maxDbs: 10
});
// Open database
var dbi = env.openDbi({
   name: "mydb1",
   create: true
});

// Begin transaction
var txn = env.beginTxn();

// Get data
var data = txn.getString(dbi, "hello");
console.log(data);

var stat = dbi.stat(txn);
console.log("\ndatabase statistics:");
console.dir(stat);

if (data === null) {
    // Put data
    txn.putString(dbi, "hello", "Hello world!");
}
else {
    // Delete data
    txn.del(dbi, "hello");
}

console.log("");
console.log("Run this example again to see the alterations on the database!");

// Commit transaction
txn.commit();

// Close the database
dbi.close();
// Close the environment
env.close();
