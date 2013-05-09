
// Require the module
var lmdb = require('./src/build/Release/node-lmdb');

// Now you can use the module

// Print the version
console.log("Current lmdb version is", lmdb.version);
// Create new LMDB environment
var env = new lmdb.Env();
// Open the environment
env.open({
    // Path to the environment
    path: "./testdata",
    // Maximum number of databases
    maxDbs: 3
});
// Open database
var dbi = env.openDbi({
   name: "mydb1",
   create: true
});

// Begin transaction
var txn = env.beginTxn();

// Get data
var data = txn.get(dbi, "hello");
console.log(data);
txn.put(dbi, "hello", "hey!");

// Commit transaction
txn.commit();

// Close the database
dbi.close();
// Close the environment
env.close();

