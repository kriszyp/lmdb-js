
// Created as an example for https://github.com/Venemo/node-lmdb/issues/99
// Demonstrates how to create a Dbi from a user-created write transaction.

// Require the module
var lmdb = require('..');
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

var txn = env.beginTxn();
var dbi = env.openDbi({
name: 'dbUsingUserSuppliedTxn',
    create: true,
    txn: txn
});
txn.putString(dbi, 'hello', 'world');
txn.commit();

var txn2 = env.beginTxn({ readOnly: true });
var str = txn2.getString(dbi, 'hello');
txn2.abort();
console.log(str);

// Close the database
dbi.close();
// Close the environment
env.close();
