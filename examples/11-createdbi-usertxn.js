
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

var txn1 = env.beginTxn();
var dbi = env.openDbi({
name: 'dbUsingUserSuppliedTxn',
    create: true,
    txn: txn1
});
txn1.putString(dbi, 'hello', 'world');
txn1.commit();

var txn2 = env.beginTxn({ readOnly: true });
var str = txn2.getString(dbi, 'hello');
txn2.abort();
console.log(str);

var txn3 = env.beginTxn();
dbi.drop({ txn: txn3 });
txn3.commit();

console.log("dbi dropped");

var txn4 = env.beginTxn({ readOnly: true });
try {
    dbi = env.openDbi({
    name: 'dbUsingUserSuppliedTxn',
        create: false,
        txn: txn4
    });
}
catch (err) {
    if (err.message.indexOf("MDB_NOTFOUND") >= 0) {
        console.log("dbi not found anymore, because we dropped it");
    }
    else {
        console.log(err);
    }
}
txn4.abort();

// Close the environment
env.close();

