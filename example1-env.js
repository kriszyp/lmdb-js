
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
    setMaxDbs: 3
});
console.log("hah");
// Open database
var dbi = env.openDbi({
    name: "myDb1"
});

console.log("hah");
// Begin transaction
var txn = env.beginTxn();
// Abort transaction
txn.abort();

console.log("hah");
// Close the database
dbi.close();
console.log("hah");
// Close the environment
env.close();

