
// Require the module
var lmdb = require('./src/build/Release/node-lmdb');

// Now you can use the module

// Print the version
console.log("Current lmdb version is", lmdb.version);
// Create new LMDB environment
var env = new lmdb.Env();
// Set maximum number of databases
env.setMaxDbs(3);
// Open the environment
env.open("testdata");

// Begin transaction
var txn = new lmdb.Txn(env);
// Abort transaction
txn.abort();

// Close the environment
env.close();

