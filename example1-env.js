
// Require the module
var lmdb = require('./src/build/Release/node-lmdb');

// Use the module

// Print the version
console.log(lmdb.version);
// Create new LMDB environment
var env = new lmdb.Env();
// Set maximum number of databases
env.setMaxDbs(3);
// Open the environment
env.open("testdata");
// Close the environment
env.close();

