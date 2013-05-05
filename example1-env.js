
// Require the module
var lmdb = require('./src/build/Release/node-lmdb');

// Use the module

// Create new LMDB environment
var env = new lmdb.LmdbEnv();
// Set maximum number of databases
env.setMaxDbs(3);
// Open the environment
env.open("testdata");
// Close the environment
env.close();
