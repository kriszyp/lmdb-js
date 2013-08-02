
var lmdb = require('./build/Release/node-lmdb');
var env = new lmdb.Env();
env.open({
    // Path to the environment
    path: "./testdata",
    // Maximum number of databases
    maxDbs: 10
});
var dbi = env.openDbi({
   name: "mydb4",
   create: true
});



dbi.close();
env.close();

