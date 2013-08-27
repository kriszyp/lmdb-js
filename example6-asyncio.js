
// Require the module
var lmdb = require('./build/Release/node-lmdb');

// Create new LMDB environment
var env = new lmdb.Env();
// Open the environment
env.open({
    path: "./testdata",
    maxDbs: 10,
    
    // These options prevent LMDB from automatically syncing on commit
    noMetaSync: true,
    noSync: true
});
// Open database
var dbi = env.openDbi({
   name: "mydb1",
   create: true
});

// Manipulate some data
var txn = env.beginTxn();
var data = txn.getString(dbi, "hello");
console.log(data);
if (data === null) {
    txn.putString(dbi, "hello", "Hello world!");
}
else {
    txn.del(dbi, "hello");
}
txn.commit();

// Manually sync the environment
env.sync(function(err) {
    if (err) {
        // There was an error
        console.log("error", err);
    }
    else {
        console.log("successful sync");
    }

    // Close the database
    dbi.close();
    // Close the environment
    env.close();
});

console.log("");
console.log("Run this example again to see the alterations on the database!");

