
var lmdb = require('./build/Release/node-lmdb');
var env = new lmdb.Env();
env.open({
    // Path to the environment
    path: "./testdata",
    // Maximum number of databases
    maxDbs: 10
});
var dbi = env.openDbi({
   name: "mydb3",
   create: true,
   keyIsUint32: true
});

var data;

// Write values

var txn0 = env.beginTxn();
txn0.putString(dbi, 1, "Hello1");
txn0.putString(dbi, 2, "Hello2");
txn0.commit();
console.log("wrote initial values");

// Now mess around with transactions

var txn1 = env.beginTxn({ readOnly: true });
console.log("txn1: started (read only)");
data = txn1.getString(dbi, 1);
console.log("-----", "txn1", 1, data);

var txn2 = env.beginTxn();
console.log("txn2: started");
txn2.putString(dbi, 1, "Ha ha ha");
console.log("txn2: put other value to key 1");

// txn2 sees the new value immediately
data = txn2.getString(dbi, 1);
console.log("-----", "txn2", 1, data);

// txn1 still sees the old value
data = txn1.getString(dbi, 1);
console.log("-----", "txn1", 1, data);

txn2.commit();
console.log("txn2: committed");

// txn1 still sees the old value!
data = txn1.getString(dbi, 1);
console.log("-----", "txn1", 1, data);

txn1.reset();
txn1.renew();
console.log("rxn1: reset+renewed");

// now txn1 sees the new value
data = txn1.getString(dbi, 1);
console.log("-----", "txn1", 1, data);

try {
    console.log("error expected here:");
    // txn1 is readonly, this will throw an exception!
    txn1.putString(dbi, 2, "hööhh");
}
catch (err) {
    console.log(err);
}

txn1.commit();
console.log("txn1: aborted");

dbi.close();
env.close();

