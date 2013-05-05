var lmdb = require('./src/build/Release/node-lmdb');
var env = new lmdb.LmdbEnv();
env.setMaxDbs(3);
env.open("testdata");
env.close();
