import { open, levelup, bufferToKeyValue, keyValueToBuffer, ABORT } from '../index.js';
let db = open('test/testdata/test-db.mdb', {
    name: 'mydb',
    overlappingSync: true,
    pageSize: 16384,
})
console.log(db.env.stat())
console.log('last value: ', db.get('test'))
let newValue = Math.random()
console.log('putting new value', newValue)
db.putSync('test', newValue)
process.exit(0);
