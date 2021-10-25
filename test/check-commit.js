import { open, levelup, bufferToKeyValue, keyValueToBuffer, ABORT } from '../index.js';
let db = open('test/testdata/test-db.mdb', {
    name: 'mydb',
    overlappingSync: true
})
console.log('last value: ', db.get('test'))
let newValue = Math.random()
console.log('putting new value', newValue)
db.put('test', newValue)

