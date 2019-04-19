if (typeof assert === 'undefined') { assert = require('chai').assert }
const inspector =  require('inspector')
inspector.open(9329, null, true)
const { removeSync } = require('fs-extra')
//removeSync('tests/db')
require('./performance')
