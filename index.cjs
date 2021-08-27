const esm = require('esm')
require = esm(module, { cache: false, mode: 'all', cjs:false,force: true })
module.exports = require('./main.mjs')