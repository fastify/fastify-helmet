'use strict'

const neo = require('neostandard')

module.exports = [
  ...neo(),
  {
    rules: {
      '@stylistic/comma-dangle': ['error', {
        arrays: 'never',
        objects: 'never',
        imports: 'never',
        exports: 'never',
        functions: 'never'
      }]
    }
  }
]
