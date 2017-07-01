'use strict'

var express = require('express')
var helmet = require('helmet')

var app = express()

app.use(helmet())
app.use(require('express-pino-logger')())

app.get('/', function (req, res) {
  res.send({ hello: 'world' })
})

app.listen(3000)
