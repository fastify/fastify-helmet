'use strict'

const express = require('express')
const helmet = require('helmet')

const app = express()

app.use(helmet())
app.use(require('express-pino-logger')())

app.get('/', function (req, res) {
  res.send({ hello: 'world' })
})

app.listen(3000)
