'use strict'

const Koa = require('koa')
const app = new Koa()

app.use(require('koa-pino-logger')())
app.use(require('koa-helmet')())

app.use(async (ctx) => {
  ctx.body = JSON.stringify({ hello: 'world' })
})

app.listen(3000)
