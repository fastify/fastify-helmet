'use strict'

const fastify = require('fastify')
const fastifyHelmet = require('fastify-helmet')

const app = fastify({
  logger: { level: 'info' }
})

app.register(fastifyHelmet)

app.get('/', function (request, reply) {
  reply.send({ hello: 'world' })
})

app.listen(3000, err => {
  if (err) throw err
})
