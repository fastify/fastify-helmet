'use strict'

const Fastify = require('fastify')
const helmet = require('..')

const fastify = Fastify({
  logger: {
    level: 'info'
  }
})

fastify.register(helmet)

const opts = {
  schema: {
    response: {
      200: {
        type: 'object',
        properties: {
          hello: {
            type: 'string'
          }
        }
      }
    }
  }
}

fastify.get('/', opts, function (_request, reply) {
  reply
    .header('Content-Type', 'application/json')
    .code(200)
    .send({ hello: 'world' })
})

fastify.get('/route-with-disabled-helmet', { ...opts, helmet: false }, function (_request, reply) {
  reply
    .header('Content-Type', 'application/json')
    .code(200)
    .send({ hello: 'world' })
})

fastify.listen({ port: 3000 }, err => {
  if (err) throw err
  fastify.log.info(`Server listening on ${fastify.server.address().address}:${fastify.server.address().port}`)
})
