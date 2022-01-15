'use strict'

const fastify = require('fastify')
const helmet = require('..')

const app = fastify({
  logger: { level: 'info' }
})

app.register(helmet)

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

app.get('/', opts, function (request, reply) {
  reply.send({ hello: 'world' })
})

app.listen(3000, err => {
  if (err) throw err
})
