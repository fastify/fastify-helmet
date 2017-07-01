'use strict'

const fastify = require('fastify')({
  logger: {
    level: 'info'
  }
})
const helmet = require('.')

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

fastify.get('/', opts, function (req, reply) {
  reply.header('Content-Type', 'application/json').code(200)
  reply.send({ hello: 'world' })
})

fastify.listen(3000, err => {
  if (err) throw err
  console.log('Server listenting on localhost:', fastify.server.address().port)
})
