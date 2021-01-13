'use strict'

const fp = require('fastify-plugin')
const helmet = require('helmet')

const fastifyHelmet = function (app, options, next) {
  const middleware = helmet(options)

  app.addHook('onRequest', function (req, reply, next) {
    middleware(req.raw, reply.raw, next)
  })

  next()
}

fastifyHelmet.contentSecurityPolicy = helmet.contentSecurityPolicy

module.exports = fp(fastifyHelmet, {
  fastify: '3.x',
  name: 'fastify-helmet'
})
