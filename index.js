'use strict'

const fp = require('fastify-plugin')
const helmet = require('helmet')

module.exports = fp(function (app, options, next) {
  const middleware = helmet(options)

  app.addHook('onRequest', function (req, reply, next) {
    middleware(req.raw, reply.raw, next)
  })

  next()
}, {
  fastify: '3.x',
  name: 'fastify-helmet'
})
