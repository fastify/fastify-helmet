'use strict'

const fp = require('fastify-plugin')
const helmet = require('helmet')
const crypto = require('crypto')

module.exports = fp(function (app, options, next) {
  const generateNonces = !!options.generateNonces
  delete options.generateNonces

  const baseCspConfig = { contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"] } } }

  options = Object.assign({}, baseCspConfig, options)

  let middleware = helmet(options)

  app.addHook('onRequest', function (req, reply, next) {
    if (generateNonces) {
      const nonce = crypto.randomBytes(16).toString('base64')

      options.contentSecurityPolicy.directives.scriptSrc.push(`'${nonce}'`)
      options.contentSecurityPolicy.directives.styleSrc.push(`'${nonce}'`)

      if (!reply.raw.locals) {
        reply.raw.locals = {}
      }

      // TODO - what is the best place to put this?
      reply.raw.locals.nonce = nonce

      middleware = helmet(options)
    }

    middleware(req.raw, reply.raw, next)
  })

  next()
}, {
  fastify: '3.x',
  name: 'fastify-helmet'
})
