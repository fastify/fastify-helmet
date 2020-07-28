'use strict'

const fp = require('fastify-plugin')
const helmet = require('helmet')

module.exports = fp(async function (app, options) {
  // TODO: Once Middie uses Decorator API we can detect presence using that: https://www.fastify.io/docs/latest/Decorators/#hasdecoratorname
  // Until then all we can do is check if `fastify.use` throws
  try {
    app.use(helmet(options))
  } catch (error) {
    if (error.code === 'FST_ERR_MISSING_MIDDLEWARE') {
      await app.register(require('middie'))
      app.use(helmet(options))
    } else {
      throw error
    }
  }
}, {
  fastify: '3.x',
  name: 'fastify-helmet'
})
