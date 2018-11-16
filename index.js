'use strict'

const fp = require('fastify-plugin')
const config = require('./config')
const helmet = {
  contentSecurityPolicy: require('helmet-csp'),
  dnsPrefetchControl: require('dns-prefetch-control'),
  expectCt: require('expect-ct'),
  featurePolicy: require('feature-policy'),
  frameguard: require('frameguard'),
  hidePoweredBy: require('hide-powered-by'),
  hpkp: require('hpkp'),
  hsts: require('hsts'),
  ieNoOpen: require('ienoopen'),
  noCache: require('nocache'),
  noSniff: require('dont-sniff-mimetype'),
  permittedCrossDomainPolicies: require('helmet-crossdomain'),
  referrerPolicy: require('referrer-policy'),
  xssFilter: require('x-xss-protection')
}

const middlewares = Object.keys(helmet)

module.exports = fp(function (fastify, opts, next) {
  middlewares.forEach(function (middlewareName) {
    const middleware = helmet[middlewareName]
    const option = opts[middlewareName]
    const isDefault = config.defaultMiddleware.indexOf(middlewareName) !== -1

    if (option === false) { return }

    if (option != null) {
      if (option === true) {
        fastify.use(middleware({}))
      } else {
        fastify.use(middleware(option))
      }
    } else if (isDefault) {
      fastify.use(middleware({}))
    }
  })

  next()
}, {
  fastify: '>=0.39.1',
  name: 'fastify-helmet'
})
