'use strict'

const { randomBytes } = require('crypto')
const fp = require('fastify-plugin')
const helmet = require('helmet')

async function helmetPlugin (fastify, options) {
  // helmet will throw when any option is explicitly set to "true"
  // using ECMAScript destructuring is a clean workaround as we do not need to alter options
  const { enableCSPNonces, global, ...globalConfiguration } = options

  const isGlobal = typeof global === 'boolean' ? global : true

  // We initialize the `helmet` reply decorator only if it does not already exists
  if (!fastify.hasReplyDecorator('helmet')) {
    fastify.decorateReply('helmet', null)
  }

  // We initialize the `cspNonce` reply decorator only if it does not already exists
  if (!fastify.hasReplyDecorator('cspNonce')) {
    fastify.decorateReply('cspNonce', null)
  }

  fastify.addHook('onRoute', (routeOptions) => {
    if (typeof routeOptions.helmet !== 'undefined') {
      if (typeof routeOptions.helmet === 'object') {
        routeOptions.config = Object.assign(
          routeOptions.config || Object.create(null),
          { helmet: routeOptions.helmet }
        )
      } else if (routeOptions.helmet === false) {
        routeOptions.config = Object.assign(
          routeOptions.config || Object.create(null),
          { helmet: { skipRoute: true } }
        )
      } else {
        throw new Error('Unknown value for route helmet configuration')
      }
    }
  })

  fastify.addHook('onRequest', async (request, reply) => {
    const routeOptions = request.context.config && typeof request.context.config.helmet !== 'undefined'
      ? request.context.config.helmet
      : undefined

    if (routeOptions) {
      const { enableCSPNonces: enableRouteCSPNonces, skipRoute, ...helmetRouteConfiguration } = routeOptions
      const mergedHelmetConfiguration = Object.assign({}, globalConfiguration, helmetRouteConfiguration)

      replyDecorators(request, reply, mergedHelmetConfiguration, enableRouteCSPNonces)
    } else {
      replyDecorators(request, reply, globalConfiguration, enableCSPNonces)
    }
  })

  fastify.addHook('onRequest', (request, reply, next) => {
    const { helmet: routeOptions } = request.context.config

    if (typeof routeOptions !== 'undefined') {
      const { enableCSPNonces: enableRouteCSPNonces, skipRoute, ...helmetRouteConfiguration } = routeOptions

      // If helmet route option is set to `false` we skip the route
      if (skipRoute === true) {
        return next()
      }

      // If route helmet options are set they overwrite the global helmet configuration
      const mergedHelmetConfiguration = Object.assign({}, globalConfiguration, helmetRouteConfiguration)

      buildHelmetOnRoutes(request, reply, next, mergedHelmetConfiguration, enableRouteCSPNonces)
      return next()
    } else if (isGlobal) {
      buildHelmetOnRoutes(request, reply, next, globalConfiguration, enableCSPNonces)
      return next()
    }

    return next()
  })
}

async function replyDecorators (request, reply, configuration, enableCSP) {
  if (enableCSP) {
    reply.cspNonce = {
      script: randomBytes(16).toString('hex'),
      style: randomBytes(16).toString('hex')
    }
  }

  reply.helmet = function (opts) {
    const helmetConfiguration = opts ? Object.assign({}, configuration, opts) : configuration

    return helmet(helmetConfiguration)(request.raw, reply.raw, (err) => new Error(err))
  }
}

function buildHelmetOnRoutes (request, reply, next, configuration, enableCSP) {
  if (enableCSP === true) {
    const cspDirectives = configuration.contentSecurityPolicy
      ? configuration.contentSecurityPolicy.directives
      : helmet.contentSecurityPolicy.getDefaultDirectives()
    const cspReportOnly = configuration.contentSecurityPolicy
      ? configuration.contentSecurityPolicy.reportOnly
      : undefined

    // We get the csp nonce from the reply
    const { script: scriptCSPNonce, style: styleCSPNonce } = reply.cspNonce

    // We prevent object reference: https://github.com/fastify/fastify-helmet/issues/118
    const directives = { ...cspDirectives }

    // We push nonce to csp
    // We allow both 'script-src' or 'scriptSrc' syntax
    const scriptKey = Array.isArray(directives['script-src']) ? 'script-src' : 'scriptSrc'
    directives[scriptKey] = Array.isArray(directives[scriptKey]) ? [...directives[scriptKey]] : []
    directives[scriptKey].push(`'nonce-${scriptCSPNonce}'`)
    // allow both style-src or styleSrc syntax
    const styleKey = Array.isArray(directives['style-src']) ? 'style-src' : 'styleSrc'
    directives[styleKey] = Array.isArray(directives[styleKey]) ? [...directives[styleKey]] : []
    directives[styleKey].push(`'nonce-${styleCSPNonce}'`)

    const mergedHelmetConfiguration = Object.assign(
      {},
      configuration,
      { contentSecurityPolicy: { directives, reportOnly: cspReportOnly } }
    )

    helmet(mergedHelmetConfiguration)(request.raw, reply.raw, next)
  } else {
    helmet(configuration)(request.raw, reply.raw, next)
  }
}

module.exports = fp(helmetPlugin, {
  fastify: '3.x',
  name: 'fastify-helmet'
})

module.exports.contentSecurityPolicy = helmet.contentSecurityPolicy
