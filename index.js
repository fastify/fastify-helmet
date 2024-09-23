'use strict'

const { randomBytes } = require('node:crypto')
const fp = require('fastify-plugin')
const helmet = require('helmet')

async function fastifyHelmet (fastify, options) {
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
    if (routeOptions.helmet !== undefined) {
      if (typeof routeOptions.helmet === 'object') {
        routeOptions.config = Object.assign(routeOptions.config || Object.create(null), { helmet: routeOptions.helmet })
      } else if (routeOptions.helmet === false) {
        routeOptions.config = Object.assign(routeOptions.config || Object.create(null), { helmet: { skipRoute: true } })
      } else {
        throw new Error('Unknown value for route helmet configuration')
      }
    }
  })

  fastify.addHook('onRequest', async function helmetConfigureReply (request, reply) {
    /* c8 ignore next */
    const { helmet: routeOptions } = request.routeOptions?.config || request.routeConfig

    if (routeOptions !== undefined) {
      const { enableCSPNonces: enableRouteCSPNonces, skipRoute, ...helmetRouteConfiguration } = routeOptions
      // If route helmet options are set they overwrite the global helmet configuration
      const mergedHelmetConfiguration = Object.assign(Object.create(null), globalConfiguration, helmetRouteConfiguration)

      // We decorate the reply with a fallback to the route scoped helmet options
      return replyDecorators(request, reply, mergedHelmetConfiguration, enableRouteCSPNonces)
    }

    // We decorate the reply with a fallback to the global helmet options
    return replyDecorators(request, reply, globalConfiguration, enableCSPNonces)
  })

  fastify.addHook('onRequest', function helmetApplyHeaders (request, reply, next) {
    /* c8 ignore next */
    const { helmet: routeOptions } = request.routeOptions?.config || request.routeConfig

    if (routeOptions !== undefined) {
      const { enableCSPNonces: enableRouteCSPNonces, skipRoute, ...helmetRouteConfiguration } = routeOptions

      if (skipRoute === true) {
        // If helmet route option is set to `false` we skip the route
      } else {
        // If route helmet options are set they overwrite the global helmet configuration
        const mergedHelmetConfiguration = Object.assign(Object.create(null), globalConfiguration, helmetRouteConfiguration)

        return buildHelmetOnRoutes(request, reply, mergedHelmetConfiguration, enableRouteCSPNonces)
      }

      return next()
    }
    if (isGlobal) {
      // if the plugin is set globally (meaning that all the routes will be decorated)
      // As the endpoint, does not have a custom helmet configuration, use the global one.
      return buildHelmetOnRoutes(request, reply, globalConfiguration, enableCSPNonces)
    }

    // if the plugin is not global we can skip the route
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
    const helmetConfiguration = opts
      ? Object.assign(Object.create(null), configuration, opts)
      : configuration

    return helmet(helmetConfiguration)(request.raw, reply.raw, done)
  }
}

async function buildHelmetOnRoutes (request, reply, configuration, enableCSP) {
  if (enableCSP === true && configuration.contentSecurityPolicy !== false) {
    const cspDirectives = configuration.contentSecurityPolicy
      ? configuration.contentSecurityPolicy.directives
      : helmet.contentSecurityPolicy.getDefaultDirectives()
    const cspReportOnly = configuration.contentSecurityPolicy
      ? configuration.contentSecurityPolicy.reportOnly
      : undefined
    const cspUseDefaults = configuration.contentSecurityPolicy
      ? configuration.contentSecurityPolicy.useDefaults
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

    const contentSecurityPolicy = { directives, reportOnly: cspReportOnly, useDefaults: cspUseDefaults }
    const mergedHelmetConfiguration = Object.assign(Object.create(null), configuration, { contentSecurityPolicy })

    helmet(mergedHelmetConfiguration)(request.raw, reply.raw, done)
  } else {
    helmet(configuration)(request.raw, reply.raw, done)
  }
}

// Helmet forward a typeof Error object so we just need to throw it as is.
function done (error) {
  if (error) throw error
}

module.exports = fp(fastifyHelmet, {
  fastify: '5.x',
  name: '@fastify/helmet'
})
module.exports.default = fastifyHelmet
module.exports.fastifyHelmet = fastifyHelmet

module.exports.contentSecurityPolicy = helmet.contentSecurityPolicy
