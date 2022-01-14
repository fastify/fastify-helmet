'use strict'

const { randomBytes } = require('crypto')
const fp = require('fastify-plugin')
const helmet = require('helmet')

function helmetPlugin (fastify, options, next) {
  // helmet will throw when any option is explicitly set to "true"
  // using ECMAScript destructuring is a clean workaround as we do not need to alter options
  const { enableCSPNonces, global, ...globalConfiguration } = options

  const isGlobal = typeof global === 'boolean' ? global : true

  // We initialize the `helmet` reply decorator
  fastify.decorateReply('helmet', null)

  // We will add the onRequest helmet middleware functions through the onRoute hook if needed
  fastify.addHook('onRoute', (routeOptions) => {
    if (typeof routeOptions.helmet !== 'undefined') {
      if (typeof routeOptions.helmet === 'object') {
        const { enableCSPNonces: enableRouteCSPNonces, ...helmetRouteConfiguration } = routeOptions.helmet

        // If route helmet options are set they overwrite the global helmet configuration
        const mergedHelmetConfiguration = Object.assign({}, globalConfiguration, helmetRouteConfiguration)

        buildRouteHooks(mergedHelmetConfiguration, routeOptions)

        if (enableRouteCSPNonces) {
          routeOptions.onRequest.push(buildCSPNonce(fastify, mergedHelmetConfiguration))
        }
      } else if (routeOptions.helmet === false) {
        // don't apply any helmet settings but decorate the reply with a fallback to the
        // global helmet options
        buildRouteHooks(globalConfiguration, routeOptions, true)
      } else {
        throw new Error('Unknown value for route helmet configuration')
      }
    } else if (isGlobal) {
      // if the plugin is set globally (meaning that all the routes will be decorated)
      // As the endpoint, does not have a custom helmet configuration, use the global one.
      buildRouteHooks(globalConfiguration, routeOptions)

      if (enableCSPNonces) {
        routeOptions.onRequest.push(buildCSPNonce(fastify, globalConfiguration))
      }
    } else {
      // if no options are specified and the plugin is not global, then we still want to decorate
      // the reply in this case
      buildRouteHooks(globalConfiguration, routeOptions, true)
    }
  })

  next()
}

function buildCSPNonce (fastify, configuration) {
  const cspDirectives = configuration.contentSecurityPolicy
    ? configuration.contentSecurityPolicy.directives
    : helmet.contentSecurityPolicy.getDefaultDirectives()
  const cspReportOnly = configuration.contentSecurityPolicy
    ? configuration.contentSecurityPolicy.reportOnly
    : undefined

  return function (request, reply, next) {
    if (!fastify.hasReplyDecorator('cspNonce')) {
      fastify.decorateReply('cspNonce', null)
    }

    // prevent object reference: https://github.com/fastify/fastify-helmet/issues/118
    const directives = { ...cspDirectives }

    // create csp nonce
    reply.cspNonce = {
      script: randomBytes(16).toString('hex'),
      style: randomBytes(16).toString('hex')
    }

    // push nonce to csp
    // allow both script-src or scriptSrc syntax
    const scriptKey = Array.isArray(directives['script-src']) ? 'script-src' : 'scriptSrc'
    directives[scriptKey] = Array.isArray(directives[scriptKey]) ? [...directives[scriptKey]] : []
    directives[scriptKey].push(`'nonce-${reply.cspNonce.script}'`)
    // allow both style-src or styleSrc syntax
    const styleKey = Array.isArray(directives['style-src']) ? 'style-src' : 'styleSrc'
    directives[styleKey] = Array.isArray(directives[styleKey]) ? [...directives[styleKey]] : []
    directives[styleKey].push(`'nonce-${reply.cspNonce.style}'`)

    const cspMiddleware = helmet.contentSecurityPolicy({ directives, reportOnly: cspReportOnly })
    cspMiddleware(request.raw, reply.raw, next)
  }
}

function buildRouteHooks (configuration, routeOptions, decorateOnly) {
  if (Array.isArray(routeOptions.onRequest)) {
    routeOptions.onRequest.push(addHelmetReplyDecorator)
  } else if (typeof routeOptions.onRequest === 'function') {
    routeOptions.onRequest = [routeOptions.onRequest, addHelmetReplyDecorator]
  } else {
    routeOptions.onRequest = [addHelmetReplyDecorator]
  }

  const middleware = helmet(configuration)

  function addHelmetReplyDecorator (request, reply, next) {
    // We decorate `reply.helmet` with all helmet middleware functions
    // NB: we allow users to pass a custom helmet options object with a fallback
    // to global helmet configuration.
    reply.helmet = (opts) => opts
      ? helmet(opts)(request.raw, reply.raw)
      : helmet(configuration)(request.raw, reply.raw)

    next()
  }

  if (decorateOnly) {
    return
  }

  // At this point `routeOptions.onRequest` is an array
  // we just have to push our `onRequest` function
  routeOptions.onRequest.push(onRequest)

  function onRequest (request, reply, next) {
    middleware(request.raw, reply.raw, next)
  }
}

module.exports = fp(helmetPlugin, {
  fastify: '3.x',
  name: 'fastify-helmet'
})

module.exports.contentSecurityPolicy = helmet.contentSecurityPolicy
