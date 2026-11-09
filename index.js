'use strict'

const { randomBytes } = require('node:crypto')
const fp = require('fastify-plugin')
const helmet = require('helmet')

const kCspNonce = Symbol('cspNonce')

function getScriptNonce (_req, res) {
  return `'nonce-${res[kCspNonce].script}'`
}

function getStyleNonce (_req, res) {
  return `'nonce-${res[kCspNonce].style}'`
}

function compileHelmetMiddleware (configuration, enableCSP) {
  if (enableCSP && configuration.contentSecurityPolicy !== false) {
    const cspDirectives = configuration.contentSecurityPolicy
      ? configuration.contentSecurityPolicy.directives
      : helmet.contentSecurityPolicy.getDefaultDirectives()
    const cspReportOnly = configuration.contentSecurityPolicy
      ? configuration.contentSecurityPolicy.reportOnly
      : undefined
    const cspUseDefaults = configuration.contentSecurityPolicy
      ? configuration.contentSecurityPolicy.useDefaults
      : undefined

    // We prevent object reference: https://github.com/fastify/fastify-helmet/issues/118
    const directives = { ...cspDirectives }

    // We push nonce to csp
    // We allow both 'script-src' or 'scriptSrc' syntax
    const scriptKey = Array.isArray(directives['script-src']) ? 'script-src' : 'scriptSrc'
    directives[scriptKey] = Array.isArray(directives[scriptKey]) ? [...directives[scriptKey]] : []
    directives[scriptKey].push(getScriptNonce)
    // allow both style-src or styleSrc syntax
    const styleKey = Array.isArray(directives['style-src']) ? 'style-src' : 'styleSrc'
    directives[styleKey] = Array.isArray(directives[styleKey]) ? [...directives[styleKey]] : []
    directives[styleKey].push(getStyleNonce)

    const contentSecurityPolicy = { directives, reportOnly: cspReportOnly, useDefaults: cspUseDefaults }
    const mergedHelmetConfiguration = Object.assign(Object.create(null), configuration, { contentSecurityPolicy })

    return helmet(mergedHelmetConfiguration)
  }

  return helmet(configuration)
}

async function fastifyHelmet (fastify, options) {
  // helmet will throw when any option is explicitly set to "true"
  // using ECMAScript destructuring is a clean workaround as we do not need to alter options
  const { enableCSPNonces, global, ...globalConfiguration } = options

  const isGlobal = typeof global === 'boolean' ? global : true
  const globalEnableNonce = enableCSPNonces === true
  const globalMiddleware = isGlobal ? compileHelmetMiddleware(globalConfiguration, globalEnableNonce) : null

  const globalState = {
    skip: !isGlobal,
    enableNonce: globalEnableNonce,
    configuration: globalConfiguration,
    middleware: globalMiddleware,
    replyMiddleware: !isGlobal || globalEnableNonce ? null : globalMiddleware
  }

  const routeStateMap = new WeakMap()

  function replyHelmet (opts) {
    const { helmet: routeHelmet } = this.request.routeOptions.config
    const state = routeHelmet !== undefined ? routeStateMap.get(routeHelmet) : globalState

    if (opts) {
      const helmetConfiguration = Object.assign(Object.create(null), state.configuration, opts)
      return helmet(helmetConfiguration)(this.request.raw, this.raw, done)
    }

    state.replyMiddleware ??= helmet(state.configuration)
    return state.replyMiddleware(this.request.raw, this.raw, done)
  }

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
      if (routeOptions.helmet === false) {
        routeOptions.config = Object.assign(routeOptions.config || Object.create(null), { helmet: { skipRoute: true } })
      } else if (typeof routeOptions.helmet === 'object' && routeOptions.helmet !== null) {
        routeOptions.config = Object.assign(routeOptions.config || Object.create(null), { helmet: routeOptions.helmet })
      } else {
        throw new Error('Unknown value for route helmet configuration')
      }
    }

    const routeHelmet = routeOptions.config?.helmet
    if (routeHelmet !== undefined) {
      const { enableCSPNonces: enableRouteCSPNonces, skipRoute, ...helmetRouteConfiguration } = routeHelmet
      // If route helmet options are set they overwrite the global helmet configuration
      const mergedHelmetConfiguration = Object.assign(Object.create(null), globalConfiguration, helmetRouteConfiguration)

      if (skipRoute === true) {
        routeStateMap.set(routeHelmet, {
          skip: true,
          enableNonce: false,
          configuration: mergedHelmetConfiguration,
          middleware: null,
          replyMiddleware: null
        })
      } else {
        const enableNonce = (enableRouteCSPNonces ?? enableCSPNonces) === true
        const middleware = compileHelmetMiddleware(mergedHelmetConfiguration, enableNonce)
        routeStateMap.set(routeHelmet, {
          skip: false,
          enableNonce,
          configuration: mergedHelmetConfiguration,
          middleware,
          replyMiddleware: enableNonce ? null : middleware
        })
      }
    }
  })

  fastify.addHook('onRequest', function onRequestHelmet (request, reply, next) {
    const { helmet: routeHelmet } = request.routeOptions.config
    const state = routeHelmet !== undefined ? routeStateMap.get(routeHelmet) : globalState

    if (state.enableNonce) {
      const nonce = {
        script: randomBytes(16).toString('hex'),
        style: randomBytes(16).toString('hex')
      }
      reply.cspNonce = nonce
      reply.raw[kCspNonce] = nonce
    }

    reply.helmet = replyHelmet

    if (state.skip) {
      return next()
    }

    return state.middleware(request.raw, reply.raw, next)
  })
}

function done (error) {
  // Helmet used to forward an Error object, so we could just rethrow it.
  // Since Helmet v8.1.0 (see PR https://github.com/helmetjs/helmet/pull/485 ),
  // errors are thrown directly instead of being passed to a callback.
  // We keep the argument for compatibility, as v8.1.0 still accepts it
  // (see https://github.com/helmetjs/helmet/blob/v8.1.0/index.ts#L109 ).
  /* c8 ignore next */
  if (error) throw error
}

module.exports = fp(fastifyHelmet, {
  fastify: '5.x',
  name: '@fastify/helmet'
})
module.exports.default = fastifyHelmet
module.exports.fastifyHelmet = fastifyHelmet

module.exports.contentSecurityPolicy = helmet.contentSecurityPolicy
