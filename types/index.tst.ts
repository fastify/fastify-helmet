import fastify, { FastifyPluginAsync } from 'fastify'
import helmet from 'helmet'
import { expect } from 'tstyche'
import fastifyHelmet, { FastifyHelmetOptions, FastifyHelmetRouteOptions } from '.'

// Plugin registered with no options
const appOne = fastify()
appOne.register(fastifyHelmet)

// Plugin registered with an empty object option
const appTwo = fastify()
expect<FastifyHelmetOptions>().type.toBeAssignableFrom({})
appTwo.register(fastifyHelmet, {})

// Plugin registered with all helmet middlewares disabled
const appThree = fastify()
const helmetOptions = {
  contentSecurityPolicy: false,
  dnsPrefetchControl: false,
  frameguard: false,
  hidePoweredBy: false,
  hsts: false,
  ieNoOpen: false,
  noSniff: false,
  permittedCrossDomainPolicies: false,
  referrerPolicy: false,
  xssFilter: false
}
expect<FastifyHelmetOptions>().type.toBeAssignableFrom(helmetOptions)
appThree.register(fastifyHelmet, helmetOptions)

// Plugin registered with helmet middlewares custom settings
const appFour = fastify()
appFour.register(fastifyHelmet, {
  contentSecurityPolicy: {
    directives: {
      'directive-1': ['foo', 'bar']
    },
    reportOnly: true,
    useDefaults: false
  },
  dnsPrefetchControl: {
    allow: true
  },
  frameguard: {
    action: 'deny'
  },
  hsts: {
    maxAge: 1,
    includeSubDomains: true,
    preload: true
  },
  permittedCrossDomainPolicies: {
    permittedPolicies: 'master-only'
  },
  referrerPolicy: {
    policy: 'no-referrer'
  }
  // these options are false or never
  // hidePoweredBy: false
  // ieNoOpen: false,
  // noSniff: false,
  // xssFilter: false
})

// Plugin registered with `enableCSPNonces` option and helmet default CSP settings
const appFive = fastify()
appFive.register(fastifyHelmet, { enableCSPNonces: true })

appFive.get('/', function (_request, reply) {
  expect(reply.cspNonce).type.toBe<{
    script: string;
    style: string;
  }>()
})

// Plugin registered with `enableCSPNonces` option and custom CSP settings
const appSix = fastify()
appSix.register(fastifyHelmet, {
  enableCSPNonces: true,
  contentSecurityPolicy: {
    directives: {
      'directive-1': ['foo', 'bar']
    },
    reportOnly: true
  }
})

appSix.get('/', function (_request, reply) {
  expect(reply.cspNonce).type.toBe<{
    script: string;
    style: string;
  }>()
})

expect(fastifyHelmet.contentSecurityPolicy).type.toBe(helmet.contentSecurityPolicy)

// Plugin registered with `global` set to `true`
const appSeven = fastify()
appSeven.register(fastifyHelmet, { global: true })

appSeven.get('/route-with-disabled-helmet', { helmet: false }, function (_request, reply) {
  expect(reply.helmet()).type.toBe(helmet)
})

appSeven.get(
  '/route-with-disabled-helmet',
  {
    // @ts-expect-error: Type 'string' is not assignable to type 'false | Omit<FastifyHelmetOptions, "global">'
    helmet: 'trigger a typescript error'
  },
  function (_request, reply) {
    expect(reply.helmet()).type.toBe(helmet)
  }
)

// Plugin registered with `global` set to `false`
const appEight = fastify()
appEight.register(fastifyHelmet, { global: false })

appEight.get('/disabled-helmet', function (_request, reply) {
  expect(reply.helmet(helmetOptions)).type.toBe(helmet)
})

const routeHelmetOptions = {
  helmet: {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      directives: {
        'directive-1': ['foo', 'bar']
      },
      reportOnly: true
    },
    dnsPrefetchControl: {
      allow: true
    },
    frameguard: {
      action: 'deny' as const
    },
    hsts: {
      maxAge: 1,
      includeSubDomains: true,
      preload: true
    },
    permittedCrossDomainPolicies: {
      permittedPolicies: 'all' as const
    },
    referrerPolicy: {
      policy: 'no-referrer' as const
    }
  }
}
expect(routeHelmetOptions).type.toBeAssignableTo<FastifyHelmetRouteOptions>()

appEight.get('/enabled-helmet', routeHelmetOptions, function (_request, reply) {
  expect(reply.helmet()).type.toBe(helmet)
  expect(reply.cspNonce).type.toBe<{
    script: string;
    style: string;
  }>()
})

appEight.get('/enable-framegard', {
  helmet: { frameguard: true }
}, function (_request, reply) {
  expect(reply.helmet()).type.toBe(helmet)
  expect(reply.cspNonce).type.toBe<{
    script: string;
    style: string;
  }>()
})

fastify().register(fastifyHelmet, {
  // @ts-expect-error: No overload matches this call
  thisOptionDoesNotExist: 'trigger a typescript error'
})

// fastify-helmet instance is using the FastifyHelmetOptions options
expect(fastifyHelmet).type.toBe<
  FastifyPluginAsync<FastifyHelmetOptions> & {
    contentSecurityPolicy: typeof helmet.contentSecurityPolicy;
  }
>()
