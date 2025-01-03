import fastify, { FastifyPluginAsync } from 'fastify'
import helmet from 'helmet'
import { expectAssignable, expectError, expectType } from 'tsd'
import fastifyHelmet, { FastifyHelmetOptions, FastifyHelmetRouteOptions } from '..'

// Plugin registered with no options
const appOne = fastify()
appOne.register(fastifyHelmet)

// Plugin registered with an empty object option
const appTwo = fastify()
expectAssignable<FastifyHelmetOptions>({})
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
expectAssignable<FastifyHelmetOptions>(helmetOptions)
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
  expectType<{
    script: string;
    style: string;
  }>(reply.cspNonce)
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
  expectType<{
    script: string;
    style: string;
  }>(reply.cspNonce)
})

const csp = fastifyHelmet.contentSecurityPolicy
expectType<typeof helmet.contentSecurityPolicy>(csp)

// Plugin registered with `global` set to `true`
const appSeven = fastify()
appSeven.register(fastifyHelmet, { global: true })

appSeven.get('/route-with-disabled-helmet', { helmet: false }, function (_request, reply) {
  expectType<typeof helmet>(reply.helmet())
})

expectError(
  appSeven.get('/route-with-disabled-helmet', {
    helmet: 'trigger a typescript error'
  }, function (_request, reply) {
    expectType<typeof helmet>(reply.helmet())
  })
)

// Plugin registered with `global` set to `false`
const appEight = fastify()
appEight.register(fastifyHelmet, { global: false })

appEight.get('/disabled-helmet', function (_request, reply) {
  expectType<typeof helmet>(reply.helmet(helmetOptions))
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
expectAssignable<FastifyHelmetRouteOptions>(routeHelmetOptions)

appEight.get('/enabled-helmet', routeHelmetOptions, function (_request, reply) {
  expectType<typeof helmet>(reply.helmet())
  expectType<{
    script: string;
    style: string;
  }>(reply.cspNonce)
})

appEight.get('/enable-framegard', {
  helmet: { frameguard: true }
}, function (_request, reply) {
  expectType<typeof helmet>(reply.helmet())
  expectType<{
    script: string;
    style: string;
  }>(reply.cspNonce)
})

// Plugin registered with an invalid helmet option
const appThatTriggerAnError = fastify()
expectError(
  appThatTriggerAnError.register(fastifyHelmet, {
    thisOptionDoesNotExist: 'trigger a typescript error'
  })
)

// fastify-helmet instance is using the FastifyHelmetOptions options
expectType<
  FastifyPluginAsync<FastifyHelmetOptions> & {
    contentSecurityPolicy: typeof helmet.contentSecurityPolicy;
  }
>(fastifyHelmet)
