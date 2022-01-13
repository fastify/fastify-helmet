import fastify, { FastifyPluginCallback } from 'fastify';
import helmet from 'helmet';
import { expectAssignable, expectError, expectType } from 'tsd';
import fastifyHelmet, { FastifyHelmetOptions, FastifyHelmetRouteOptions } from '../..';

// Plugin registered with no options
const appOne = fastify();
appOne.register(fastifyHelmet);

// Plugin registered with an empty object option
const appTwo = fastify();
expectAssignable<FastifyHelmetOptions>({});
appTwo.register(fastifyHelmet, {});

// Plugin registered with all helmet middlewares disabled
const appThree = fastify();
const helmetOptions = {
  contentSecurityPolicy: false,
  dnsPrefetchControl: false,
  expectCt: false,
  frameguard: false,
  hidePoweredBy: false,
  hsts: false,
  ieNoOpen: false,
  noSniff: false,
  permittedCrossDomainPolicies: false,
  referrerPolicy: false,
  xssFilter: false
};
expectAssignable<FastifyHelmetOptions>(helmetOptions);
appThree.register(fastifyHelmet, helmetOptions);

// Plugin registered with helmet middlewares custom settings
const appFour = fastify();
appFour.register(fastifyHelmet, {
  contentSecurityPolicy: {
    directives: {
      'directive-1': ['foo', 'bar']
    },
    reportOnly: true
  },
  dnsPrefetchControl: {
    allow: true
  },
  expectCt: {
    maxAge: 1,
    enforce: true,
    reportUri: 'foo'
  },
  frameguard: {
    action: 'foo'
  },
  hsts: {
    maxAge: 1,
    includeSubDomains: true,
    preload: true
  },
  permittedCrossDomainPolicies: {
    permittedPolicies: 'foo'
  },
  referrerPolicy: {
    policy: 'foo'
  }
  // these options are false or never
  // hidePoweredBy: false
  // ieNoOpen: false,
  // noSniff: false,
  // xssFilter: false
});

// Plugin registered with `enableCSPNonces` option and helmet default CSP settings
const appFive = fastify();
appFive.register(fastifyHelmet, { enableCSPNonces: true });

appFive.get('/', function (request, reply) {
  expectType<{
    script: string;
    style: string;
  }>(reply.cspNonce);
});

// Plugin registered with `enableCSPNonces` option and custom CSP settings
const appSix = fastify();
appSix.register(fastifyHelmet, {
  enableCSPNonces: true,
  contentSecurityPolicy: {
    directives: {
      'directive-1': ['foo', 'bar']
    },
    reportOnly: true
  }
});

appSix.get('/', function (request, reply) {
  expectType<{
    script: string;
    style: string;
  }>(reply.cspNonce);
});

const csp = fastifyHelmet.contentSecurityPolicy;
expectType<typeof helmet.contentSecurityPolicy>(csp);

// Plugin registered with `global` set to `true`
const appSeven = fastify();
appSeven.register(fastifyHelmet, { global: true });

appSeven.get('/route-with-disabled-helmet', { helmet: false }, function (request, reply) {
  expectType<typeof helmet>(reply.helmet());
});

expectError(
  appSeven.get('/route-with-disabled-helmet', {
    helmet: 'trigger a typescript error'
  }, function (request, reply) {
    expectType<typeof helmet>(reply.helmet());
  })
);

// Plugin registered with `global` set to `false`
const appEight = fastify();
appEight.register(fastifyHelmet, { global: false });

appEight.get('/disabled-helmet', function (request, reply) {
  expectType<typeof helmet>(reply.helmet(helmetOptions));
});

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
    expectCt: {
      maxAge: 1,
      enforce: true,
      reportUri: 'foo'
    },
    frameguard: {
      action: 'foo'
    },
    hsts: {
      maxAge: 1,
      includeSubDomains: true,
      preload: true
    },
    permittedCrossDomainPolicies: {
      permittedPolicies: 'foo'
    },
    referrerPolicy: {
      policy: 'foo'
    }
  }
};
expectAssignable<FastifyHelmetRouteOptions>(routeHelmetOptions)

appEight.get('/enabled-helmet', routeHelmetOptions, function (request, reply) {
  expectType<typeof helmet>(reply.helmet());
  expectType<{
    script: string;
    style: string;
  }>(reply.cspNonce);
})

appEight.get('/enable-framegard', {
  helmet: { frameguard: true }
}, function (request, reply) {
  expectType<typeof helmet>(reply.helmet());
  expectType<{
    script: string;
    style: string;
  }>(reply.cspNonce);
})

// Plugin registered with an invalid helmet option
const appThatTriggerAnError = fastify();
expectError(
  appThatTriggerAnError.register(fastifyHelmet, {
    thisOptionDoesNotExist: 'trigger a typescript error'
  })
);

// fastify-helmet instance is using the FastifyHelmetOptions options
expectType<
  FastifyPluginCallback<FastifyHelmetOptions> & {
    contentSecurityPolicy: typeof helmet.contentSecurityPolicy;
  }
>(fastifyHelmet);
