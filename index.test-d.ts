import fastifyHelmet from ".";
import fastify from "fastify";

const app = fastify();

app.register(fastifyHelmet);
app.register(fastifyHelmet, {});
app.register(fastifyHelmet, {
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
});

app.register(fastifyHelmet, {
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
  },
  // these options are false or never
  // hidePoweredBy: false 
  // ieNoOpen: false,
  // noSniff: false,
  // xssFilter: false
});
