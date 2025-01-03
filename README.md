# @fastify/helmet

[![CI](https://github.com/fastify/fastify-helmet/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/fastify/fastify-helmet/actions/workflows/ci.yml)
[![NPM version](https://img.shields.io/npm/v/@fastify/helmet)](https://www.npmjs.com/package/@fastify/helmet)
[![neostandard javascript style](https://img.shields.io/badge/code_style-neostandard-brightgreen?style=flat)](https://github.com/neostandard/neostandard)

Important security headers for Fastify. It is a tiny wrapper around
[helmet](https://npm.im/helmet).

## Install
```
npm i @fastify/helmet
```

### Compatibility

| Plugin version | Fastify version |
| ---------------|-----------------|
| `^12.x`        | `^5.x`          |
| `^9.x`         | `^4.x`          |
| `^7.x`         | `^3.x`          |
| `^1.x`         | `^2.x`          |
| `^1.x`         | `^1.x`          |


Please note that if a Fastify version is out of support, then so are the corresponding versions of this plugin
in the table above.
See [Fastify's LTS policy](https://github.com/fastify/fastify/blob/main/docs/Reference/LTS.md) for more details.

## Usage

Simply require this plugin and the basic security headers will be set.

```js
const fastify = require('fastify')()
const helmet = require('@fastify/helmet')

fastify.register(
  helmet,
  // Example disables the `contentSecurityPolicy` middleware but keeps the rest.
  { contentSecurityPolicy: false }
)

fastify.listen({ port: 3000 }, err => {
  if (err) throw err
})
```

## How it works

`@fastify/helmet` is a tiny wrapper around helmet that adds an `'onRequest'` hook
and a `reply.helmet` decorator.

It accepts the same options as helmet, and you can see more in [the helmet documentation](https://helmetjs.github.io/).

### Apply Helmet to all your application routes

By passing `{ global: true }` into the options, `@fastify/helmet` allows you to register Helmet for all your application
routes by default. If you want a more granular control on how to apply Helmet to your application you can choose to
disable it on a global scope by passing `{ global: false }` to the options. By default, this option is set to `true`.

#### Example - enable `@fastify/helmet` globally

```js
fastify.register(helmet)
// or
fastify.register(helmet, { global: true })
```

#### Example - disable `@fastify/helmet` globally

```js
// register the package with the `{ global: false }` option
fastify.register(helmet, { global: false })

fastify.get('/route-with-disabled-helmet', async (request, reply) => {
  return { message: 'helmet is not enabled here' }
})

fastify.get('/route-with-enabled-helmet', {
  // We enable and configure helmet for this route only
  helmet: {
    dnsPrefetchControl: {
      allow: true
    },
    frameguard: {
      action: 'foo'
    },
    referrerPolicy: false
  }
}, async (request, reply) => {
  return { message: 'helmet is enabled here' }
})

// helmet is disabled on this route but we have access to `reply.helmet` decorator
// that allows us to apply helmet conditionally
fastify.get('/here-we-use-helmet-reply-decorator', async (request, reply) => {
  if (condition) {
    // we apply the default options
    await reply.helmet()
  } else {
    // we apply customized options
    await reply.helmet({ frameguard: false })
  }

  return {
    message: 'we use the helmet reply decorator to conditionally apply helmet middlewares'
  }
})
```

### `helmet` route option

`@fastify/helmet` allows you to enable, disable, and customize helmet for each one of your application hooks by using the
`helmet` shorthand route option when you register your application routes.

If you want to disable helmet for a specific endpoint you must pass `{ helmet: false }` to your route options.

If you want to enable or customize helmet for a specific endpoint you must pass a helmet configuration object to your
route options. E.g.: `{ helmet: { frameguard: false } }`.

#### Example - `@fastify/helmet` configuration using the `helmet` shorthand route option

```js
// register the package with the `{ global: true }` option
fastify.register(helmet, { global: true })

fastify.get('/route-with-disabled-helmet', { helmet: false }, async (request, reply) => {
  return { message: 'helmet is not enabled here' }
})

fastify.get('/route-with-enabled-helmet', async (request, reply) => {
  return { message: 'helmet is enabled by default here' }
})

fastify.get('/route-with-custom-helmet-configuration', {
  // We change the helmet configuration for this route only
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
    referrerPolicy: false
  }
}, async (request, reply) => {
  return { message: 'helmet is enabled with a custom configuration on this route' }
})
```

### Content-Security-Policy Nonce

`@fastify/helmet` provide a simple way for `csp nonces generation`. You can enable this behavior by passing
`{ enableCSPNonces: true }` into the options. Then, you can retrieve the `nonces` through `reply.cspNonce`.

> Note: This feature is implemented inside this module. It is not a valid option or supported by helmet.
> If you need to use helmet feature only for csp nonce you can follow the example [here](#example---generate-by-helmet).

#### Example - Generate by options

```js
fastify.register(
  helmet,
  // enable csp nonces generation with default content-security-policy option
  { enableCSPNonces: true }
)

fastify.register(
  helmet,
  // customize content security policy with nonce generation
  {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      directives: {
        ...
      }
    }
  }
)

fastify.get('/', function(request, reply) {
  // retrieve script nonce
  reply.cspNonce.script
  // retrieve style nonce
  reply.cspNonce.style
})
```

#### Example - Generate by helmet

```js
fastify.register(
  helmet,
  {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          function (req, res) {
            // "res" here is actually "reply.raw" in fastify
            res.scriptNonce = crypto.randomBytes(16).toString('hex')
            // make sure to return nonce-... directive to helmet, so it can be sent in the headers
            return `'nonce-${res.scriptNonce}'`
          }
        ],
        styleSrc: [
          function (req, res) {
            // "res" here is actually "reply.raw" in fastify
            res.styleNonce = crypto.randomBytes(16).toString('hex')
            // make sure to return nonce-... directive to helmet, so it can be sent in the headers
            return `'nonce-${res.styleNonce}'`
          }
        ]
      }
    }
  }
)

fastify.get('/', function(request, reply) {
  // you can access the generated nonce by "reply.raw"
  reply.raw.scriptNonce
  reply.raw.styleNonce
})

```

### Disable Default `helmet` Directives

By default, `helmet` will add [a default set of CSP directives](https://github.com/helmetjs/helmet/tree/main/middlewares/content-security-policy#content-security-policy-middleware) to the response.
This behavior can be disabled by setting `useDefaults: false` in the `contentSecurityPolicy` configuration.

```js
fastify.register(
  helmet,
  {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"]
      }
    }
  }
)
```

## License

Licensed under [MIT](./LICENSE).
