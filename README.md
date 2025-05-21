# @fastify/helmet

[![CI](https://github.com/fastify/fastify-helmet/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fastify/fastify-helmet/actions/workflows/ci.yml)
[![NPM version](https://img.shields.io/npm/v/@fastify/helmet)](https://www.npmjs.com/package/@fastify/helmet)
[![neostandard javascript style](https://img.shields.io/badge/code_style-neostandard-brightgreen?style=flat)](https://github.com/neostandard/neostandard)

Important security headers for Fastify, using [helmet](https://npm.im/helmet).

## Install
```
npm i @fastify/helmet
```

### Compatibility

| Plugin version | Fastify version |
| ---------------|-----------------|
| `>=12.x`       | `^5.x`          |
| `>=9.x <12.x`  | `^4.x`          |
| `>=7.x <9.x`   | `^3.x`          |
| `>=1.x <7.x`   | `^2.x`          |
| `>=1.x <7.x`   | `^1.x`          |


Please note that if a Fastify version is out of support, then so are the corresponding versions of this plugin
in the table above.
See [Fastify's LTS policy](https://github.com/fastify/fastify/blob/main/docs/Reference/LTS.md) for more details.

## Usage

Simply require this plugin to set basic security headers.

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

`@fastify/helmet` is a wrapper around `helmet` that adds an `'onRequest'` hook
and a `reply.helmet` decorator.

It accepts the same options as `helmet`. See [helmet documentation](https://helmetjs.github.io/).

### Apply Helmet to all routes

Pass `{ global: true }` to register Helmet for all routes.
For granular control, pass `{ global: false }` to disable it at a global scope.
Default is `true`.

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

`@fastify/helmet` allows enabling, disabling, and customizing `helmet` for each route using the `helmet` shorthand option
when registering routes.

To disable `helmet` for a specific endpoint, pass `{ helmet: false }` to the route options.

To enable or customize `helmet` for a specific endpoint, pass a configuration object to route options, e.g., `{ helmet: { frameguard: false } }`.

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

`@fastify/helmet` also allows CSP nonce generation, which can be enabled by passing `{ enableCSPNonces: true }` into the options.
Retrieve the `nonces` through `reply.cspNonce`.

> ℹ️ Note: This feature is implemented by this module and is not supported by `helmet`.
> For using `helmet` only for csp nonces, see [example](#example---generate-by-helmet).

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
  // access the generated nonce by "reply.raw"
  reply.raw.scriptNonce
  reply.raw.styleNonce
})

```

### Disable Default `helmet` Directives

By default, `helmet` adds [a default set of CSP directives](https://github.com/helmetjs/helmet/tree/main/middlewares/content-security-policy#content-security-policy-middleware) to the response.
Disable this by setting `useDefaults: false` in the `contentSecurityPolicy` configuration.

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
