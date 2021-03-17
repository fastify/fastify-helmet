# fastify-helmet

![CI](https://github.com/fastify/fastify-helmet/workflows/CI/badge.svg)
[![NPM version](https://img.shields.io/npm/v/fastify-helmet)](https://www.npmjs.com/package/fastify-helmet)
[![Known Vulnerabilities](https://snyk.io/test/github/fastify/fastify-helmet/badge.svg)](https://snyk.io/test/github/fastify/fastify-helmet)
[![Coverage Status](https://coveralls.io/repos/github/fastify/fastify-helmet/badge.svg?branch=master)](https://coveralls.io/github/fastify/fastify-helmet?branch=master)
[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat)](http://standardjs.com/) 

Important security headers for Fastify. It is a tiny wrapper around
[helmet](https://npm.im/helmet).

## Install
```
npm i fastify-helmet
```

## Usage

Simply require this plugin, and the basic security headers will be set.

```js
const fastify = require('fastify')()
const helmet = require('fastify-helmet')

fastify.register(
  helmet,
  // Example disables the `contentSecurityPolicy` middleware but keeps the rest.
  { contentSecurityPolicy: false }
)

fastify.listen(3000, err => {
  if (err) throw err
})
```

### Content-Security-Policy Nonce

`fastify-helmet` provide a simple way for `csp nonces generation`. You can enable
this behavior by passing `{ enableCSPNonces: true }` into the options. Then, you can
retrieve the `nonces` through `reply.cspNonce`.

Note: This feature is implemented inside this module. It is not a valid option or
      supported by helmet. If you need to use helmet feature only for csp nonce you
      can follow the example [here](#example---generate-by-helmet).

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
          }
        ],
        styleSrc: [
          function (req, res) {
            // "res" here is actually "reply.raw" in fastify
            res.styleNonce = crypto.randomBytes(16).toString('hex')
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


## How it works

`fastify-helmet` is just a tiny wrapper around helmet that adds an `'onRequest'` hook.
It accepts the same options of Helmet, and you can see more in [the helmet documentation](https://helmetjs.github.io/docs/).

## License

MIT
