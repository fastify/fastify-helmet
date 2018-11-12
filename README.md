# fastify-helmet
[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat)](http://standardjs.com/)  [![Build Status](https://travis-ci.org/fastify/fastify-helmet.svg?branch=master)](https://travis-ci.org/fastify/fastify-helmet) [![Greenkeeper badge](https://badges.greenkeeper.io/fastify/fastify-helmet.svg)](https://greenkeeper.io/)

Important security headers for Fastify. It is a port from express of
[helmet](http://npm.im/helmet)

## Install
```
npm i fastify-helmet --save
```

## Usage

Simply require this plugin, and the basic security headers will be set.

```js
const fastify = require('fastify')()
const helmet = require('fastify-helmet')

fastify.register(
  helmet,
  // Example of passing an option to x-powered-by middleware
  { hidePoweredBy: { setTo: 'PHP 4.2.0' } }
)

fastify.listen(3000, err => {
  if (err) throw err
  console.log('Server listenting on localhost:', fastify.server.address().port)
})
```

## How it works

`fastify-helmet` is a collection of 12 smaller middleware functions that set HTTP headers. Running `fastify.register(helmet)` will not include all of these middleware functions by default.

| Module | Default? |
|---|---|
| [contentSecurityPolicy](https://helmetjs.github.io/docs/csp/) for setting Content Security Policy |  |
| [crossdomain](https://helmetjs.github.io/docs/crossdomain/) for handling Adobe products’ crossdomain requests |  |
| [expectCt](https://helmetjs.github.io/docs/expect-ct/) for handling Certificate Transparency |  |
| [dnsPrefetchControl](https://helmetjs.github.io/docs/dns-prefetch-control) controls browser DNS prefetching | ✓ |
| [featurePolicy](https://helmetjs.github.io/docs/feature-policy/) to limit your site’s features |  |
| [frameguard](https://helmetjs.github.io/docs/frameguard/) to prevent clickjacking | ✓ |
| [hidePoweredBy](https://helmetjs.github.io/docs/hide-powered-by) to remove the X-Powered-By header | ✓ |
| [hpkp](https://helmetjs.github.io/docs/hpkp/) for HTTP Public Key Pinning |  |
| [hsts](https://helmetjs.github.io/docs/hsts/) for HTTP Strict Transport Security | ✓ |
| [ieNoOpen](https://helmetjs.github.io/docs/ienoopen) sets X-Download-Options for IE8+ | ✓ |
| [noCache](https://helmetjs.github.io/docs/nocache/) to disable client-side caching |  |
| [noSniff](https://helmetjs.github.io/docs/dont-sniff-mimetype) to keep clients from sniffing the MIME type | ✓ |
| [referrerPolicy](https://helmetjs.github.io/docs/referrer-policy) to hide the Referer header |  |
| [xssFilter](https://helmetjs.github.io/docs/xss-filter) adds some small XSS protections | ✓ |

`fastify-helmet` accept the same options of Helmet, and you can see more in [the helmet documentation](https://helmetjs.github.io/docs/).

## License

MIT
