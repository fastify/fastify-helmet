# fastify-helmet
[![npm version](https://img.shields.io/npm/v/fastify-helmet)](https://www.npmjs.com/package/fastify-helmet)
![CI workflow](https://github.com/fastify/fastify-helmet/workflows/CI%20workflow/badge.svg)
[![Known Vulnerabilities](https://snyk.io/test/github/fastify/fastify-helmet/badge.svg)](https://snyk.io/test/github/fastify/fastify-helmet)
[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat)](http://standardjs.com/) 

Important security headers for Fastify. It is a tiny wrapper around
[helmet](http://npm.im/helmet).

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

## How it works

`fastify-helmet` is just a tiny wrapper around helmet that adds an `'onRequest'` hook.
It accepts the same options of Helmet, and you can see more in [the helmet documentation](https://helmetjs.github.io/docs/).

## License

MIT
