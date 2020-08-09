# fastify-helmet

[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat)](http://standardjs.com/) ![CI
workflow](https://github.com/fastify/fastify-helmet/workflows/CI%20workflow/badge.svg)

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
  // Example of passing an option to x-powered-by middleware
  { hidePoweredBy: { setTo: 'PHP 4.2.0' } }
)

fastify.listen(3000, err => {
  if (err) throw err
})
```

## How it works

`fastify-helmet` is just a tiny wrapper around helmet that adds an `'onRequest'` hook.
It accepts the same options of Helmet, and you can see more in [the helmet documentation](https://helmetjs.github.io/docs/).

## Advanced Usage
One of the more fine grained use cases of a content security policy is to generate nonces for dynamic <script> and <style> tags that get generated in html. To enable dynamic nonce generation on every request, simply include the `generateNonces: true` as part of your configuration.  Example:
```js
fastify.register(helmet, {
  generateNonces: true,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"]
    }
  }
})

fastify.get('/some-page', (request, reply) => {
  console.log(reply.raw.locals.nonce) // your nonce - brmN+y1vMxcK7AIimSeQDA==

  reply.view('my-view', { nonce: reply.raw.locals.nonce })
})
```
Now, in your route handler, you will have a CSP that "knows" your nonce value, and you will have access to it for server rendering via `reply.raw.locals.nonce` so that you can pass the value to your dynamically rendered view code.

You may not want your server to use resources generating this nonce on every request, therefore it is suggested to scope this handling nonces to only your routes that need to use it, such as your view / dynamic html routes.  That way you keep performance up.

## License

MIT
