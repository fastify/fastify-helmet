'use strict'

const { test } = require('tap')
const Fastify = require('fastify')
const helmet = require('..')

test('It should apply route specific helmet options over the global options', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/', { helmet: { frameguard: false } }, (request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    url: '/'
  })

  const notExpected = {
    'x-frame-options': 'SAMEORIGIN'
  }

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  t.notMatch(response.headers, notExpected)
  t.has(response.headers, expected)
})

test('It should disable helmet on specific route when route `helmet` option is set to `false`', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet, { global: true })

  fastify.get('/disabled', { helmet: false }, (request, reply) => {
    reply.send({ hello: 'disabled' })
  })

  fastify.get('/enabled', (request, reply) => {
    reply.send({ hello: 'enabled' })
  })

  const helmetHeaders = {
    'x-frame-options': 'SAMEORIGIN',
    'x-dns-prefetch-control': 'off',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  await fastify.inject({
    method: 'GET',
    url: '/disabled'
  }).then((response) => {
    t.notMatch(response.headers, helmetHeaders)
  }).catch((err) => {
    t.error(err)
  })

  await fastify.inject({
    method: 'GET',
    url: '/enabled'
  }).then((response) => {
    t.has(response.headers, helmetHeaders)
  }).catch((err) => {
    t.error(err)
  })
})

test('It should add CSPNonce decorator and hooks when route `enableCSPNonces` option is set to true', async (t) => {
  t.plan(4)

  const fastify = Fastify()

  await fastify.register(helmet, {
    global: false,
    enableCSPNonces: false,
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        'script-src': ["'self'", "'unsafe-eval'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"]
      }
    }
  })

  fastify.get('/', {
    helmet: {
      enableCSPNonces: true
    }
  }, (request, reply) => {
    t.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  const response = await fastify.inject({ method: 'GET', url: '/' })
  const cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `default-src 'self';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self' 'unsafe-eval' 'unsafe-inline' 'nonce-${cspCache.script}';script-src-attr 'none';style-src 'self' 'unsafe-inline' 'nonce-${cspCache.style}';upgrade-insecure-requests`
  })
})

test('It should add CSPNonce decorator and hooks with default options when route `enableCSPNonces` option is set to true', async (t) => {
  t.plan(8)

  const fastify = Fastify()

  await fastify.register(helmet, {
    global: false,
    enableCSPNonces: false
  })

  fastify.get('/no-csp', (request, reply) => {
    t.equal(reply.cspNonce, null)
    reply.send({ message: 'no csp' })
  })

  fastify.get('/with-csp', {
    helmet: {
      enableCSPNonces: true
    }
  }, (request, reply) => {
    t.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  fastify.inject({
    method: 'GET',
    path: '/no-csp'
  })

  let response

  response = await fastify.inject({ method: 'GET', url: '/with-csp' })
  const cspCache = response.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)

  response = await fastify.inject({ method: 'GET', url: '/with-csp' })
  const newCsp = response.json()
  t.not(cspCache, newCsp)
  t.ok(cspCache.script)
  t.ok(cspCache.style)
})

test('It should throw an error when route specific helmet options are of an invalid type', (t) => {
  t.plan(2)

  const fastify = Fastify()
  fastify.register(helmet)

  fastify.get('/', { helmet: 'invalid_options' }, (request, reply) => {
    return { message: 'ok' }
  })

  fastify.inject({
    method: 'GET',
    url: '/'
  }).catch((err) => {
    if (err) {
      t.ok(err)
      t.equal(err.message, 'Unknown value for route helmet configuration')
    }
  })
})
