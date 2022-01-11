'use strict'

const { test } = require('tap')
const Fastify = require('fastify')
const helmet = require('..')

test('It should set the default headers', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet)

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    url: '/'
  })

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  t.has(response.headers, expected)
})

test('It should not set the default headers when global is set to `false`', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    url: '/'
  })

  const notExpected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  t.notMatch(response.headers, notExpected)
})

test('It should set the default cross-domain-policy', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet)

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    url: '/'
  })
  const expected = {
    'x-permitted-cross-domain-policies': 'none'
  }

  t.has(response.headers, expected)
})

test('It should be able to set cross-domain-policy', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet, {
    permittedCrossDomainPolicies: { permittedPolicies: 'by-content-type' }
  })

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    url: '/'
  })

  const expected = {
    'x-permitted-cross-domain-policies': 'by-content-type'
  }

  t.has(response.headers, expected)
})

test('disabling one header does not disable the other headers', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet, { frameguard: false })

  fastify.get('/', (request, reply) => {
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

test('default CSP directives can be accessed through plugin export', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives()
      }
    }
  })

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    url: '/'
  })

  const expected = { 'content-security-policy': 'default-src \'self\';base-uri \'self\';block-all-mixed-content;font-src \'self\' https: data:;form-action \'self\';frame-ancestors \'self\';img-src \'self\' data:;object-src \'none\';script-src \'self\';script-src-attr \'none\';style-src \'self\' https: \'unsafe-inline\';upgrade-insecure-requests' }

  t.has(response.headers, expected)
})

test('auto generate nonce pre request', async (t) => {
  t.plan(7)

  const fastify = Fastify()
  await fastify.register(helmet, {
    enableCSPNonces: true
  })

  fastify.get('/', (request, reply) => {
    t.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  let response

  response = await fastify.inject({ method: 'GET', url: '/' })
  const cspCache = response.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)

  response = await fastify.inject({ method: 'GET', url: '/' })
  const newCsp = response.json()
  t.not(cspCache, newCsp)
  t.ok(cspCache.script)
  t.ok(cspCache.style)
})

test('allow merging options for enableCSPNonces', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  await fastify.register(helmet, {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"]
      }
    }
  })

  fastify.get('/', (request, reply) => {
    t.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  const response = await fastify.inject({ method: 'GET', url: '/' })
  const cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  })
})

test('nonce array is not stacked in csp header', async (t) => {
  t.plan(8)

  const fastify = Fastify()
  await fastify.register(helmet, {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"]
      }
    }
  })

  fastify.get('/', (request, reply) => {
    t.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  let response = await fastify.inject({ method: 'GET', url: '/' })
  let cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  })

  response = await fastify.inject({ method: 'GET', url: '/' })
  cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  })
})

test('access the correct options property', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  await fastify.register(helmet, {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        'script-src': ["'self'", "'unsafe-eval'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"]
      }
    }
  })

  fastify.get('/', (request, reply) => {
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

test('do not set script-src or style-src', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  await fastify.register(helmet, {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"]
      }
    }
  })

  fastify.get('/', (request, reply) => {
    t.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  const response = await fastify.inject({ method: 'GET', url: '/' })
  const cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `default-src 'self';script-src 'nonce-${cspCache.script}';style-src 'nonce-${cspCache.style}';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  })
})

test('It should add hooks correctly', async (t) => {
  t.plan(14)

  const fastify = Fastify()

  fastify.addHook('onRequest', async (request, reply) => {
    reply.header('x-fastify-global-test', 'ok')
  })

  await fastify.register(helmet, { global: true })

  fastify.get('/one', {
    onRequest: [
      async (request, reply) => { reply.header('x-fastify-test-one', 'ok') }
    ]
  }, (request, reply) => {
    return { message: 'one' }
  })

  fastify.get('/two', {
    onRequest: async (request, reply) => { reply.header('x-fastify-test-two', 'ok') }
  }, (request, reply) => {
    return { message: 'two' }
  })

  fastify.get('/three', { onRequest: null }, (request, reply) => {
    return { message: 'three' }
  })

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  await fastify.inject({
    url: '/one',
    method: 'GET'
  }).then((response) => {
    t.equal(response.statusCode, 200)
    t.equal(response.headers['x-fastify-global-test'], 'ok')
    t.equal(response.headers['x-fastify-test-one'], 'ok')
    t.has(response.headers, expected)
    t.equal(JSON.parse(response.payload).message, 'one')
  }).catch((err) => {
    t.error(err)
  })

  await fastify.inject({
    url: '/two',
    method: 'GET'
  }).then((response) => {
    t.equal(response.statusCode, 200)
    t.equal(response.headers['x-fastify-global-test'], 'ok')
    t.equal(response.headers['x-fastify-test-two'], 'ok')
    t.has(response.headers, expected)
    t.equal(JSON.parse(response.payload).message, 'two')
  }).catch((err) => {
    t.error(err)
  })

  await fastify.inject({
    url: '/three',
    method: 'GET',
    headers: {
      'accept-encoding': 'deflate'
    }
  }).then((response) => {
    t.equal(response.statusCode, 200)
    t.equal(response.headers['x-fastify-global-test'], 'ok')
    t.has(response.headers, expected)
    t.equal(JSON.parse(response.payload).message, 'three')
  }).catch((err) => {
    t.error(err)
  })
})
