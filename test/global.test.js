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
    path: '/'
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
    path: '/'
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
    path: '/'
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
    path: '/'
  })

  const expected = {
    'x-permitted-cross-domain-policies': 'by-content-type'
  }

  t.has(response.headers, expected)
})

test('It should not disable the other headers when disabling one header', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet, { frameguard: false })

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
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

test('It should be able to access default CSP directives through plugin export', async (t) => {
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
    path: '/'
  })

  const expected = { 'content-security-policy': 'default-src \'self\';base-uri \'self\';block-all-mixed-content;font-src \'self\' https: data:;form-action \'self\';frame-ancestors \'self\';img-src \'self\' data:;object-src \'none\';script-src \'self\';script-src-attr \'none\';style-src \'self\' https: \'unsafe-inline\';upgrade-insecure-requests' }

  t.has(response.headers, expected)
})

test('It should auto generate nonce per request', async (t) => {
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

  response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)

  response = await fastify.inject({ method: 'GET', path: '/' })
  const newCsp = response.json()
  t.not(cspCache, newCsp)
  t.ok(cspCache.script)
  t.ok(cspCache.style)
})

test('It should allow merging options for enableCSPNonces', async (t) => {
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

  const response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  })
})

test('It should not stack nonce array in csp header', async (t) => {
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

  let response = await fastify.inject({ method: 'GET', path: '/' })
  let cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  })

  response = await fastify.inject({ method: 'GET', path: '/' })
  cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  })
})

test('It should access the correct options property', async (t) => {
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

  const response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `default-src 'self';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self' 'unsafe-eval' 'unsafe-inline' 'nonce-${cspCache.script}';script-src-attr 'none';style-src 'self' 'unsafe-inline' 'nonce-${cspCache.style}';upgrade-insecure-requests`
  })
})

test('It should not set script-src or style-src', async (t) => {
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

  const response = await fastify.inject({ method: 'GET', path: '/' })
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
    path: '/one',
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
    path: '/two',
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
    path: '/three',
    method: 'GET'
  }).then((response) => {
    t.equal(response.statusCode, 200)
    t.equal(response.headers['x-fastify-global-test'], 'ok')
    t.has(response.headers, expected)
    t.equal(JSON.parse(response.payload).message, 'three')
  }).catch((err) => {
    t.error(err)
  })
})

test('It should add the `helmet` reply decorator', async (t) => {
  t.plan(3)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/', async (request, reply) => {
    t.ok(reply.helmet)
    t.not(reply.helmet, null)

    await reply.helmet()
    return { message: 'ok' }
  })

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
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

test('It should not throw when trying to add the `helmet` and `cspNonce` reply decorators if they already exist', async (t) => {
  t.plan(7)

  const fastify = Fastify()

  // We decorate the reply with helmet and cspNonce to trigger the existence check
  fastify.decorateReply('helmet', null)
  fastify.decorateReply('cspNonce', null)

  await fastify.register(helmet, { enableCSPNonces: true, global: true })

  fastify.get('/', async (request, reply) => {
    t.ok(reply.helmet)
    t.not(reply.helmet, null)
    t.ok(reply.cspNonce)
    t.not(reply.cspNonce, null)

    reply.send(reply.cspNonce)
  })

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })

  const cspCache = response.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  t.has(response.headers, expected)
})

test('It should be able to pass custom options to the `helmet` reply decorator', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/', async (request, reply) => {
    t.ok(reply.helmet)
    t.not(reply.helmet, null)

    await reply.helmet({ frameguard: false })
    return { message: 'ok' }
  })

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  const notExpected = {
    'x-frame-options': 'SAMEORIGIN'
  }

  t.notMatch(response.headers, notExpected)
  t.has(response.headers, expected)
})

test('It should be able to conditionally apply the middlewares through the `helmet` reply decorator', async (t) => {
  t.plan(10)

  const fastify = Fastify()
  await fastify.register(helmet, { global: true })

  fastify.get('/:condition', { helmet: false }, async (request, reply) => {
    const { condition } = request.params

    t.ok(reply.helmet)
    t.not(reply.helmet, null)

    if (condition !== 'frameguard') {
      await reply.helmet({ frameguard: false })
    } else {
      await reply.helmet({ frameguard: true })
    }
    return { message: 'ok' }
  })

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  const maybeExpected = {
    'x-frame-options': 'SAMEORIGIN'
  }

  {
    const response = await fastify.inject({
      method: 'GET',
      path: '/no-frameguard'
    })

    t.equal(response.statusCode, 200)
    t.notMatch(response.headers, maybeExpected)
    t.has(response.headers, expected)
  }

  const response = await fastify.inject({
    method: 'GET',
    path: '/frameguard'
  })

  t.equal(response.statusCode, 200)
  t.has(response.headers, maybeExpected)
  t.has(response.headers, expected)
})

test('It should apply helmet headers when returning error messages', async (t) => {
  t.plan(6)

  const fastify = Fastify()
  await fastify.register(helmet, { enableCSPNonces: true })

  fastify.get('/', {
    onRequest: async (request, reply) => {
      reply.code(401)
      reply.send({ message: 'Unauthorized' })
    }
  }, async (request, reply) => {
    return { message: 'ok' }
  })

  fastify.get('/error-handler', {
  }, async (request, reply) => {
    return Promise.reject(new Error('error handler triggered'))
  })

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  {
    const response = await fastify.inject({
      method: 'GET',
      path: '/'
    })

    t.equal(response.statusCode, 401)
    t.has(response.headers, expected)
  }

  {
    const response = await fastify.inject({
      method: 'GET',
      path: '/error-handler'
    })

    t.equal(response.statusCode, 500)
    t.has(response.headers, expected)
  }

  {
    const response = await fastify.inject({
      method: 'GET',
      path: '/404-route'
    })

    t.equal(response.statusCode, 404)
    t.has(response.headers, expected)
  }
})
