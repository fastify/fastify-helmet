'use strict'

const { test } = require('tap')
const Fastify = require('fastify')
const helmet = require('..')

test('It should apply route specific helmet options over the global options', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet, { global: true })

  fastify.get('/', { helmet: { frameguard: false } }, (request, reply) => {
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
    path: '/disabled'
  }).then((response) => {
    t.notMatch(response.headers, helmetHeaders)
  }).catch((err) => {
    t.error(err)
  })

  await fastify.inject({
    method: 'GET',
    path: '/enabled'
  }).then((response) => {
    t.has(response.headers, helmetHeaders)
  }).catch((err) => {
    t.error(err)
  })
})

test('It should add CSPNonce decorator and hooks when route `enableCSPNonces` option is set to `true`', async (t) => {
  t.plan(4)

  const fastify = Fastify()

  await fastify.register(helmet, {
    global: false,
    enableCSPNonces: false,
    contentSecurityPolicy: {
      directives: {
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

  const response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()

  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.has(response.headers, {
    'content-security-policy': `script-src 'self' 'unsafe-eval' 'unsafe-inline' 'nonce-${cspCache.script}';style-src 'self' 'unsafe-inline' 'nonce-${cspCache.style}';default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  })
})

test('It should add CSPNonce decorator and hooks with default options when route `enableCSPNonces` option is set to `true`', async (t) => {
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

  response = await fastify.inject({ method: 'GET', path: '/with-csp' })
  const cspCache = response.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)

  response = await fastify.inject({ method: 'GET', path: '/with-csp' })
  const newCsp = response.json()
  t.not(cspCache, newCsp)
  t.ok(cspCache.script)
  t.ok(cspCache.style)
})

test('It should not add CSPNonce decorator when route `enableCSPNonces` option is set to `false`', async (t) => {
  t.plan(8)

  const fastify = Fastify()

  await fastify.register(helmet, {
    global: true,
    enableCSPNonces: true
  })

  fastify.get('/with-csp', (request, reply) => {
    t.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  fastify.get('/no-csp', { helmet: { enableCSPNonces: false } }, (request, reply) => {
    t.equal(reply.cspNonce, null)
    reply.send({ message: 'no csp' })
  })

  fastify.inject({
    method: 'GET',
    path: '/no-csp'
  })

  let response

  response = await fastify.inject({ method: 'GET', path: '/with-csp' })
  const cspCache = response.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)

  response = await fastify.inject({ method: 'GET', path: '/with-csp' })
  const newCsp = response.json()
  t.not(cspCache, newCsp)
  t.ok(cspCache.script)
  t.ok(cspCache.style)
})

test('It should not set default directives when route useDefaults is set to `false`', async (t) => {
  t.plan(1)

  const fastify = Fastify()

  await fastify.register(helmet, {
    global: false,
    enableCSPNonces: false,
    contentSecurityPolicy: {
      directives: {
      }
    }
  })

  fastify.get('/', {
    helmet: {
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", "'unsafe-eval'", "'unsafe-inline'"],
          'style-src': ["'self'", "'unsafe-inline'"]
        }
      }
    }
  }, (request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({ method: 'GET', path: '/' })

  t.has(response.headers, {
    'content-security-policy': "default-src 'self';script-src 'self' 'unsafe-eval' 'unsafe-inline';style-src 'self' 'unsafe-inline'"
  })
})

test('It should be able to conditionally apply the middlewares through the `helmet` reply decorator', async (t) => {
  t.plan(10)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/:condition', async (request, reply) => {
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

test('It should throw an error when route specific helmet options are of an invalid type', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet)

  try {
    fastify.get('/', { helmet: 'invalid_options' }, (request, reply) => {
      return { message: 'ok' }
    })
  } catch (error) {
    t.ok(error)
    t.equal(error.message, 'Unknown value for route helmet configuration')
  }
})

test('It should forward `helmet` reply decorator and route specific errors to `fastify-helmet`', async (t) => {
  t.plan(6)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/helmet-reply-decorator-error', async (request, reply) => {
    await reply.helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'", () => 'bad;value']
        }
      }
    })

    return { message: 'ok' }
  })

  fastify.get('/helmet-route-configuration-error', {
    helmet: {
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'", () => 'bad;value']
        }
      }
    }
  }, async (request, reply) => {
    return { message: 'ok' }
  })

  const notExpected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  {
    const response = await fastify.inject({
      method: 'GET',
      path: '/helmet-reply-decorator-error'
    })

    t.equal(response.statusCode, 500)
    t.equal(
      JSON.parse(response.payload).message,
      'Content-Security-Policy received an invalid directive value for "default-src"'
    )
    t.notMatch(response.headers, notExpected)
  }

  const response = await fastify.inject({
    method: 'GET',
    path: '/helmet-route-configuration-error'
  })

  t.equal(response.statusCode, 500)
  t.equal(
    JSON.parse(response.payload).message,
    'Content-Security-Policy received an invalid directive value for "default-src"'
  )
  t.notMatch(response.headers, notExpected)
})
