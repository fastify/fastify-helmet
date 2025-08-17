'use strict'

const stream = require('node:stream')
const { test } = require('node:test')
const fp = require('fastify-plugin')
const Fastify = require('fastify')
const helmet = require('..')

test('It should set the default headers', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet)

  fastify.get('/', (_request, reply) => {
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

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-frame-options': response.headers['x-frame-options'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should not set the default headers when global is set to `false`', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/', (_request, reply) => {
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

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-frame-options': response.headers['x-frame-options'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  t.assert.notDeepStrictEqual(actualResponseHeaders, notExpected)
})

test('It should set the default cross-domain-policy', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet)

  fastify.get('/', (_request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })
  const expected = {
    'x-permitted-cross-domain-policies': 'none'
  }

  t.assert.deepStrictEqual(
    response.headers['x-permitted-cross-domain-policies'],
    expected['x-permitted-cross-domain-policies']
  )
})

test('It should be able to set cross-domain-policy', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet, {
    permittedCrossDomainPolicies: { permittedPolicies: 'by-content-type' }
  })

  fastify.get('/', (_request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })

  const expected = {
    'x-permitted-cross-domain-policies': 'by-content-type'
  }

  t.assert.deepStrictEqual(
    response.headers['x-permitted-cross-domain-policies'],
    expected['x-permitted-cross-domain-policies']
  )
})

test('It should not disable the other headers when disabling one header', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet, { frameguard: false })

  fastify.get('/', (_request, reply) => {
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

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  t.assert.notDeepStrictEqual(actualResponseHeaders, notExpected)
  t.assert.deepStrictEqual(actualResponseHeaders, expected)
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

  fastify.get('/', (_request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })

  const expected = {
    'content-security-policy':
      "default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests"
  }

  t.assert.deepStrictEqual(
    response.headers['content-security-policy'],
    expected['content-security-policy']
  )
})

test('It should not set default directives when useDefaults is set to `false`', async (t) => {
  t.plan(1)

  const fastify = Fastify()
  await fastify.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"]
      }
    }
  })

  fastify.get('/', (_request, reply) => {
    reply.send({ hello: 'world' })
  })

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })

  const expected = { 'content-security-policy': "default-src 'self'" }

  t.assert.deepStrictEqual(
    response.headers['content-security-policy'],
    expected['content-security-policy']
  )
})

test('It should auto generate nonce per request', async (t) => {
  t.plan(7)

  const fastify = Fastify()
  await fastify.register(helmet, {
    enableCSPNonces: true
  })

  fastify.get('/', (_request, reply) => {
    t.assert.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  let response

  response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()
  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)

  response = await fastify.inject({ method: 'GET', path: '/' })
  const newCsp = response.json()
  t.assert.notDeepStrictEqual(cspCache, newCsp)
  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
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

  fastify.get('/', (_request, reply) => {
    t.assert.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  const response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()

  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
  t.assert.deepStrictEqual(
    response.headers['content-security-policy'],
    `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  )
})

test('It should not set default directives when using enableCSPNonces and useDefaults is set to `false`', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  await fastify.register(helmet, {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"]
      }
    }
  })

  fastify.get('/', (_request, reply) => {
    t.assert.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  const response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()

  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
  t.assert.deepStrictEqual(
    response.headers['content-security-policy'],
    `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}'`
  )
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

  fastify.get('/', (_request, reply) => {
    t.assert.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  let response = await fastify.inject({ method: 'GET', path: '/' })
  let cspCache = response.json()

  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
  t.assert.deepStrictEqual(
    response.headers['content-security-policy'],
    `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  )

  response = await fastify.inject({ method: 'GET', path: '/' })
  cspCache = response.json()

  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
  t.assert.deepStrictEqual(
    response.headers['content-security-policy'],
    `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  )
})

test('It should access the correct options property', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  await fastify.register(helmet, {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      directives: {
        'script-src': ["'self'", "'unsafe-eval'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"]
      }
    }
  })

  fastify.get('/', (_request, reply) => {
    t.assert.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  const response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()

  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
  t.assert.deepStrictEqual(
    response.headers['content-security-policy'],
    `script-src 'self' 'unsafe-eval' 'unsafe-inline' 'nonce-${cspCache.script}';style-src 'self' 'unsafe-inline' 'nonce-${cspCache.style}';default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  )
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

  fastify.get('/', (_request, reply) => {
    t.assert.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  const response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()

  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
  t.assert.deepStrictEqual(
    response.headers['content-security-policy'],
    `default-src 'self';script-src 'nonce-${cspCache.script}';style-src 'nonce-${cspCache.style}';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  )
})

test('It should add hooks correctly', async (t) => {
  t.plan(14)

  const fastify = Fastify()

  fastify.addHook('onRequest', async (_request, reply) => {
    reply.header('x-fastify-global-test', 'ok')
  })

  await fastify.register(helmet, { global: true })

  fastify.get(
    '/one',
    {
      onRequest: [
        async (_request, reply) => {
          reply.header('x-fastify-test-one', 'ok')
        }
      ]
    },
    () => {
      return { message: 'one' }
    }
  )

  fastify.get(
    '/two',
    {
      onRequest: async (_request, reply) => {
        reply.header('x-fastify-test-two', 'ok')
      }
    },
    () => {
      return { message: 'two' }
    }
  )

  fastify.get('/three', { onRequest: async () => {} }, () => {
    return { message: 'three' }
  })

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  await fastify
    .inject({
      path: '/one',
      method: 'GET'
    })
    .then((response) => {
      const actualResponseHeaders = {
        'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
        'x-frame-options': response.headers['x-frame-options'],
        'x-download-options': response.headers['x-download-options'],
        'x-content-type-options': response.headers['x-content-type-options'],
        'x-xss-protection': response.headers['x-xss-protection']
      }
      t.assert.deepStrictEqual(response.statusCode, 200)
      t.assert.deepStrictEqual(response.headers['x-fastify-global-test'], 'ok')
      t.assert.deepStrictEqual(response.headers['x-fastify-test-one'], 'ok')
      t.assert.deepStrictEqual(actualResponseHeaders, expected)
      t.assert.deepStrictEqual(JSON.parse(response.payload).message, 'one')
    })
    .catch((err) => {
      t.assert.ifError(err)
    })

  await fastify
    .inject({
      path: '/two',
      method: 'GET'
    })
    .then((response) => {
      const actualResponseHeaders = {
        'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
        'x-frame-options': response.headers['x-frame-options'],
        'x-download-options': response.headers['x-download-options'],
        'x-content-type-options': response.headers['x-content-type-options'],
        'x-xss-protection': response.headers['x-xss-protection']
      }
      t.assert.deepStrictEqual(response.statusCode, 200)
      t.assert.deepStrictEqual(response.headers['x-fastify-global-test'], 'ok')
      t.assert.deepStrictEqual(response.headers['x-fastify-test-two'], 'ok')
      t.assert.deepStrictEqual(actualResponseHeaders, expected)
      t.assert.deepStrictEqual(JSON.parse(response.payload).message, 'two')
    })
    .catch((err) => {
      t.error(err)
    })

  await fastify
    .inject({
      path: '/three',
      method: 'GET'
    })
    .then((response) => {
      const actualResponseHeaders = {
        'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
        'x-frame-options': response.headers['x-frame-options'],
        'x-download-options': response.headers['x-download-options'],
        'x-content-type-options': response.headers['x-content-type-options'],
        'x-xss-protection': response.headers['x-xss-protection']
      }
      t.assert.deepStrictEqual(response.statusCode, 200)
      t.assert.deepStrictEqual(response.headers['x-fastify-global-test'], 'ok')
      t.assert.deepStrictEqual(actualResponseHeaders, expected)
      t.assert.deepStrictEqual(JSON.parse(response.payload).message, 'three')
    })
    .catch((err) => {
      t.assert.ifError(err)
    })
})

test('It should add the `helmet` reply decorator', async (t) => {
  t.plan(3)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/', async (_request, reply) => {
    t.assert.ok(reply.helmet)
    t.assert.notStrictEqual(reply.helmet, null)

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

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-frame-options': response.headers['x-frame-options'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should not throw when trying to add the `helmet` and `cspNonce` reply decorators if they already exist', async (t) => {
  t.plan(7)

  const fastify = Fastify()

  // We decorate the reply with helmet and cspNonce to trigger the existence check
  fastify.decorateReply('helmet', null)
  fastify.decorateReply('cspNonce', null)

  await fastify.register(helmet, { enableCSPNonces: true, global: true })

  fastify.get('/', async (_request, reply) => {
    t.assert.ok(reply.helmet)
    t.assert.notDeepStrictEqual(reply.helmet, null)
    t.assert.ok(reply.cspNonce)
    t.assert.notDeepStrictEqual(reply.cspNonce, null)

    reply.send(reply.cspNonce)
  })

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })

  const cspCache = response.json()
  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-frame-options': response.headers['x-frame-options'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should be able to pass custom options to the `helmet` reply decorator', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/', async (_request, reply) => {
    t.assert.ok(reply.helmet)
    t.assert.notDeepStrictEqual(reply.helmet, null)

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

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  const actualNotExpectedHeaders = {
    'x-frame-options': response.headers['x-frame-options']
  }

  t.assert.notDeepStrictEqual(actualNotExpectedHeaders, notExpected)
  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should be able to conditionally apply the middlewares through the `helmet` reply decorator', async (t) => {
  t.plan(10)

  const fastify = Fastify()
  await fastify.register(helmet, { global: true })

  fastify.get('/:condition', { helmet: false }, async (request, reply) => {
    const { condition } = request.params

    t.assert.ok(reply.helmet)
    t.assert.notDeepStrictEqual(reply.helmet, null)

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

    const actualResponseHeaders = {
      'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
      'x-download-options': response.headers['x-download-options'],
      'x-content-type-options': response.headers['x-content-type-options'],
      'x-xss-protection': response.headers['x-xss-protection']
    }

    const actualMaybeExpectedHeaders = {
      'x-frame-options': response.headers['x-frame-options']
    }

    t.assert.strictEqual(response.statusCode, 200)
    t.assert.notDeepStrictEqual(actualMaybeExpectedHeaders, maybeExpected)
    t.assert.deepStrictEqual(actualResponseHeaders, expected)
  }

  const response = await fastify.inject({
    method: 'GET',
    path: '/frameguard'
  })

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  const actualMaybeExpectedHeaders = {
    'x-frame-options': response.headers['x-frame-options']
  }

  t.assert.strictEqual(response.statusCode, 200)
  t.assert.deepStrictEqual(actualMaybeExpectedHeaders, maybeExpected)
  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should apply helmet headers when returning error messages', async (t) => {
  t.plan(6)

  const fastify = Fastify()
  await fastify.register(helmet, { enableCSPNonces: true })

  fastify.get(
    '/',
    {
      onRequest: async (_request, reply) => {
        reply.code(401)
        reply.send({ message: 'Unauthorized' })
      }
    },
    async () => {
      return { message: 'ok' }
    }
  )

  fastify.get('/error-handler', {}, async () => {
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

    const actualResponseHeaders = {
      'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
      'x-frame-options': response.headers['x-frame-options'],
      'x-download-options': response.headers['x-download-options'],
      'x-content-type-options': response.headers['x-content-type-options'],
      'x-xss-protection': response.headers['x-xss-protection']
    }

    t.assert.deepStrictEqual(response.statusCode, 401)
    t.assert.deepStrictEqual(actualResponseHeaders, expected)
  }

  {
    const response = await fastify.inject({
      method: 'GET',
      path: '/error-handler'
    })

    const actualResponseHeaders = {
      'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
      'x-frame-options': response.headers['x-frame-options'],
      'x-download-options': response.headers['x-download-options'],
      'x-content-type-options': response.headers['x-content-type-options'],
      'x-xss-protection': response.headers['x-xss-protection']
    }

    t.assert.deepStrictEqual(response.statusCode, 500)
    t.assert.deepStrictEqual(actualResponseHeaders, expected)
  }

  {
    const response = await fastify.inject({
      method: 'GET',
      path: '/404-route'
    })

    const actualResponseHeaders = {
      'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
      'x-frame-options': response.headers['x-frame-options'],
      'x-download-options': response.headers['x-download-options'],
      'x-content-type-options': response.headers['x-content-type-options'],
      'x-xss-protection': response.headers['x-xss-protection']
    }

    t.assert.deepStrictEqual(response.statusCode, 404)
    t.assert.deepStrictEqual(actualResponseHeaders, expected)
  }
})

// To avoid regressions.
// ref.: https://github.com/fastify/fastify-helmet/pull/169#issuecomment-1017413835
test('It should not return a fastify `FST_ERR_REP_ALREADY_SENT - Reply already sent` error', async (t) => {
  t.plan(5)

  const logs = []
  const destination = new stream.Writable({
    write: function (chunk, _encoding, next) {
      logs.push(JSON.parse(chunk))
      next()
    }
  })

  const fastify = Fastify({ logger: { level: 'info', stream: destination } })

  await fastify.register(helmet)
  await fastify.register(
    fp(
      async (instance, _options) => {
        instance.addHook('onRequest', async (request, reply) => {
          const unauthorized = new Error('Unauthorized')

          const errorResponse = (err) => {
            return { error: err.message }
          }

          // We want to crash in the scope of this test
          const crash = request.routeOptions?.config?.fail

          Promise.resolve(crash)
            .then((fail) => {
              if (fail === true) {
                reply.code(401)
                reply.send(errorResponse(unauthorized))
                return reply
              }
            })
            .catch(() => undefined)
        })
      },
      {
        name: 'regression-plugin-test'
      }
    )
  )

  fastify.get(
    '/fail',
    {
      config: { fail: true }
    },
    async () => {
      return { message: 'unreachable' }
    }
  )

  const expected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  const response = await fastify.inject({
    method: 'GET',
    path: '/fail'
  })

  const failure = logs.find(
    (entry) => entry.err && entry.err.statusCode === 500
  )

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-frame-options': response.headers['x-frame-options'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  if (failure) {
    t.not(failure.err.message, 'Reply was already sent.')
    t.not(failure.err.name, 'FastifyError')
    t.not(failure.err.code, 'FST_ERR_REP_ALREADY_SENT')
    t.not(failure.err.statusCode, 500)
    t.not(failure.msg, 'Reply already sent')
  }

  t.assert.deepStrictEqual(failure, undefined)

  t.assert.deepStrictEqual(response.statusCode, 401)
  t.assert.deepStrictEqual(actualResponseHeaders, expected)
  t.assert.deepStrictEqual(JSON.parse(response.payload).error, 'Unauthorized')
  t.assert.notDeepStrictEqual(
    JSON.parse(response.payload).message,
    'unreachable'
  )
})

test('It should forward `helmet` errors to `fastify-helmet`', async (t) => {
  t.plan(3)

  const fastify = Fastify()
  await fastify.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'", () => 'bad;value']
      }
    }
  })

  fastify.get('/', async () => {
    return { message: 'ok' }
  })

  const notExpected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-frame-options': response.headers['x-frame-options'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  t.assert.deepStrictEqual(response.statusCode, 500)
  t.assert.deepStrictEqual(
    JSON.parse(response.payload).message,
    'Content-Security-Policy received an invalid directive value for "default-src"'
  )
  t.assert.notDeepStrictEqual(actualResponseHeaders, notExpected)
})

test('It should be able to catch `helmet` errors with a fastify `onError` hook', async (t) => {
  t.plan(7)

  const errorDetected = []

  const fastify = Fastify()
  await fastify.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'", () => 'bad;value']
      }
    }
  })

  fastify.addHook('onError', async (_request, _reply, error) => {
    if (error) {
      errorDetected.push(error)
      t.assert.ok(error)
    }
  })

  fastify.get('/', async () => {
    return { message: 'ok' }
  })

  const notExpected = {
    'x-dns-prefetch-control': 'off',
    'x-frame-options': 'SAMEORIGIN',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  t.assert.deepStrictEqual(errorDetected.length, 0)

  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-frame-options': response.headers['x-frame-options'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  t.assert.deepStrictEqual(response.statusCode, 500)
  t.assert.deepStrictEqual(
    JSON.parse(response.payload).message,
    'Content-Security-Policy received an invalid directive value for "default-src"'
  )
  t.assert.notDeepStrictEqual(actualResponseHeaders, notExpected)
  t.assert.deepStrictEqual(errorDetected.length, 1)
  t.assert.deepStrictEqual(
    errorDetected[0].message,
    'Content-Security-Policy received an invalid directive value for "default-src"'
  )
})
