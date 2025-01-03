'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const helmet = require('..')

test('It should apply route specific helmet options over the global options', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet, { global: true })

  fastify.get('/', { helmet: { frameguard: false } }, (_request, reply) => {
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

  t.assert.notDeepStrictEqual(
    response.headers['x-frame-options'],
    notExpected['x-frame-options']
  )
  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should disable helmet on specific route when route `helmet` option is set to `false`', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet, { global: true })

  fastify.get('/disabled', { helmet: false }, (_request, reply) => {
    reply.send({ hello: 'disabled' })
  })

  fastify.get('/enabled', (_request, reply) => {
    reply.send({ hello: 'enabled' })
  })

  const helmetHeaders = {
    'x-frame-options': 'SAMEORIGIN',
    'x-dns-prefetch-control': 'off',
    'x-download-options': 'noopen',
    'x-content-type-options': 'nosniff',
    'x-xss-protection': '0'
  }

  await fastify
    .inject({
      method: 'GET',
      path: '/disabled'
    })
    .then((response) => {
      const actualResponseHeaders = {
        'x-frame-options': response.headers['x-frame-options'],
        'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
        'x-download-options': response.headers['x-download-options'],
        'x-content-type-options': response.headers['x-content-type-options'],
        'x-xss-protection': response.headers['x-xss-protection']
      }

      t.assert.notDeepStrictEqual(actualResponseHeaders, helmetHeaders)
    })
    .catch((err) => {
      t.assert.fail(err)
    })

  await fastify
    .inject({
      method: 'GET',
      path: '/enabled'
    })
    .then((response) => {
      const actualResponseHeaders = {
        'x-frame-options': response.headers['x-frame-options'],
        'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
        'x-download-options': response.headers['x-download-options'],
        'x-content-type-options': response.headers['x-content-type-options'],
        'x-xss-protection': response.headers['x-xss-protection']
      }
      t.assert.deepStrictEqual(actualResponseHeaders, helmetHeaders)
    })
    .catch((err) => {
      t.assert.fail(err)
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

  fastify.get(
    '/',
    {
      helmet: {
        enableCSPNonces: true
      }
    },
    (_request, reply) => {
      t.assert.ok(reply.cspNonce)
      reply.send(reply.cspNonce)
    }
  )

  const response = await fastify.inject({ method: 'GET', path: '/' })
  const cspCache = response.json()

  const expected = {
    'content-security-policy': `script-src 'self' 'unsafe-eval' 'unsafe-inline' 'nonce-${cspCache.script}';style-src 'self' 'unsafe-inline' 'nonce-${cspCache.style}';default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src-attr 'none';upgrade-insecure-requests`
  }

  const actualResponseHeaders = {
    'content-security-policy': response.headers['content-security-policy']
  }
  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should add CSPNonce decorator and hooks with default options when route `enableCSPNonces` option is set to `true`', async (t) => {
  t.plan(8)

  const fastify = Fastify()

  await fastify.register(helmet, {
    global: false,
    enableCSPNonces: false
  })

  fastify.get('/no-csp', (_request, reply) => {
    t.assert.equal(reply.cspNonce, null)
    reply.send({ message: 'no csp' })
  })

  fastify.get(
    '/with-csp',
    {
      helmet: {
        enableCSPNonces: true
      }
    },
    (_request, reply) => {
      t.assert.ok(reply.cspNonce)
      reply.send(reply.cspNonce)
    }
  )

  fastify.inject({
    method: 'GET',
    path: '/no-csp'
  })

  let response

  response = await fastify.inject({ method: 'GET', path: '/with-csp' })
  const cspCache = response.json()
  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)

  response = await fastify.inject({ method: 'GET', path: '/with-csp' })
  const newCsp = response.json()
  t.assert.notEqual(cspCache, newCsp)
  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
})

test('It should not add CSPNonce decorator when route `enableCSPNonces` option is set to `false`', async (t) => {
  t.plan(8)

  const fastify = Fastify()

  await fastify.register(helmet, {
    global: true,
    enableCSPNonces: true
  })

  fastify.get('/with-csp', (_request, reply) => {
    t.assert.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  fastify.get(
    '/no-csp',
    { helmet: { enableCSPNonces: false } },
    (_request, reply) => {
      t.assert.equal(reply.cspNonce, null)
      reply.send({ message: 'no csp' })
    }
  )

  fastify.inject({
    method: 'GET',
    path: '/no-csp'
  })

  let response

  response = await fastify.inject({ method: 'GET', path: '/with-csp' })
  const cspCache = response.json()
  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)

  response = await fastify.inject({ method: 'GET', path: '/with-csp' })
  const newCsp = response.json()
  t.assert.notEqual(cspCache, newCsp)
  t.assert.ok(cspCache.script)
  t.assert.ok(cspCache.style)
})

test('It should not set default directives when route useDefaults is set to `false`', async (t) => {
  t.plan(1)

  const fastify = Fastify()

  await fastify.register(helmet, {
    global: false,
    enableCSPNonces: false,
    contentSecurityPolicy: {
      directives: {}
    }
  })

  fastify.get(
    '/',
    {
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
    },
    (_request, reply) => {
      reply.send({ hello: 'world' })
    }
  )

  const response = await fastify.inject({ method: 'GET', path: '/' })

  const expected = {
    'content-security-policy':
      "default-src 'self';script-src 'self' 'unsafe-eval' 'unsafe-inline';style-src 'self' 'unsafe-inline'"
  }

  const actualResponseHeaders = {
    'content-security-policy': response.headers['content-security-policy']
  }

  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should not set `content-security-policy` header, if route contentSecurityPolicy is false', async (t) => {
  t.plan(1)

  const fastify = Fastify()

  await fastify.register(helmet, {
    global: false,
    enableCSPNonces: false,
    contentSecurityPolicy: {
      directives: {}
    }
  })

  fastify.get(
    '/',
    {
      helmet: {
        contentSecurityPolicy: false
      }
    },
    (_request, reply) => {
      reply.send({ hello: 'world' })
    }
  )

  const response = await fastify.inject({ method: 'GET', path: '/' })

  const expected = {
    'content-security-policy': undefined
  }

  const actualResponseHeaders = {
    'content-security-policy': response.headers['content-security-policy']
  }

  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should be able to conditionally apply the middlewares through the `helmet` reply decorator', async (t) => {
  t.plan(10)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/:condition', async (request, reply) => {
    const { condition } = request.params

    t.assert.ok(reply.helmet)
    t.assert.notEqual(reply.helmet, null)

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

    t.assert.equal(response.statusCode, 200)
    t.assert.notDeepStrictEqual(
      response.headers['x-frame-options'],
      maybeExpected['x-frame-options']
    )
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

  t.assert.equal(response.statusCode, 200)
  t.assert.deepStrictEqual(
    response.headers['x-frame-options'],
    maybeExpected['x-frame-options']
  )
  t.assert.deepStrictEqual(actualResponseHeaders, expected)
})

test('It should throw an error when route specific helmet options are of an invalid type', async (t) => {
  t.plan(2)

  const fastify = Fastify()
  await fastify.register(helmet)

  try {
    fastify.get('/', { helmet: 'invalid_options' }, () => {
      return { message: 'ok' }
    })
  } catch (error) {
    t.assert.ok(error)
    t.assert.equal(
      error.message,
      'Unknown value for route helmet configuration'
    )
  }
})

test('It should forward `helmet` reply decorator and route specific errors to `fastify-helmet`', async (t) => {
  t.plan(6)

  const fastify = Fastify()
  await fastify.register(helmet, { global: false })

  fastify.get('/helmet-reply-decorator-error', async (_request, reply) => {
    await reply.helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'", () => 'bad;value']
        }
      }
    })

    return { message: 'ok' }
  })

  fastify.get(
    '/helmet-route-configuration-error',
    {
      helmet: {
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'", () => 'bad;value']
          }
        }
      }
    },
    async () => {
      return { message: 'ok' }
    }
  )

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

    const actualResponseHeaders = {
      'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
      'x-download-options': response.headers['x-download-options'],
      'x-content-type-options': response.headers['x-content-type-options'],
      'x-xss-protection': response.headers['x-xss-protection']
    }

    t.assert.equal(response.statusCode, 500)
    t.assert.equal(
      JSON.parse(response.payload).message,
      'Content-Security-Policy received an invalid directive value for "default-src"'
    )
    t.assert.notDeepStrictEqual(actualResponseHeaders, notExpected)
  }

  const response = await fastify.inject({
    method: 'GET',
    path: '/helmet-route-configuration-error'
  })

  const actualResponseHeaders = {
    'x-dns-prefetch-control': response.headers['x-dns-prefetch-control'],
    'x-download-options': response.headers['x-download-options'],
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-xss-protection': response.headers['x-xss-protection']
  }

  t.assert.equal(response.statusCode, 500)
  t.assert.equal(
    JSON.parse(response.payload).message,
    'Content-Security-Policy received an invalid directive value for "default-src"'
  )
  t.assert.notDeepStrictEqual(actualResponseHeaders, notExpected)
})
