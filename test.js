'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const helmet = require('.')

test('set the default headers', (t) => {
  const fastify = Fastify()

  fastify.register(helmet)

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  fastify.inject({
    method: 'GET',
    url: '/'
  }, (err, res) => {
    t.error(err)
    const expected = {
      'x-dns-prefetch-control': 'off',
      'x-frame-options': 'SAMEORIGIN',
      'x-download-options': 'noopen',
      'x-content-type-options': 'nosniff',
      'x-xss-protection': '0'
    }

    t.include(res.headers, expected)
    t.end()
  })
})
test('sets default cross-domain-policy', (t) => {
  const fastify = Fastify()

  fastify.register(helmet)

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  fastify.inject({
    method: 'GET',
    url: '/'
  }, (err, res) => {
    t.error(err)
    const expected = {
      'x-permitted-cross-domain-policies': 'none'
    }

    t.include(res.headers, expected)
    t.end()
  })
})
test('can set cross-domain-policy', (t) => {
  const fastify = Fastify()

  fastify.register(helmet, { permittedCrossDomainPolicies: { permittedPolicies: 'by-content-type' } })

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  fastify.inject({
    method: 'GET',
    url: '/'
  }, (err, res) => {
    t.error(err)
    const expected = {
      'x-permitted-cross-domain-policies': 'by-content-type'
    }

    t.include(res.headers, expected)
    t.end()
  })
})

test('disabling one header does not disable the other headers', (t) => {
  const fastify = Fastify()

  fastify.register(helmet, {
    frameguard: false
  })

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  fastify.inject({
    method: 'GET',
    url: '/'
  }, (err, res) => {
    t.error(err)
    const notExpected = {
      'x-frame-options': 'SAMEORIGIN'
    }

    const expected = {
      'x-dns-prefetch-control': 'off',
      'x-download-options': 'noopen',
      'x-content-type-options': 'nosniff',
      'x-xss-protection': '0'
    }

    t.doesNotHave(res.headers, notExpected)
    t.include(res.headers, expected)
    t.end()
  })
})
test('default CSP directives can be accessed through plugin export', (t) => {
  const fastify = Fastify()

  fastify.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives()
      }
    }
  })

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world' })
  })

  fastify.inject({
    method: 'GET',
    url: '/'
  }, (err, res) => {
    t.error(err)

    const expected = { 'content-security-policy': 'default-src \'self\';base-uri \'self\';block-all-mixed-content;font-src \'self\' https: data:;frame-ancestors \'self\';img-src \'self\' data:;object-src \'none\';script-src \'self\';script-src-attr \'none\';style-src \'self\' https: \'unsafe-inline\';upgrade-insecure-requests' }

    t.include(res.headers, expected)
    t.end()
  })
})

test('auto generate nonce pre request', async (t) => {
  t.plan(7)

  const fastify = Fastify()
  fastify.register(helmet, {
    enableCSPNonces: true
  })

  fastify.get('/', (request, reply) => {
    t.ok(reply.cspNonce)
    reply.send(reply.cspNonce)
  })

  let res

  res = await fastify.inject({ method: 'GET', url: '/' })
  const cspCache = res.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)

  res = await fastify.inject({ method: 'GET', url: '/' })
  const newCsp = res.json()
  t.notEqual(cspCache, newCsp)
  t.ok(cspCache.script)
  t.ok(cspCache.style)
})

test('allow merging options for enableCSPNonces', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  fastify.register(helmet, {
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

  const res = await fastify.inject({ method: 'GET', url: '/' })
  const cspCache = res.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.includes(res.headers, {
    'content-security-policy': `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}'`
  })
})

test('nonce array is not stacked in csp header', async (t) => {
  t.plan(8)

  const fastify = Fastify()
  fastify.register(helmet, {
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

  let res = await fastify.inject({ method: 'GET', url: '/' })
  let cspCache = res.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.includes(res.headers, {
    'content-security-policy': `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}'`
  })

  res = await fastify.inject({ method: 'GET', url: '/' })
  cspCache = res.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.includes(res.headers, {
    'content-security-policy': `default-src 'self';script-src 'self' 'nonce-${cspCache.script}';style-src 'self' 'nonce-${cspCache.style}'`
  })
})

test('access the correct options property', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  fastify.register(helmet, {
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

  const res = await fastify.inject({ method: 'GET', url: '/' })
  const cspCache = res.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.includes(res.headers, {
    'content-security-policy': `default-src 'self';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self' 'unsafe-eval' 'unsafe-inline' 'nonce-${cspCache.script}';script-src-attr 'none';style-src 'self' 'unsafe-inline' 'nonce-${cspCache.style}';upgrade-insecure-requests`
  })
})

test('do not set script-src or style-src', async (t) => {
  t.plan(4)

  const fastify = Fastify()
  fastify.register(helmet, {
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

  const res = await fastify.inject({ method: 'GET', url: '/' })
  const cspCache = res.json()
  t.ok(cspCache.script)
  t.ok(cspCache.style)
  t.includes(res.headers, {
    'content-security-policy': `default-src 'self';script-src 'nonce-${cspCache.script}';style-src 'nonce-${cspCache.style}'`
  })
})
