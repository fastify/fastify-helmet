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

test('set nonces', (t) => {
  const fastify = Fastify()

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

  fastify.get('/', (request, reply) => {
    reply.send({ hello: 'world', nonce: reply.raw.locals.nonce })
  })

  fastify.inject({
    method: 'GET',
    url: '/'
  }, (err, res) => {
    t.error(err)
    t.true(!!res.json().nonce)
    t.end()
  })
})

test('only sets nonces in a scoped plugin', (t) => {
  const fastify = Fastify()

  fastify.register((instance, opts, next) => {
    instance.register(helmet, {
      generateNonces: true,
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"]
        }
      }
    })

    instance.get('/scoped', (request, reply) => {
      reply.send({ nonce: reply.raw.locals.nonce, hello: 'scoped' })
    })

    next()
  })

  fastify.get('/root', (request, reply) => {
    const { locals: { nonce = null } = {} } = reply.raw

    reply.send({ hello: 'world', nonce })
  })

  fastify.inject({
    method: 'GET',
    url: '/root'
  }, (err, res) => {
    t.error(err)
    t.equals(res.json().nonce, null)

    fastify.inject({ method: 'GET', url: '/scoped' }, (err, res) => {
      t.error(err)
      t.true(!!res.json().nonce)
      t.end()
    })
  })
})
