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
      'x-xss-protection': '1; mode=block'
    }

    t.include(res.headers, expected)
    t.end()
  })
})
test('sets default cross-domain-policy', (t) => {
  const fastify = Fastify()

  fastify.register(helmet, { permittedCrossDomainPolicies: true })

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
test('can add feature policy', (t) => {
  const fastify = Fastify()

  fastify.register(helmet, {
    featurePolicy: {
      features: {
        fullscreen: ["'self'"],
        vibrate: ["'none'"],
        payment: ['example.com'],
        syncXhr: ["'none'"]
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
    const expected = {
      'feature-policy': "fullscreen 'self';vibrate 'none';payment example.com;sync-xhr 'none'"
    }

    t.include(res.headers, expected)
    t.end()
  })
})
