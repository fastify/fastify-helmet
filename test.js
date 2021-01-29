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
