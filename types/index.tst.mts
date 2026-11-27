import { expect } from 'tstyche'
import fastifyHelmet, { contentSecurityPolicy, type FastifyHelmetOptions } from './index.js'

// An ES module gets the module itself as the default import, so `contentSecurityPolicy` must be typed on it.
expect(fastifyHelmet.contentSecurityPolicy).type.toBe(contentSecurityPolicy)
expect(fastifyHelmet.contentSecurityPolicy).type.toBe(fastifyHelmet.fastifyHelmet.contentSecurityPolicy)

// Helmet's ESM and CommonJS builds each have their own symbol: the one the plugin exports is the one its options take.
const options = {
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      'default-src': contentSecurityPolicy.dangerouslyDisableDefaultSrc,
      'frame-ancestors': ["'none'"]
    }
  }
} satisfies FastifyHelmetOptions

expect(options).type.toBeAssignableTo<FastifyHelmetOptions>()
