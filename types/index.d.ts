import { FastifyPluginAsync, RawServerBase, RawServerDefault } from 'fastify'
import helmet, { contentSecurityPolicy, HelmetOptions } from 'helmet'

declare module 'fastify' {
  export interface RouteShorthandOptions<
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    RawServer extends RawServerBase = RawServerDefault
  > extends fastifyHelmet.FastifyHelmetRouteOptions { }

  interface FastifyReply {
    cspNonce: {
      script: string;
      style: string;
    },
    helmet: (opts?: HelmetOptions) => typeof helmet
  }

  export interface RouteOptions extends fastifyHelmet.FastifyHelmetRouteOptions { }
}

type FastifyHelmet = FastifyPluginAsync<fastifyHelmet.FastifyHelmetOptions> & {
  contentSecurityPolicy: typeof contentSecurityPolicy;
}

declare namespace fastifyHelmet {

  export interface FastifyHelmetRouteOptions {
    helmet?: Omit<FastifyHelmetOptions, 'global'> | false;
  }

  export type FastifyHelmetOptions = {
    enableCSPNonces?: boolean,
    global?: boolean;
  } & NonNullable<HelmetOptions>

  export const fastifyHelmet: FastifyHelmet
  export { fastifyHelmet as default }
}

declare function fastifyHelmet (...params: Parameters<FastifyHelmet>): ReturnType<FastifyHelmet>
export = fastifyHelmet
