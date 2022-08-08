import { FastifyPluginAsync, RawServerBase, RawServerDefault } from 'fastify';
import helmet, { contentSecurityPolicy, HelmetOptions } from 'helmet';

declare module 'fastify' {
  export interface RouteShorthandOptions<
    RawServer extends RawServerBase = RawServerDefault
  > extends FastifyHelmetRouteOptions {}

  interface FastifyReply {
    cspNonce: {
      script: string;
      style: string;
    },
    helmet: (opts?: HelmetOptions) => typeof helmet
  }

  export interface RouteOptions extends FastifyHelmetRouteOptions {}
}

export interface FastifyHelmetRouteOptions {
  helmet?: Omit<FastifyHelmetOptions, 'global'> | false;
}

export interface FastifyHelmetOptions extends NonNullable<HelmetOptions> {
  enableCSPNonces?: boolean,
  global?: boolean;
}

export const fastifyHelmet: FastifyPluginAsync<FastifyHelmetOptions> & {
  contentSecurityPolicy: typeof contentSecurityPolicy;
};

export default fastifyHelmet;
