import { FastifyPluginAsync, FastifyPluginCallback, RawServerBase, RawServerDefault } from 'fastify';
import helmet, { contentSecurityPolicy as HelmetContentSecurityPolicy, HelmetOptions } from 'helmet';

declare module 'fastify' {
  export interface RouteShorthandOptions<
    RawServer extends RawServerBase = RawServerDefault
  > extends fastifyHelmet.FastifyHelmetRouteOptions {}

  interface FastifyReply {
    cspNonce: {
      script: string;
      style: string;
    },
    helmet: (opts?: HelmetOptions) => typeof helmet
  }

  export interface RouteOptions extends fastifyHelmet.FastifyHelmetRouteOptions {}
}

type FastifyHelmetPlugin = FastifyPluginCallback<fastifyHelmet.FastifyHelmetOptions>;

declare namespace fastifyHelmet {
  export interface FastifyHelmetOptions extends NonNullable<HelmetOptions> {
    enableCSPNonces?: boolean,
    global?: boolean;
  }

  export interface FastifyHelmetRouteOptions {
    helmet?: Omit<FastifyHelmetOptions, 'global'> | false;
  }
  
  export const contentSecurityPolicy: FastifyPluginAsync<FastifyHelmetOptions> & typeof HelmetContentSecurityPolicy;
  
}

declare function fastifyHelmet(
  ...params: Parameters<FastifyHelmetPlugin>
): ReturnType<FastifyHelmetPlugin>;

export = fastifyHelmet;
