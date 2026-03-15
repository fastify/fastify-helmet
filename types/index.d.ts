import {
  AnyFastifyInstance,
  ApplyDecorators,
  FastifyPluginAsync,
  RawServerBase,
  RawServerDefault,
  UnEncapsulatedPlugin
} from 'fastify'
import helmet, { contentSecurityPolicy, HelmetOptions } from 'helmet'

declare module 'fastify' {
  export interface RouteShorthandOptions<
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    RawServer extends RawServerBase = RawServerDefault
  > extends fastifyHelmet.FastifyHelmetRouteOptions { }

  export interface RouteOptions extends fastifyHelmet.FastifyHelmetRouteOptions { }
}

declare namespace fastifyHelmet {
  export type FastifyHelmetPluginDecorators = {
    reply: {
      cspNonce: {
        script: string;
        style: string;
      };
      helmet: (opts?: HelmetOptions) => typeof helmet;
    }
  }

  export type FastifyHelmetPlugin<TInstance extends AnyFastifyInstance = AnyFastifyInstance> = UnEncapsulatedPlugin<
    FastifyPluginAsync<
      fastifyHelmet.FastifyHelmetOptions,
      TInstance,
      ApplyDecorators<TInstance, FastifyHelmetPluginDecorators>
    >
  > & {
    contentSecurityPolicy: typeof contentSecurityPolicy;
  }

  export interface FastifyHelmetRouteOptions {
    helmet?: Omit<FastifyHelmetOptions, 'global'> | false;
  }

  export type FastifyHelmetOptions = {
    enableCSPNonces?: boolean,
    global?: boolean;
  } & NonNullable<HelmetOptions>

  export const fastifyHelmet: FastifyHelmetPlugin
  export { fastifyHelmet as default }
}

declare function fastifyHelmet (...params: Parameters<fastifyHelmet.FastifyHelmetPlugin>): ReturnType<fastifyHelmet.FastifyHelmetPlugin>
export = fastifyHelmet
