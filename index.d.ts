import { FastifyPluginCallback } from "fastify";
import helmet from "helmet";

declare module 'fastify' {
  interface FastifyReply {
    cspNonce: {
      script: string
      style: string
    }
  }
}

export type FastifyHelmetOptions = NonNullable<Parameters<typeof helmet>[0] & { enableCSPNonces?: boolean }>;

export const fastifyHelmet: FastifyPluginCallback<FastifyHelmetOptions> & {
  contentSecurityPolicy: typeof helmet.contentSecurityPolicy;
};

export default fastifyHelmet;
