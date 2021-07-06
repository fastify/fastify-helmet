import { FastifyPluginCallback } from "fastify";
import helmet = require("helmet");

declare module 'fastify' {
  interface FastifyReply {
    cspNonce: {
      script: string
      style: string
    }
  }
}

type FastifyHelmetOptions = Parameters<typeof helmet>[0] & { enableCSPNonces?: boolean };

export const fastifyHelmet: FastifyPluginCallback<NonNullable<FastifyHelmetOptions>> & {
  contentSecurityPolicy: typeof helmet.contentSecurityPolicy;
};

export default fastifyHelmet;
