import { FastifyPluginCallback } from "fastify";
import helmet from "helmet";
import contentSecurityPolicy from "helmet/dist/middlewares/content-security-policy";

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
  contentSecurityPolicy: typeof contentSecurityPolicy;
};

export default fastifyHelmet;
