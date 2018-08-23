import * as fastify from "fastify";
import * as http from "http";

declare module fastifyHelmet {
  interface FastifyHelmetOptions {
    contentSecurityPolicy?: any;
    dnsPrefetchControl?: any;
    expectCt?: any;
    frameguard?: any;
    hidePoweredBy?: any;
    hpkp?: any;
    hsts?: any;
    ieNoOpen?: any;
    noCache?: any;
    noSniff?: any;
    referrerPolicy?: any;
    xssFilter?: any;
  }
}

declare let fastifyHelmet: fastify.Plugin<
  http.Server,
  http.IncomingMessage,
  http.ServerResponse,
  fastifyHelmet.FastifyHelmetOptions
>;

export = fastifyHelmet;
