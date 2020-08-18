import { FastifyPlugin } from "fastify";
import * as helmet from "helmet";

type FastifyHelmetOptions = Parameters<typeof helmet>[0];

export const fastifyHelmet: FastifyPlugin<FastifyHelmetOptions>;

export default fastifyHelmet;
