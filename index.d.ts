import { FastifyPluginCallback } from "fastify";
import * as helmet from "helmet";

type FastifyHelmetOptions = Parameters<typeof helmet>[0];

export const fastifyHelmet: FastifyPluginCallback<NonNullable<FastifyHelmetOptions>>;

export default fastifyHelmet;
