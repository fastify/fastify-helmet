import { FastifyPluginCallback } from "fastify";
import helmet = require("helmet");

type FastifyHelmetOptions = Parameters<typeof helmet>[0];

export const fastifyHelmet: FastifyPluginCallback<NonNullable<FastifyHelmetOptions>>;

export default fastifyHelmet;
