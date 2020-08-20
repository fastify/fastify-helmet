import { FastifyPlugin } from "fastify";
import helmet from "helmet";

type FastifyHelmetOptions = Parameters<typeof helmet>[0];

export const fastifyHelmet: FastifyPlugin<NonNullable<FastifyHelmetOptions>>;

export default fastifyHelmet;
