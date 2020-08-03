import { FastifyPlugin } from 'fastify';
import { HelmetOptions } from 'helmet';

interface FastifyHelmetOptions extends HelmetOptions {}

declare const fastifyHelmet: FastifyPlugin<FastifyHelmetOptions>;
export = fastifyHelmet;