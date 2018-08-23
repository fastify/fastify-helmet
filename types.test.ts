import fastifyHelmet = require("../fastify-helmet");
import fastify = require("fastify");

const app = fastify();

app.register(fastifyHelmet, { hpkp: true });
