import * as http from "http";
import * as https from "https";
import * as http2 from "http2";
import fastifyHelmet, { IHelmetContentSecurityPolicyConfiguration } from ".";
import fastify from "fastify";
import { expectType } from 'tsd';

const app = fastify();

app.register(fastifyHelmet);
app.register(fastifyHelmet, {});
app.register(fastifyHelmet, { frameguard: false });
app.register(fastifyHelmet, { frameguard: true });

const appWithHttp2 = fastify({ http2: true });
appWithHttp2.register(fastifyHelmet, {});
appWithHttp2.register(fastifyHelmet, {
  frameguard: {
    action: "deny"
  },
  contentSecurityPolicy: {
    directives: {
      scriptSrc: ["scripts.example.com", (req, res) => {
        expectType<http.IncomingMessage | http2.Http2ServerRequest>(req);
        expectType<http.ServerResponse | http2.Http2ServerResponse>(res);

        // Discriminating union
        if ('authority' in req) {
          expectType<http2.Http2ServerRequest>(req);
        } else {
          expectType<http.IncomingMessage>(req);
        }

        // Discriminating union
        if ('createPushResponse' in res) {
          expectType<http2.Http2ServerResponse>(res);
        } else {
          expectType<http.ServerResponse>(res);
        }

        return "'nonce-abc123'";
      }],
    }
  }
});

function contentSecurityPolicyTest() {
  const emptyArray: string[] = [];
  const config: IHelmetContentSecurityPolicyConfiguration = {
    directives: {
      baseUri: ["base.example.com"],
      blockAllMixedContent: true,
      childSrc: ["child.example.com"],
      connectSrc: ["connect.example.com"],
      defaultSrc: ["*"],
      fontSrc: ["font.example.com"],
      formAction: ["formaction.example.com"],
      frameAncestors: ["'none'"],
      frameSrc: emptyArray,
      imgSrc: ["images.example.com"],
      mediaSrc: ["media.example.com"],
      manifestSrc: ["manifest.example.com"],
      objectSrc: ["objects.example.com"],
      pluginTypes: emptyArray,
      prefetchSrc: ["prefetch.example.com"],
      reportUri: "/some-url",
      reportTo: "report.example.com",
      requireSriFor: emptyArray,
      sandbox: ["allow-presentation"],
      scriptSrc: [
        "scripts.example.com",
        (_req, _res) => "'nonce-abc123'"
      ],
      styleSrc: ["css.example.com"],
      upgradeInsecureRequests: true,
      workerSrc: ["worker.example.com"]
    },
    reportOnly: false,
    setAllHeaders: false,
    disableAndroid: false
  };

  const configWithBooleanSandbox: IHelmetContentSecurityPolicyConfiguration = {
    directives: {
      baseUri: ["base.example.com"],
      blockAllMixedContent: true,
      childSrc: ["child.example.com"],
      connectSrc: ["connect.example.com"],
      defaultSrc: ["*"],
      fontSrc: ["font.example.com"],
      formAction: ["formaction.example.com"],
      frameAncestors: ["'none'"],
      frameSrc: emptyArray,
      imgSrc: ["images.example.com"],
      mediaSrc: ["media.example.com"],
      manifestSrc: ["manifest.example.com"],
      objectSrc: ["objects.example.com"],
      pluginTypes: emptyArray,
      prefetchSrc: ["prefetch.example.com"],
      reportUri: "/some-url",
      reportTo: "report.example.com",
      requireSriFor: emptyArray,
      sandbox: true,
      scriptSrc: [
        "scripts.example.com",
        (_req, _res) => "'nonce-abc123'"
      ],
      styleSrc: ["css.example.com"],
      upgradeInsecureRequests: true,
      workerSrc: ["worker.example.com"]
    },
    reportOnly: false,
    setAllHeaders: false,
    disableAndroid: false
  };

  app.register(fastifyHelmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        reportUri: (_req, _res) => "/some-uri",
        "report-uri": (_req, _res) => "/some-uri",
        reportTo: (_req, _res) => "/some-uri",
        "report-to": (_req, _res) => "/some-uri"
      },
      reportOnly: (_req, _res) => false,
      loose: false,
      setAllHeaders: true
    }
  });
}

function dnsPrefetchControlTest() {
  app.register(fastifyHelmet, { dnsPrefetchControl: {} });
  app.register(fastifyHelmet, { dnsPrefetchControl: { allow: false } });
  app.register(fastifyHelmet, { dnsPrefetchControl: { allow: true } });
}

function featurePolicyTest() {
  app.register(fastifyHelmet, { featurePolicy: { features: { notifications: ['self'] } } });
  app.register(fastifyHelmet, { featurePolicy: { features: { supportedButNotYetTyped: ["'self'"] } } });
}

function frameguardTest() {
  app.register(fastifyHelmet, { frameguard: {} });
  app.register(fastifyHelmet, { frameguard: { action: "deny" } });
  app.register(fastifyHelmet, { frameguard: { action: "sameorigin" } });
  app.register(fastifyHelmet, {
    frameguard: {
      action: "allow-from",
      domain: "http://example.com"
    }
  });
}

function hidePoweredBy() {
  app.register(fastifyHelmet, { hidePoweredBy: {} });
  app.register(fastifyHelmet, { hidePoweredBy: { setTo: "PHP 4.2.0" } });
}

function hpkpTest() {
  app.register(fastifyHelmet, { hpkp: true });

  app.register(fastifyHelmet, {
    hpkp: {
      maxAge: 7776000000,
      sha256s: ["AbCdEf123=", "ZyXwVu456="]
    }
  });

  app.register(fastifyHelmet, {
    hpkp: {
      maxAge: 7776000000,
      sha256s: ["AbCdEf123=", "ZyXwVu456="],
      includeSubdomains: false
    }
  });

  app.register(fastifyHelmet, {
    hpkp: {
      maxAge: 7776000000,
      sha256s: ["AbCdEf123=", "ZyXwVu456="],
      includeSubdomains: true
    }
  });

  app.register(fastifyHelmet, {
    hpkp: {
      maxAge: 7776000000,
      sha256s: ["AbCdEf123=", "ZyXwVu456="],
      reportUri: "http://example.com"
    }
  });

  app.register(fastifyHelmet, {
    hpkp: {
      maxAge: 7776000000,
      sha256s: ["AbCdEf123=", "ZyXwVu456="],
      reportOnly: true
    }
  });

  app.register(fastifyHelmet, {
    hpkp: {
      maxAge: 7776000000,
      sha256s: ["AbCdEf123=", "ZyXwVu456="],
      setIf: function (req, res) {
        return true;
      }
    }
  });
}

function hstsTest() {
  app.register(fastifyHelmet, { hsts: { maxAge: 7776000000 } });

  app.register(fastifyHelmet, {
    hsts: {
      maxAge: 7776000000
    }
  });

  app.register(fastifyHelmet, {
    hsts: {
      maxAge: 7776000000,
      includeSubdomains: true
    }
  });

  app.register(fastifyHelmet, {
    hsts: {
      maxAge: 7776000000,
      preload: true
    }
  });

  app.register(fastifyHelmet, {
    hsts: {
      maxAge: 7776000000,
      force: true
    }
  });

  app.register(fastifyHelmet, {
    hsts: {
      maxAge: 7776000000,
      setIf: function (req, res) {
        return true;
      }
    }
  });
}

function ieNoOpenTest() {
  app.register(fastifyHelmet, { ieNoOpen: true });
  app.register(fastifyHelmet, { ieNoOpen: undefined });
}

function noCacheTest() {
  app.register(fastifyHelmet, { noCache: true });
  app.register(fastifyHelmet, { noCache: false });
}

function noSniffTest() {
  app.register(fastifyHelmet, { noSniff: true });
  app.register(fastifyHelmet, { noSniff: false });
}

function referrerPolicyTest() {
  app.register(fastifyHelmet, { referrerPolicy: { policy: "same-origin" } });
}

function xssFilterTest() {
  app.register(fastifyHelmet, { xssFilter: {} });
  app.register(fastifyHelmet, { xssFilter: { setOnOldIE: false } });
  app.register(fastifyHelmet, { xssFilter: { setOnOldIE: true } });
}

function permittedCrossDomainPoliciesTest() {
  app.register(fastifyHelmet, { permittedCrossDomainPolicies: true });
  app.register(fastifyHelmet, {
    permittedCrossDomainPolicies: { permittedPolicies: "none" }
  });
}
