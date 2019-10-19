// Type definitions for fastify-helmet
// Types are heavily based on the type definitions from helmet

import * as fastify from 'fastify';
import * as http from 'http';


declare let fastifyHelmet: fastify.Plugin<
  http.Server,
  http.IncomingMessage,
  http.ServerResponse,
  fastifyHelmet.FastifyHelmetOptions
>;

export = fastifyHelmet;

declare namespace fastifyHelmet {

  interface FastifyHelmetOptions {
    contentSecurityPolicy?: boolean | IHelmetContentSecurityPolicyConfiguration;
    dnsPrefetchControl?: boolean | IHelmetDnsPrefetchControlConfiguration;
    expectCt?: boolean | IHelmetExpectCtConfiguration;
    featurePolicy?: IHelmetFeaturePolicyConfigurationStrict | IHelmetFeaturePolicyConfiguration;
    frameguard?: boolean | IHelmetFrameguardConfiguration;
    hidePoweredBy?: boolean | IHelmetHidePoweredByConfiguration;
    hpkp?: boolean | IHelmetHpkpConfiguration;
    hsts?: boolean | IHelmetHstsConfiguration;
    ieNoOpen?: boolean;
    noCache?: boolean;
    noSniff?: boolean;
    permittedCrossDomainPolicies?: boolean | IHelmetPermittedCrossDomainPoliciesConfiguration;
    referrerPolicy?: boolean | IHelmetReferrerPolicyConfiguration;
    xssFilter?: boolean | IHelmetXssFilterConfiguration;
  }

  interface IHelmetPermittedCrossDomainPoliciesConfiguration {
    permittedPolicies?: string;
  }

  interface IHelmetContentSecurityPolicyDirectiveFunction {
    (req: fastify.FastifyRequest<http.IncomingMessage>, res: fastify.FastifyReply<http.ServerResponse>): string;
  }

  type HelmetCspDirectiveValue = string | IHelmetContentSecurityPolicyDirectiveFunction;

  type HelmetCspSandboxDirective =
    | string
    | 'allow-forms'
    | 'allow-modals'
    | 'allow-orientation-lock'
    | 'allow-pointer-lock'
    | 'allow-popups-to-escape-sandbox'
    | 'allow-popups'
    | 'allow-presentation'
    | 'allow-same-origin'
    | 'allow-scripts'
    | 'allow-top-navigation';

  type HelmetCspRequireSriForValue = string | 'script' | 'style';

  interface IHelmetContentSecurityPolicyDirectives {
    baseUri?: HelmetCspDirectiveValue[];
    blockAllMixedContent?: boolean;
    childSrc?: HelmetCspDirectiveValue[];
    connectSrc?: HelmetCspDirectiveValue[];
    defaultSrc?: HelmetCspDirectiveValue[];
    fontSrc?: HelmetCspDirectiveValue[];
    formAction?: HelmetCspDirectiveValue[];
    frameAncestors?: HelmetCspDirectiveValue[];
    frameSrc?: HelmetCspDirectiveValue[];
    imgSrc?: HelmetCspDirectiveValue[];
    manifestSrc?: HelmetCspDirectiveValue[];
    mediaSrc?: HelmetCspDirectiveValue[];
    objectSrc?: HelmetCspDirectiveValue[];
    pluginTypes?: HelmetCspDirectiveValue[];
    prefetchSrc?: HelmetCspDirectiveValue[];
    reportTo?: HelmetCspDirectiveValue;
    reportUri?: HelmetCspDirectiveValue;
    requireSriFor?: HelmetCspRequireSriForValue[];
    sandbox?: HelmetCspSandboxDirective[] | true;
    scriptSrc?: HelmetCspDirectiveValue[];
    styleSrc?: HelmetCspDirectiveValue[];
    upgradeInsecureRequests?: boolean;
    workerSrc?: HelmetCspDirectiveValue[];
  }

  interface IHelmetContentSecurityPolicyDirectives {
    'base-uri'?: HelmetCspDirectiveValue[];
    'block-all-mixed-content'?: boolean;
    'child-src'?: HelmetCspDirectiveValue[];
    'connect-src'?: HelmetCspDirectiveValue[];
    'default-src'?: HelmetCspDirectiveValue[];
    'font-src'?: HelmetCspDirectiveValue[];
    'form-action'?: HelmetCspDirectiveValue[];
    'frame-ancestors'?: HelmetCspDirectiveValue[];
    'frame-src'?: HelmetCspDirectiveValue[];
    'img-src'?: HelmetCspDirectiveValue[];
    'manifest-src'?: HelmetCspDirectiveValue[];
    'media-src'?: HelmetCspDirectiveValue[];
    'object-src'?: HelmetCspDirectiveValue[];
    'plugin-types'?: HelmetCspDirectiveValue[];
    'prefetch-src'?: HelmetCspDirectiveValue[];
    'report-to'?: HelmetCspDirectiveValue;
    'report-uri'?: HelmetCspDirectiveValue;
    'require-sri-for'?: HelmetCspRequireSriForValue[];
    sandbox?: HelmetCspSandboxDirective[] | true;
    'script-src'?: HelmetCspDirectiveValue;
    'style-src'?: HelmetCspDirectiveValue;
    'upgrade-insecure-requests'?: boolean;
    'worker-src'?: HelmetCspDirectiveValue;
  }

  interface IHelmetContentSecurityPolicyConfiguration {
    reportOnly?: boolean | ((req: fastify.FastifyRequest<http.IncomingMessage>, res: fastify.FastifyReply<http.ServerResponse>) => boolean);
    setAllHeaders?: boolean;
    disableAndroid?: boolean;
    browserSniff?: boolean;
    directives?: IHelmetContentSecurityPolicyDirectives;
    loose?: boolean;
  }

  interface IHelmetDnsPrefetchControlConfiguration {
    allow?: boolean;
  }

  interface IHelmetFeaturePolicyConfiguration {
    features: {
      [key: string]: string[];
    }
  }

  interface IHelmetFeaturePolicyConfigurationStrict {
    features: {
      geolocation?: string[];
      midi?: string[];
      notifications?: string[];
      push?: string[];
      syncXhr?: string[];
      microphone?: string[];
      camera?: string[];
      magnetometer?: string[];
      gyroscope?: string[];
      speaker?: string[];
      vibrate?: string[];
      fullscreen?: string[];
      payment?: string[];
      accelerometer?: string[];
      usb?: string[];
      vr?: string[];
      autoplay?: string[];
    }
  }

  interface IHelmetFrameguardConfiguration {
    action?: string;
    domain?: string;
  }

  interface IHelmetHidePoweredByConfiguration {
    setTo?: string;
  }

  interface IHelmetSetIfFunction {
    (req: fastify.FastifyRequest<http.IncomingMessage>, res: fastify.FastifyReply<http.ServerResponse>): boolean;
  }

  interface IHelmetHpkpConfiguration {
    maxAge: number;
    sha256s: string[];
    includeSubdomains?: boolean;
    reportUri?: string;
    reportOnly?: boolean;
    setIf?: IHelmetSetIfFunction;
  }

  interface IHelmetHstsConfiguration {
    maxAge?: number;
    includeSubdomains?: boolean;
    preload?: boolean;
    setIf?: IHelmetSetIfFunction;
    force?: boolean;
  }

  interface IHelmetReferrerPolicyConfiguration {
    policy?: string;
  }

  interface IHelmetXssFilterConfiguration {
    setOnOldIE?: boolean;
  }

  interface IHelmetExpectCtConfiguration {
    enforce?: boolean;
    maxAge?: number;
    reportUri?: string;
  }
}
