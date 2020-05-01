/// <reference types="node" />

import {
  FastifyRequest,
  FastifyReply,
  FastifyPlugin,
  RawRequestDefaultExpression,
  RawReplyDefaultExpression,
  RawServerBase,
} from 'fastify';

export interface IHelmetPermittedCrossDomainPoliciesConfiguration {
  permittedPolicies?: string;
}

export interface IHelmetContentSecurityPolicyDirectiveFunction {
  (req: RawRequestDefaultExpression<RawServerBase>, res: RawReplyDefaultExpression<RawServerBase>): string;
}

export type HelmetCspDirectiveValue = string | IHelmetContentSecurityPolicyDirectiveFunction;

export type HelmetCspSandboxDirective =
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

export type HelmetCspRequireSriForValue = string | 'script' | 'style';

export interface IHelmetContentSecurityPolicyDirectives {
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

export interface IHelmetContentSecurityPolicyDirectives {
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

export interface IHelmetContentSecurityPolicyConfiguration {
  reportOnly?: boolean | ((req: FastifyRequest, res: FastifyReply) => boolean);
  setAllHeaders?: boolean;
  disableAndroid?: boolean;
  browserSniff?: boolean;
  directives?: IHelmetContentSecurityPolicyDirectives;
  loose?: boolean;
}

export interface IHelmetDnsPrefetchControlConfiguration {
  allow?: boolean;
}

export interface IHelmetFeaturePolicyConfiguration {
  features: {
    [key: string]: string[];
  }
}

export interface IHelmetFeaturePolicyConfigurationStrict {
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

export interface IHelmetFrameguardConfiguration {
  action?: string;
  domain?: string;
}

export interface IHelmetHidePoweredByConfiguration {
  setTo?: string;
}

export interface IHelmetSetIfFunction {
  (req: FastifyRequest, res: FastifyReply): boolean;
}

export interface IHelmetHpkpConfiguration {
  maxAge: number;
  sha256s: string[];
  includeSubdomains?: boolean;
  reportUri?: string;
  reportOnly?: boolean;
  setIf?: IHelmetSetIfFunction;
}

export interface IHelmetHstsConfiguration {
  maxAge?: number;
  includeSubdomains?: boolean;
  preload?: boolean;
  setIf?: IHelmetSetIfFunction;
  force?: boolean;
}

export interface IHelmetReferrerPolicyConfiguration {
  policy?: string;
}

export interface IHelmetXssFilterConfiguration {
  setOnOldIE?: boolean;
}

export interface IHelmetExpectCtConfiguration {
  enforce?: boolean;
  maxAge?: number;
  reportUri?: string;
}

export interface FastifyHelmetOptions {
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

declare const fastifyHelmet: FastifyPlugin<FastifyHelmetOptions>;
export default fastifyHelmet;