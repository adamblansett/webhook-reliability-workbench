import type { SupportedSignatureAlgorithm } from './types.js';

export interface WebhookProviderPreset {
  name: string;
  displayName: string;
  signatureHeader: string;
  algorithm: SupportedSignatureAlgorithm;
  signaturePrefix?: string;
  encoding: 'hex' | 'base64';
  toleranceSeconds?: number;
  timestampHeader?: string;
  idHeader?: string;
  description: string;
}

export const PROVIDER_PRESETS: Record<string, WebhookProviderPreset> = {
  stripe: {
    name: 'stripe',
    displayName: 'Stripe',
    signatureHeader: 'stripe-signature',
    algorithm: 'sha256',
    signaturePrefix: '',
    encoding: 'hex',
    toleranceSeconds: 300,
    description: 'Stripe webhook signature (HMAC-SHA256 with timestamp tolerance)',
  },
  github: {
    name: 'github',
    displayName: 'GitHub',
    signatureHeader: 'x-hub-signature-256',
    algorithm: 'sha256',
    signaturePrefix: 'sha256=',
    encoding: 'hex',
    description: 'GitHub webhook signature (HMAC-SHA256 with sha256= prefix)',
  },
  shopify: {
    name: 'shopify',
    displayName: 'Shopify',
    signatureHeader: 'x-shopify-hmac-sha256',
    algorithm: 'sha256',
    encoding: 'base64',
    description: 'Shopify webhook signature (base64-encoded HMAC-SHA256)',
  },
  slack: {
    name: 'slack',
    displayName: 'Slack',
    signatureHeader: 'x-slack-signature',
    algorithm: 'sha256',
    signaturePrefix: 'v0=',
    encoding: 'hex',
    toleranceSeconds: 300,
    timestampHeader: 'x-slack-request-timestamp',
    description: 'Slack events API signature (v0= with timestamp header)',
  },
  svix: {
    name: 'svix',
    displayName: 'Svix / Standard Webhooks',
    signatureHeader: 'webhook-signature',
    algorithm: 'sha256',
    signaturePrefix: 'v1,',
    encoding: 'base64',
    toleranceSeconds: 300,
    timestampHeader: 'webhook-timestamp',
    idHeader: 'webhook-id',
    description: 'Standard Webhooks specification (v1, base64 digest with timestamp)',
  },
};

export function getProviderPreset(name: string): WebhookProviderPreset | undefined {
  return PROVIDER_PRESETS[name.toLowerCase().trim()];
}

export function listProviderPresets(): WebhookProviderPreset[] {
  return Object.values(PROVIDER_PRESETS);
}
