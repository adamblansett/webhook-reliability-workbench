import { describe, it, expect } from 'vitest';
import {
  generateSyntheticWebhook,
  listAvailableTemplates,
} from '../src/testing/generator.js';
import { verifySignature } from '../src/signatures/verifier.js';

describe('Synthetic Webhook Generator & Templates', () => {
  it('lists available templates across all supported providers', () => {
    const list = listAvailableTemplates();
    expect(list.length).toBeGreaterThanOrEqual(5);

    const providers = list.map((l) => l.provider);
    expect(providers).toContain('stripe');
    expect(providers).toContain('github');
    expect(providers).toContain('shopify');
    expect(providers).toContain('slack');
    expect(providers).toContain('svix');
  });

  it('generates a Stripe payment_intent.succeeded webhook verifiable by verifySignature', () => {
    const secret = 'whsec_test_secret_123';
    const generated = generateSyntheticWebhook('stripe', 'payment_intent.succeeded', {
      secret,
    });

    expect(generated.provider).toBe('stripe');
    expect(generated.eventType).toBe('payment_intent.succeeded');
    expect(generated.headers['stripe-signature']).toBeDefined();

    // Verify signature with workbench verifier
    const verifyResult = verifySignature(
      generated.rawBody,
      {
        secret,
        algorithm: 'sha256',
        toleranceSeconds: 300,
      },
      generated.headers['stripe-signature'],
    );

    expect(verifyResult.valid).toBe(true);
    expect((generated.body as Record<string, unknown>).type).toBe(
      'payment_intent.succeeded',
    );
  });

  it('generates a GitHub push webhook verifiable by verifySignature', () => {
    const secret = 'ghp_secret_key_456';
    const generated = generateSyntheticWebhook('github', 'push', { secret });

    expect(generated.headers['x-hub-signature-256']).toBeDefined();
    expect(generated.headers['x-github-event']).toBe('push');

    const verifyResult = verifySignature(
      generated.rawBody,
      {
        secret,
        algorithm: 'sha256',
        prefix: 'sha256=',
      },
      generated.headers['x-hub-signature-256'],
    );

    expect(verifyResult.valid).toBe(true);
  });

  it('generates a Shopify orders/create webhook verifiable by verifySignature', () => {
    const secret = 'shpss_secret_key_789';
    const generated = generateSyntheticWebhook('shopify', 'orders/create', { secret });

    expect(generated.headers['x-shopify-hmac-sha256']).toBeDefined();
    expect(generated.headers['x-shopify-topic']).toBe('orders/create');

    const verifyResult = verifySignature(
      generated.rawBody,
      {
        secret,
        algorithm: 'sha256',
        encoding: 'base64',
      },
      generated.headers['x-shopify-hmac-sha256'],
    );

    expect(verifyResult.valid).toBe(true);
  });

  it('generates a Svix / Standard Webhook verifiable by verifySignature', () => {
    const secret = 'whsec_svix_secret_key_abc';
    const generated = generateSyntheticWebhook('svix', 'user.created', { secret });

    expect(generated.headers['webhook-signature']).toBeDefined();
    expect(generated.headers['webhook-timestamp']).toBeDefined();
    expect(generated.headers['webhook-id']).toBeDefined();

    const verifyResult = verifySignature(
      generated.rawBody,
      {
        secret,
        algorithm: 'sha256',
        encoding: 'base64',
        prefix: 'v1,',
        messageId: generated.headers['webhook-id'],
        timestamp: generated.headers['webhook-timestamp'],
        toleranceSeconds: 300,
      },
      generated.headers['webhook-signature'],
    );

    expect(verifyResult.valid).toBe(true);
  });

  it('throws informative error on unknown provider or event', () => {
    expect(() => generateSyntheticWebhook('unknown-provider', 'test')).toThrowError(
      'Unknown provider "unknown-provider"',
    );

    expect(() => generateSyntheticWebhook('stripe', 'non.existent.event')).toThrowError(
      'Unknown event type "non.existent.event" for provider "stripe"',
    );
  });
});
