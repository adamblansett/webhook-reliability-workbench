import { describe, it, expect } from 'vitest';
import {
  generateTypeScriptTypes,
  generateZodSchema,
} from '../src/codegen/typeGenerator.js';
import { generateCurlCommand } from '../src/codegen/curlGenerator.js';
import type { WebhookEvent } from '../src/events/types.js';

describe('Codegen: Type Generator & cURL Exporter', () => {
  const samplePayload = {
    id: 'evt_stripe_999',
    type: 'payment_intent.succeeded',
    created: 1718000000,
    livemode: false,
    data: {
      object: {
        id: 'pi_3MtwBwLkdIwHu7ix28a3tqPa',
        amount: 2000,
        currency: 'usd',
        status: 'succeeded',
        metadata: {
          customer_name: 'Jane Doe',
          order_id: 'ord_123',
        },
      },
    },
    tags: ['stripe', 'payments'],
  };

  it('generates clean TypeScript interfaces from nested JSON', () => {
    const tsCode = generateTypeScriptTypes(samplePayload, 'StripePaymentEvent');

    expect(tsCode).toContain('export interface StripePaymentEvent');
    expect(tsCode).toContain('id: string;');
    expect(tsCode).toContain('created: number;');
    expect(tsCode).toContain('livemode: boolean;');
    expect(tsCode).toContain('tags: string[];');
    expect(tsCode).toContain('amount: number;');
  });

  it('generates executable Zod schemas and inferred types', () => {
    const zodCode = generateZodSchema(samplePayload, 'StripePaymentEvent');

    expect(zodCode).toContain("import { z } from 'zod';");
    expect(zodCode).toContain('export const StripePaymentEventSchema = z.object({');
    expect(zodCode).toContain('id: z.string(),');
    expect(zodCode).toContain('amount: z.number(),');
    expect(zodCode).toContain(
      'export type StripePaymentEvent = z.infer<typeof StripePaymentEventSchema>;',
    );
  });

  it('generates executable cURL command line with preserved headers and body', () => {
    const mockEvent: WebhookEvent = {
      id: 'evt_001',
      timestamp: '2026-10-10T12:00:00Z',
      method: 'POST',
      path: '/api/v1/webhooks',
      headers: {
        'content-type': 'application/json',
        'stripe-signature': 't=123,v1=abc',
        authorization: 'Bearer secret_token',
      },
      query: {},
      rawBody: '{"hello":"world"}',
      body: { hello: 'world' },
      isJson: true,
      jsonError: null,
      contentType: 'application/json',
      contentLength: 17,
      responseStatus: 200,
      durationMs: 15,
      signature: null,
      replays: [],
    };

    const curl = generateCurlCommand(mockEvent, {
      overrideUrl: 'http://localhost:3000/api/webhooks',
    });

    expect(curl).toContain('curl -X POST "http://localhost:3000/api/webhooks"');
    expect(curl).toContain('-H "content-type: application/json"');
    expect(curl).toContain('-H "stripe-signature: t=123,v1=abc"');
    expect(curl).toContain(`-d '{"hello":"world"}'`);
  });
});
