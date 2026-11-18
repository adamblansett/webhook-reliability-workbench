import crypto from 'node:crypto';
import { computeHmacDigest } from '../signatures/verifier.js';
import { getProviderPreset } from '../signatures/presets.js';

export interface GeneratedWebhook {
  provider: string;
  eventType: string;
  headers: Record<string, string>;
  rawBody: string;
  body: unknown;
  method: string;
}

export interface GenerateWebhookOptions {
  secret?: string;
  timestamp?: number;
  messageId?: string;
  customPayload?: Record<string, unknown>;
}

export const TEMPLATES: Record<string, Record<string, () => Record<string, unknown>>> = {
  stripe: {
    'payment_intent.succeeded': () => ({
      id: `evt_test_${Date.now()}`,
      object: 'event',
      api_version: '2023-10-16',
      created: Math.floor(Date.now() / 1000),
      type: 'payment_intent.succeeded',
      data: {
        object: {
          id: `pi_${crypto.randomBytes(8).toString('hex')}`,
          object: 'payment_intent',
          amount: 2000,
          currency: 'usd',
          status: 'succeeded',
          payment_method: `pm_${crypto.randomBytes(6).toString('hex')}`,
        },
      },
    }),
    'charge.refunded': () => ({
      id: `evt_test_${Date.now()}`,
      object: 'event',
      type: 'charge.refunded',
      data: {
        object: {
          id: `ch_${crypto.randomBytes(8).toString('hex')}`,
          amount_refunded: 1500,
          currency: 'usd',
          refunded: true,
        },
      },
    }),
    'customer.subscription.created': () => ({
      id: `evt_test_${Date.now()}`,
      object: 'event',
      type: 'customer.subscription.created',
      data: {
        object: {
          id: `sub_${crypto.randomBytes(8).toString('hex')}`,
          customer: `cus_${crypto.randomBytes(6).toString('hex')}`,
          status: 'active',
          current_period_end: Math.floor(Date.now() / 1000) + 86400 * 30,
        },
      },
    }),
  },
  github: {
    push: () => ({
      ref: 'refs/heads/main',
      before: crypto.randomBytes(20).toString('hex'),
      after: crypto.randomBytes(20).toString('hex'),
      repository: {
        id: 12345678,
        name: 'sample-repo',
        full_name: 'octocat/sample-repo',
        private: false,
      },
      pusher: {
        name: 'octocat',
        email: 'octocat@github.com',
      },
    }),
    pull_request: () => ({
      action: 'opened',
      number: 42,
      pull_request: {
        id: 987654321,
        title: 'Fix webhook retry edge case',
        state: 'open',
        user: { login: 'octocat' },
      },
    }),
    ping: () => ({
      zen: 'Approachable is better than simple.',
      hook_id: 12345,
      hook: {
        type: 'Repository',
        active: true,
        events: ['push', 'pull_request'],
      },
    }),
  },
  shopify: {
    'orders/create': () => ({
      id: 820982911946154500,
      email: 'customer@example.com',
      created_at: new Date().toISOString(),
      total_price: '199.00',
      currency: 'USD',
      financial_status: 'paid',
      line_items: [
        {
          id: 1,
          title: 'Mechanical Keyboard',
          quantity: 1,
          price: '199.00',
        },
      ],
    }),
  },
  slack: {
    app_mention: () => ({
      token: 'verification-token-123',
      team_id: 'T012AB34CDE',
      api_app_id: 'A012XYZ987',
      event: {
        type: 'app_mention',
        user: 'U12345678',
        text: '<@U0123BOT> deploy latest build',
        ts: `${Date.now() / 1000}`,
        channel: 'C01234567',
      },
      type: 'event_callback',
    }),
  },
  svix: {
    'user.created': () => ({
      type: 'user.created',
      timestamp: new Date().toISOString(),
      data: {
        id: `usr_${crypto.randomBytes(6).toString('hex')}`,
        email: 'user@example.com',
        username: 'workbench_tester',
      },
    }),
  },
};

export function listAvailableTemplates(): Array<{
  provider: string;
  eventTypes: string[];
}> {
  return Object.entries(TEMPLATES).map(([provider, events]) => ({
    provider,
    eventTypes: Object.keys(events),
  }));
}

/**
 * Generates a realistic mock webhook payload with appropriate headers and cryptographic signature.
 */
export function generateSyntheticWebhook(
  providerName: string,
  eventType: string,
  options: GenerateWebhookOptions = {},
): GeneratedWebhook {
  const normProvider = providerName.toLowerCase().trim();
  const providerTemplates = TEMPLATES[normProvider];
  if (!providerTemplates) {
    throw new Error(
      `Unknown provider "${providerName}". Available providers: ${Object.keys(TEMPLATES).join(', ')}`,
    );
  }

  const templateFactory = providerTemplates[eventType];
  if (!templateFactory) {
    throw new Error(
      `Unknown event type "${eventType}" for provider "${normProvider}". Available: ${Object.keys(providerTemplates).join(', ')}`,
    );
  }

  const payloadObject = options.customPayload ?? templateFactory();
  const rawBody = JSON.stringify(payloadObject, null, 2);
  const secret = options.secret ?? 'whsec_test_secret_key_12345';
  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
  const messageId = options.messageId ?? `msg_${crypto.randomBytes(8).toString('hex')}`;

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'user-agent': `Webhook-Workbench-Trigger/0.1.0 (${normProvider})`,
  };

  const preset = getProviderPreset(normProvider);

  if (normProvider === 'stripe') {
    const toSign = `${timestamp}.${rawBody}`;
    const digest = computeHmacDigest(toSign, secret, 'sha256', 'hex');
    headers['stripe-signature'] = `t=${timestamp},v1=${digest}`;
  } else if (normProvider === 'github') {
    const digest = computeHmacDigest(rawBody, secret, 'sha256', 'hex');
    headers['x-hub-signature-256'] = `sha256=${digest}`;
    headers['x-github-event'] = eventType;
    headers['x-github-delivery'] = crypto.randomUUID();
  } else if (normProvider === 'shopify') {
    const digest = computeHmacDigest(rawBody, secret, 'sha256', 'base64');
    headers['x-shopify-hmac-sha256'] = digest;
    headers['x-shopify-topic'] = eventType;
    headers['x-shopify-shop-domain'] = 'test-store.myshopify.com';
  } else if (normProvider === 'slack') {
    const toSign = `v0:${timestamp}:${rawBody}`;
    const digest = computeHmacDigest(toSign, secret, 'sha256', 'hex');
    headers['x-slack-signature'] = `v0=${digest}`;
    headers['x-slack-request-timestamp'] = String(timestamp);
  } else if (normProvider === 'svix') {
    const toSign = `${messageId}.${timestamp}.${rawBody}`;
    const digest = computeHmacDigest(toSign, secret, 'sha256', 'base64');
    headers['webhook-id'] = messageId;
    headers['webhook-timestamp'] = String(timestamp);
    headers['webhook-signature'] = `v1,${digest}`;
  } else if (preset) {
    const digest = computeHmacDigest(
      rawBody,
      secret,
      preset.algorithm as 'sha256',
      preset.encoding,
    );
    const prefix = preset.signaturePrefix ?? '';
    headers[preset.signatureHeader] = `${prefix}${digest}`;
  }

  return {
    provider: normProvider,
    eventType,
    headers,
    rawBody,
    body: payloadObject,
    method: 'POST',
  };
}
