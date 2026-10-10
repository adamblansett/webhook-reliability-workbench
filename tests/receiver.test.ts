import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { createReceiver, ReceiverSecurityError } from '../src/receiver/server.js';
import { InMemoryEventStore } from '../src/events/store.js';
import { computeHmacDigest } from '../src/signatures/verifier.js';

describe('Local Webhook Receiver', () => {
  let receiver: ReturnType<typeof createReceiver> | null = null;
  let store: InMemoryEventStore;

  beforeEach(() => {
    store = new InMemoryEventStore();
  });

  afterEach(async () => {
    if (receiver) {
      await receiver.stop();
      receiver = null;
    }
  });

  async function sendRequest(
    url: string,
    options: {
      method?: string;
      headers?: Record<string, string>;
      body?: string | Buffer;
    } = {},
  ): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
    const parsed = new URL(url);

    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: parsed.hostname,
          port: parsed.port,
          path: `${parsed.pathname}${parsed.search}`,
          method: options.method ?? 'POST',
          headers: {
            connection: 'close',
            ...(options.headers ?? {}),
          },
        },
        (res) => {
          let responseBody = '';
          res.on('data', (chunk) => {
            responseBody += chunk.toString('utf8');
          });
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode ?? 0,
              headers: res.headers,
              body: responseBody,
            });
          });
        },
      );

      req.on('error', reject);

      if (options.body) {
        req.write(options.body);
      }
      req.end();
    });
  }

  it('starts on an ephemeral port and shuts down gracefully', async () => {
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      store,
      silent: true,
    });

    const info = await receiver.start();
    expect(info.port).toBeGreaterThan(0);
    expect(info.url).toContain(`:${info.port}`);

    // Health check
    const healthRes = await sendRequest(
      `http://127.0.0.1:${info.port}/__workbench/health`,
      {
        method: 'GET',
      },
    );
    expect(healthRes.statusCode).toBe(200);
    const healthJson = JSON.parse(healthRes.body);
    expect(healthJson.status).toBe('healthy');

    await receiver.stop();
    receiver = null;
  });

  it('rejects binding to external interfaces without allowExternal', () => {
    expect(() => {
      createReceiver({
        host: '0.0.0.0',
        port: 0,
        silent: true,
      });
    }).toThrowError(ReceiverSecurityError);
  });

  it('captures POST request metadata, headers, query parameters, and raw body', async () => {
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      store,
      silent: true,
    });
    const info = await receiver.start();

    const payload = JSON.stringify({ event: 'invoice.paid', amount: 5000 });
    const res = await sendRequest(
      `http://127.0.0.1:${info.port}/webhooks?env=test&batch=1`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-custom-header': 'WorkbenchTest',
        },
        body: payload,
      },
    );

    expect(res.statusCode).toBe(200);

    const events = await store.list();
    expect(events.length).toBe(1);

    const event = events[0]!;
    expect(event.method).toBe('POST');
    expect(event.path).toBe('/webhooks');
    expect(event.query).toEqual({ env: 'test', batch: '1' });
    expect(event.headers['x-custom-header']).toBe('WorkbenchTest');
    expect(event.rawBody).toBe(payload);
    expect(event.isJson).toBe(true);
    expect(event.body).toEqual({ event: 'invoice.paid', amount: 5000 });
    expect(event.jsonError).toBeNull();
  });

  it('handles malformed JSON without crashing and flags jsonError', async () => {
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      store,
      silent: true,
    });
    const info = await receiver.start();

    const malformed = '{"event": "broken", invalid_json';
    const res = await sendRequest(`http://127.0.0.1:${info.port}/test`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: malformed,
    });

    expect(res.statusCode).toBe(200);

    const events = await store.list();
    expect(events.length).toBe(1);
    const event = events[0]!;
    expect(event.isJson).toBe(false);
    expect(event.rawBody).toBe(malformed);
    expect(event.body).toBeNull();
    expect(event.jsonError).not.toBeNull();
  });

  it('enforces request size limit and returns HTTP 413 Payload Too Large', async () => {
    const smallLimit = 512; // 512 bytes limit
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      maxBodySize: smallLimit,
      store,
      silent: true,
    });
    const info = await receiver.start();

    // Send payload exceeding limit
    const largeBody = 'A'.repeat(2048);

    try {
      const res = await sendRequest(`http://127.0.0.1:${info.port}/large`, {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: largeBody,
      });

      expect(res.statusCode).toBe(413);
      const json = JSON.parse(res.body);
      expect(json.error).toBe('Payload Too Large');
    } catch {
      // Stream destroyed by server on size excess is also a valid outcome
    }

    // Event should not be stored because it was rejected
    expect(await store.count()).toBe(0);
  });

  it('simulates HTTP failure status code (e.g. 500 Internal Server Error)', async () => {
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      responseStatus: 500,
      responseBody: JSON.stringify({ error: 'Database connection failed' }),
      store,
      silent: true,
    });
    const info = await receiver.start();

    const res = await sendRequest(`http://127.0.0.1:${info.port}/hooks`, {
      method: 'POST',
      body: 'ping',
    });

    expect(res.statusCode).toBe(500);
    const body = JSON.parse(res.body);
    expect(body.error).toBe('Database connection failed');

    const event = (await store.list())[0]!;
    expect(event.responseStatus).toBe(500);
  });

  it('simulates artificial response delay', async () => {
    const delayMs = 150;
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      delayMs,
      store,
      silent: true,
    });
    const info = await receiver.start();

    const start = Date.now();
    const res = await sendRequest(`http://127.0.0.1:${info.port}/delayed`, {
      method: 'POST',
      body: 'test',
    });
    const elapsed = Date.now() - start;

    expect(res.statusCode).toBe(200);
    expect(elapsed).toBeGreaterThanOrEqual(delayMs - 30);
  });

  it('verifies incoming HMAC signatures when secret is configured', async () => {
    const secret = 'webhook-receiver-secret';
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      secret,
      signatureHeader: 'x-hub-signature-256',
      signaturePrefix: 'sha256=',
      store,
      silent: true,
    });
    const info = await receiver.start();

    const payload = JSON.stringify({ user: 'alice', action: 'login' });
    const validDigest = computeHmacDigest(payload, secret, 'sha256');

    // 1. Request with VALID signature
    await sendRequest(`http://127.0.0.1:${info.port}/secure`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': `sha256=${validDigest}`,
      },
      body: payload,
    });

    // 2. Request with INVALID signature
    await sendRequest(`http://127.0.0.1:${info.port}/secure`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': 'sha256=invalidhex000000000000000000000000',
      },
      body: payload,
    });

    const events = await store.list();
    expect(events.length).toBe(2);

    // Newest first: event 0 was invalid, event 1 was valid
    expect(events[0]?.signature?.valid).toBe(false);
    expect(events[1]?.signature?.valid).toBe(true);
  });

  it('enforces webhook path filtering when specific path is configured', async () => {
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      path: '/api/v1/webhooks',
      store,
      silent: true,
    });
    const info = await receiver.start();

    // Request to matching path
    const validPathRes = await sendRequest(
      `http://127.0.0.1:${info.port}/api/v1/webhooks`,
      {
        method: 'POST',
        body: 'ok',
      },
    );
    expect(validPathRes.statusCode).toBe(200);

    // Request to non-matching path
    const wrongPathRes = await sendRequest(`http://127.0.0.1:${info.port}/other-path`, {
      method: 'POST',
      body: 'nope',
    });
    expect(wrongPathRes.statusCode).toBe(404);
  });
});
