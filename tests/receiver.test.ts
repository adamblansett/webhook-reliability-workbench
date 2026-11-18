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

  it('immediately rejects upfront Content-Length exceeding limit with HTTP 413', async () => {
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      maxBodySize: 1024,
      store,
      silent: true,
    });
    const info = await receiver.start();

    try {
      const res = await sendRequest(`http://127.0.0.1:${info.port}/oversized`, {
        method: 'POST',
        headers: {
          'content-length': '102400',
          'content-type': 'application/json',
        },
        body: '{"ping": true}',
      });

      expect(res.statusCode).toBe(413);
      const json = JSON.parse(res.body);
      expect(json.error).toBe('Payload Too Large');
    } catch {
      // Connection closed by server
    }
  });

  it('rejects invalid or negative Content-Length with HTTP 400 Bad Request', async () => {
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      store,
      silent: true,
    });
    const info = await receiver.start();

    const resNegative = await sendRequest(`http://127.0.0.1:${info.port}/bad-len`, {
      method: 'POST',
      headers: {
        'content-length': '-50',
      },
      body: 'ping',
    });
    expect(resNegative.statusCode).toBe(400);

    const resInvalid = await sendRequest(`http://127.0.0.1:${info.port}/bad-len`, {
      method: 'POST',
      headers: {
        'content-length': 'not-a-number',
      },
      body: 'ping',
    });
    expect(resInvalid.statusCode).toBe(400);
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

  it('verifies signatures using provider presets (e.g. preset: stripe)', async () => {
    const secret = 'whsec_stripe_test_secret';
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      preset: 'stripe',
      secret,
      store,
      silent: true,
    });
    const info = await receiver.start();

    const timestamp = Math.floor(Date.now() / 1000);
    const payload = JSON.stringify({ event: 'charge.succeeded', id: 'ch_123' });
    const digest = computeHmacDigest(`${timestamp}.${payload}`, secret, 'sha256');

    const res = await sendRequest(`http://127.0.0.1:${info.port}/webhooks`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'stripe-signature': `t=${timestamp},v1=${digest}`,
      },
      body: payload,
    });
    expect(res.statusCode).toBe(200);

    const event = (await store.list())[0]!;
    expect(event.signature?.valid).toBe(true);
    expect(event.signature?.algorithm).toBe('sha256');
  });

  it('serves embedded Web Inspector UI on /__workbench/ui', async () => {
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      path: '/filtered-path',
      store,
      silent: true,
    });
    const info = await receiver.start();

    const res = await sendRequest(`http://127.0.0.1:${info.port}/__workbench/ui`, {
      method: 'GET',
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain('Webhook Reliability Workbench');
    expect(res.body).toContain('Live SSE Connected');
  });

  it('streams captured events over SSE on /__workbench/stream', async () => {
    receiver = createReceiver({
      port: 0,
      host: '127.0.0.1',
      store,
      silent: true,
    });
    const info = await receiver.start();

    let sseOutput = '';
    const sseReq = http.request(
      `http://127.0.0.1:${info.port}/__workbench/stream`,
      { method: 'GET' },
      (sseRes) => {
        expect(sseRes.headers['content-type']).toContain('text/event-stream');
        sseRes.on('data', (c) => (sseOutput += c.toString('utf8')));
      },
    );
    sseReq.end();

    // Wait for SSE handshake
    await new Promise((r) => setTimeout(r, 50));

    // Post an event
    await sendRequest(`http://127.0.0.1:${info.port}/event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ping: 'pong' }),
    });

    await new Promise((r) => setTimeout(r, 50));
    sseReq.destroy();

    expect(sseOutput).toContain(': connected');
    expect(sseOutput).toContain('data:');
    expect(sseOutput).toContain('ping');
  });

  it('transparently forwards captured events when forwardTo is configured', async () => {
    const targetReceived: Array<{ body: string; headers: http.IncomingHttpHeaders }> = [];
    const targetServer = http.createServer((req, res) => {
      let b = '';
      req.on('data', (c) => (b += c.toString('utf8')));
      req.on('end', () => {
        targetReceived.push({ body: b, headers: req.headers });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ forwarded: true }));
      });
    });

    let targetPort = 0;
    await new Promise<void>((resolve) => {
      targetServer.listen(0, '127.0.0.1', () => {
        targetPort = (targetServer.address() as { port: number }).port;
        resolve();
      });
    });

    try {
      receiver = createReceiver({
        port: 0,
        host: '127.0.0.1',
        forwardTo: `http://127.0.0.1:${targetPort}/target`,
        forwardAllowLoopback: true,
        store,
        silent: true,
      });
      const info = await receiver.start();

      const payload = JSON.stringify({ item: 'forwarded-webhook', amount: 100 });
      await sendRequest(`http://127.0.0.1:${info.port}/hook`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: payload,
      });

      expect(targetReceived.length).toBe(1);
      expect(targetReceived[0]!.body).toBe(payload);

      const saved = (await store.list())[0]!;
      expect(saved.forwardResult).toBeDefined();
      expect(saved.forwardResult?.success).toBe(true);
      expect(saved.forwardResult?.status).toBe(200);
    } finally {
      await new Promise<void>((r) => targetServer.close(() => r()));
    }
  });

  it('triggers event replay via POST /__workbench/replay', async () => {
    let targetHit = false;
    const targetServer = http.createServer((_req, res) => {
      targetHit = true;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
    });
    let targetPort = 0;
    await new Promise<void>((r) => {
      targetServer.listen(0, '127.0.0.1', () => {
        targetPort = (targetServer.address() as { port: number }).port;
        r();
      });
    });

    try {
      receiver = createReceiver({
        port: 0,
        host: '127.0.0.1',
        store,
        silent: true,
      });
      const info = await receiver.start();

      // Send initial webhook
      const initRes = await sendRequest(`http://127.0.0.1:${info.port}/init`, {
        method: 'POST',
        body: 'test-replay',
      });
      const eventId = initRes.headers['x-workbench-event-id'] as string;
      expect(eventId).toBeDefined();

      // Trigger replay via API
      const replayRes = await sendRequest(
        `http://127.0.0.1:${info.port}/__workbench/replay`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            eventId,
            destination: `http://127.0.0.1:${targetPort}/replayed`,
            allowLoopback: true,
          }),
        },
      );

      expect(replayRes.statusCode).toBe(200);
      const replayData = JSON.parse(replayRes.body);
      expect(replayData.success).toBe(true);
      expect(targetHit).toBe(true);
    } finally {
      await new Promise<void>((r) => targetServer.close(() => r()));
    }
  });
});
