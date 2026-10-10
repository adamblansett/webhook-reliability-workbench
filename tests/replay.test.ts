import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { replayWebhookEvent } from '../src/replay/engine.js';
import { InMemoryEventStore } from '../src/events/store.js';
import type { WebhookEvent } from '../src/events/types.js';
import { computeHmacDigest } from '../src/signatures/verifier.js';
import { SsrSecurityError } from '../src/security/ssrf.js';

describe('Webhook Replay Engine', () => {
  let targetServer: http.Server | null = null;
  let targetPort: number = 0;
  let receivedRequests: Array<{
    method: string;
    url: string;
    headers: http.IncomingHttpHeaders;
    body: string;
  }> = [];
  let responseHandler: (req: http.IncomingMessage, res: http.ServerResponse) => void;
  let store: InMemoryEventStore;

  beforeEach(async () => {
    store = new InMemoryEventStore();
    receivedRequests = [];

    // Default 200 OK handler
    responseHandler = (req, res) => {
      let body = '';
      req.on('data', (c) => (body += c.toString('utf8')));
      req.on('end', () => {
        receivedRequests.push({
          method: req.method ?? '',
          url: req.url ?? '',
          headers: req.headers,
          body,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, received: true }));
      });
    };

    targetServer = http.createServer((req, res) => responseHandler(req, res));
    await new Promise<void>((resolve) => {
      targetServer!.listen(0, '127.0.0.1', () => {
        const addr = targetServer!.address() as { port: number };
        targetPort = addr.port;
        resolve();
      });
    });
  });

  afterEach(async () => {
    if (targetServer) {
      await new Promise<void>((resolve) => targetServer!.close(() => resolve()));
      targetServer = null;
    }
  });

  function createSampleEvent(): WebhookEvent {
    return {
      id: 'evt_sample_123',
      timestamp: '2026-10-10T12:00:00Z',
      method: 'POST',
      path: '/target/webhooks',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer secret-token-should-be-stripped',
        'x-hub-signature-256': 'sha256=stale-signature-should-be-stripped',
        'x-custom-tracking': 'track_abc123',
      },
      query: { mode: 'test' },
      rawBody: JSON.stringify({ item: 'Widget', qty: 2 }),
      body: { item: 'Widget', qty: 2 },
      isJson: true,
      jsonError: null,
      contentType: 'application/json',
      contentLength: 29,
      responseStatus: 200,
      durationMs: 10,
      signature: null,
      replays: [],
    };
  }

  it('successfully replays event to target destination with allowLoopback', async () => {
    const event = createSampleEvent();
    await store.save(event);
    const result = await replayWebhookEvent(
      event,
      {
        url: `http://127.0.0.1:${targetPort}/target/webhooks?mode=test`,
        allowLoopback: true,
      },
      store,
    );

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);

    expect(receivedRequests.length).toBe(1);
    const req = receivedRequests[0]!;
    expect(req.method).toBe('POST');
    expect(req.url).toBe('/target/webhooks?mode=test');
    expect(req.body).toBe(event.rawBody);
    expect(req.headers['x-custom-tracking']).toBe('track_abc123');

    // Default security: auth and signature headers were stripped
    expect(req.headers['authorization']).toBeUndefined();
    expect(req.headers['x-hub-signature-256']).toBeUndefined();

    // Verify recorded in store
    const updated = await store.get(event.id);
    expect(updated?.replays.length).toBe(1);
    expect(updated?.replays[0]?.destination).toBe(
      `http://127.0.0.1:${targetPort}/target/webhooks?mode=test`,
    );
  });

  it('blocks replay to loopback without explicit allowLoopback', async () => {
    const event = createSampleEvent();
    await expect(
      replayWebhookEvent(event, {
        url: `http://127.0.0.1:${targetPort}/webhooks`,
        allowLoopback: false,
      }),
    ).rejects.toThrowError(SsrSecurityError);
  });

  it('allows header overrides and removal of specific headers', async () => {
    const event = createSampleEvent();
    const result = await replayWebhookEvent(
      event,
      {
        url: `http://127.0.0.1:${targetPort}/override`,
        allowLoopback: true,
        headerOverrides: {
          'x-override-key': 'value123',
          'x-custom-tracking': 'new-tracking-id',
        },
        removeHeaders: ['x-not-wanted'],
      },
      store,
    );

    expect(result.success).toBe(true);
    const req = receivedRequests[0]!;
    expect(req.headers['x-override-key']).toBe('value123');
    expect(req.headers['x-custom-tracking']).toBe('new-tracking-id');
  });

  it('keeps auth and signature headers when explicitly configured', async () => {
    const event = createSampleEvent();
    const result = await replayWebhookEvent(
      event,
      {
        url: `http://127.0.0.1:${targetPort}/keep-auth`,
        allowLoopback: true,
        keepAuth: true,
        keepSignatures: true,
      },
      store,
    );

    expect(result.success).toBe(true);
    const req = receivedRequests[0]!;
    expect(req.headers['authorization']).toBe('Bearer secret-token-should-be-stripped');
    expect(req.headers['x-hub-signature-256']).toBe(
      'sha256=stale-signature-should-be-stripped',
    );
  });

  it('regenerates HMAC signature for destination when requested', async () => {
    const secret = 'new-destination-secret';
    const event = createSampleEvent();

    const expectedDigest = computeHmacDigest(event.rawBody, secret, 'sha256');

    const result = await replayWebhookEvent(
      event,
      {
        url: `http://127.0.0.1:${targetPort}/regen-sig`,
        allowLoopback: true,
        regenerateSignature: true,
        secret,
        signatureHeader: 'x-hub-signature-256',
        signaturePrefix: 'sha256=',
        algorithm: 'sha256',
      },
      store,
    );

    expect(result.success).toBe(true);
    const req = receivedRequests[0]!;
    expect(req.headers['x-hub-signature-256']).toBe(`sha256=${expectedDigest}`);
  });

  it('handles request timeout cleanly', async () => {
    // Hang target server response
    responseHandler = (_req, _res) => {
      // Do nothing, never end
    };

    const event = createSampleEvent();
    const result = await replayWebhookEvent(
      event,
      {
        url: `http://127.0.0.1:${targetPort}/timeout`,
        allowLoopback: true,
        timeoutMs: 150,
      },
      store,
    );

    expect(result.success).toBe(false);
    expect(result.statusText).toBe('Request Timeout');
    expect(result.error).toContain('timed out');
  });

  it('handles network connection failures (ECONNREFUSED) clearly', async () => {
    const event = createSampleEvent();
    // Use an unassigned port (e.g. 59999)
    const result = await replayWebhookEvent(
      event,
      {
        url: 'http://127.0.0.1:59999/failed-conn',
        allowLoopback: true,
        timeoutMs: 500,
      },
      store,
    );

    expect(result.success).toBe(false);
    expect(result.statusText).toBe('Network Error');
    expect(result.error).toContain('ECONNREFUSED');
  });

  it('enforces maximum response size limit and truncates preview', async () => {
    responseHandler = (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      // Send 50KB response
      res.end('B'.repeat(50000));
    };

    const event = createSampleEvent();
    const result = await replayWebhookEvent(
      event,
      {
        url: `http://127.0.0.1:${targetPort}/large-response`,
        allowLoopback: true,
        maxResponseSizeBytes: 1024, // 1KB limit
      },
      store,
    );

    expect(result.success).toBe(true);
    expect(result.responseBodyPreview).toContain('Truncated: exceeded 1024 bytes');
  });
});
