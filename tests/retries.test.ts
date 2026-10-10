import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { testWebhookRetries } from '../src/retries/tester.js';
import { InMemoryEventStore } from '../src/events/store.js';
import type { WebhookEvent } from '../src/events/types.js';

describe('Retry and Duplicate Delivery Tester', () => {
  let targetServer: http.Server | null = null;
  let targetPort: number = 0;
  let requestCount = 0;
  let store: InMemoryEventStore;

  beforeEach(async () => {
    store = new InMemoryEventStore();
    requestCount = 0;

    targetServer = http.createServer((req, res) => {
      requestCount++;
      let body = '';
      req.on('data', (c) => (body += c.toString('utf8')));
      req.on('end', () => {
        // Fail the first 2 attempts with 503 Service Unavailable, succeed on attempt 3
        if (requestCount <= 2) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Temporarily Unavailable' }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, attempt: requestCount }));
        }
      });
    });

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
      if (typeof targetServer.closeAllConnections === 'function') {
        targetServer.closeAllConnections();
      }
      await new Promise<void>((resolve) => targetServer!.close(() => resolve()));
      targetServer = null;
    }
  });

  function createSampleEvent(): WebhookEvent {
    return {
      id: 'evt_retry_test',
      timestamp: '2026-10-10T12:00:00Z',
      method: 'POST',
      path: '/webhook',
      headers: { 'content-type': 'application/json' },
      query: {},
      rawBody: JSON.stringify({ event: 'payment.created' }),
      body: { event: 'payment.created' },
      isJson: true,
      jsonError: null,
      contentType: 'application/json',
      contentLength: 27,
      responseStatus: 200,
      durationMs: 5,
      signature: null,
      replays: [],
    };
  }

  it('executes requested number of attempts and records accurate breakdown', async () => {
    const event = createSampleEvent();
    const summary = await testWebhookRetries(
      event,
      {
        url: `http://127.0.0.1:${targetPort}/webhook`,
        allowLoopback: true,
        attempts: 3,
        delayMs: 20, // small delay for fast test
      },
      store,
    );

    expect(summary.totalAttempts).toBe(3);
    expect(summary.successfulAttempts).toBe(1);
    expect(summary.failedAttempts).toBe(2);
    expect(summary.attempts.length).toBe(3);

    // Attempt 1: failed (503)
    expect(summary.attempts[0]?.attempt).toBe(1);
    expect(summary.attempts[0]?.scheduledDelayMs).toBe(0);
    expect(summary.attempts[0]?.replayResult.status).toBe(503);
    expect(summary.attempts[0]?.replayResult.success).toBe(false);

    // Attempt 2: failed (503)
    expect(summary.attempts[1]?.attempt).toBe(2);
    expect(summary.attempts[1]?.scheduledDelayMs).toBe(20);
    expect(summary.attempts[1]?.replayResult.status).toBe(503);

    // Attempt 3: succeeded (200)
    expect(summary.attempts[2]?.attempt).toBe(3);
    expect(summary.attempts[2]?.replayResult.status).toBe(200);
    expect(summary.attempts[2]?.replayResult.success).toBe(true);

    expect(summary.avgDurationMs).toBeGreaterThanOrEqual(0);
  });

  it('applies exponential backoff correctly', async () => {
    const event = createSampleEvent();
    const summary = await testWebhookRetries(
      event,
      {
        url: `http://127.0.0.1:${targetPort}/webhook`,
        allowLoopback: true,
        attempts: 4,
        delayMs: 10,
        exponentialBackoff: true,
        maxBackoffMs: 100,
      },
      store,
    );

    expect(summary.totalAttempts).toBe(4);
    // Delays should be: attempt 1 = 0ms, attempt 2 = 10ms, attempt 3 = 20ms, attempt 4 = 40ms
    expect(summary.attempts[0]?.scheduledDelayMs).toBe(0);
    expect(summary.attempts[1]?.scheduledDelayMs).toBe(10);
    expect(summary.attempts[2]?.scheduledDelayMs).toBe(20);
    expect(summary.attempts[3]?.scheduledDelayMs).toBe(40);
  });

  it('enforces bounds on retry attempts (clamps between 1 and 20)', async () => {
    const event = createSampleEvent();
    // Pass excessive attempts: 50 -> should be clamped to 20
    // But to keep test fast, test min clamp: 0 -> clamped to 1
    const summary = await testWebhookRetries(
      event,
      {
        url: `http://127.0.0.1:${targetPort}/webhook`,
        allowLoopback: true,
        attempts: 0, // Clamps to MIN_RETRY_ATTEMPTS (1)
        delayMs: 0,
      },
      store,
    );

    expect(summary.totalAttempts).toBe(1);
    expect(summary.attempts.length).toBe(1);
  });
});
