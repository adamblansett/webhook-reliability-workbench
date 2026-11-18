import { describe, it, expect } from 'vitest';
import { diffEvents } from '../src/output/diff.js';
import type { WebhookEvent } from '../src/events/types.js';

describe('Event Payload and Header Diffing', () => {
  function makeEvent(overrides: Partial<WebhookEvent> = {}): WebhookEvent {
    return {
      id: 'evt_1',
      timestamp: '2026-11-18T10:00:00.000Z',
      method: 'POST',
      path: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-request-id': 'req_123',
      },
      query: {},
      rawBody: '{"status":"pending","amount":100}',
      body: { status: 'pending', amount: 100 },
      isJson: true,
      jsonError: null,
      contentType: 'application/json',
      contentLength: 32,
      responseStatus: 200,
      durationMs: 5,
      signature: null,
      replays: [],
      ...overrides,
    };
  }

  it('reports identical events cleanly', () => {
    const e1 = makeEvent({ id: 'evt_1' });
    const e2 = makeEvent({ id: 'evt_2' });
    const diff = diffEvents(e1, e2);

    expect(diff).toContain('(Identical headers)');
    expect(diff).toContain('(Identical payloads)');
  });

  it('detects added, removed, and modified headers', () => {
    const e1 = makeEvent({
      id: 'evt_1',
      headers: {
        'content-type': 'application/json',
        'x-old-header': 'old_value',
        'x-modified': 'v1',
      },
    });

    const e2 = makeEvent({
      id: 'evt_2',
      headers: {
        'content-type': 'application/json',
        'x-new-header': 'new_value',
        'x-modified': 'v2',
      },
    });

    const diff = diffEvents(e1, e2);
    expect(diff).toContain('+ x-new-header: new_value');
    expect(diff).toContain('- x-old-header: old_value');
    expect(diff).toContain('~ x-modified:');
  });

  it('detects payload differences', () => {
    const e1 = makeEvent({
      id: 'evt_1',
      rawBody: '{"status":"pending"}',
      body: { status: 'pending' },
    });

    const e2 = makeEvent({
      id: 'evt_2',
      rawBody: '{"status":"completed"}',
      body: { status: 'completed' },
    });

    const diff = diffEvents(e1, e2);
    expect(diff).toContain('-   "status": "pending"');
    expect(diff).toContain('+   "status": "completed"');
  });
});
