import { describe, it, expect } from 'vitest';
import { evaluateChaos } from '../src/chaos/chaosSimulator.js';
import { generateFuzzMutations } from '../src/fuzz/fuzzer.js';
import type { WebhookEvent } from '../src/events/types.js';

describe('Chaos Simulator & Payload Fuzzer', () => {
  it('respects disabled chaos configuration', () => {
    const decision = evaluateChaos({ enabled: false });
    expect(decision.applyChaos).toBe(false);
    expect(decision.shouldDrop).toBe(false);
  });

  it('evaluates chaos status codes when failure rate is 1.0', () => {
    const decision = evaluateChaos({
      enabled: true,
      failureRate: 1.0,
      failureStatusCodes: [503],
    });
    expect(decision.applyChaos).toBe(true);
    expect(decision.injectedStatus).toBe(503);
  });

  it('evaluates connection drop when drop rate is 1.0', () => {
    const decision = evaluateChaos({
      enabled: true,
      dropRate: 1.0,
    });
    expect(decision.applyChaos).toBe(true);
    expect(decision.shouldDrop).toBe(true);
  });

  it('generates rich mutation varieties for valid JSON events', () => {
    const mockEvent: WebhookEvent = {
      id: 'evt_test',
      timestamp: '2026-10-10T10:00:00Z',
      method: 'POST',
      path: '/webhooks',
      headers: { 'content-type': 'application/json' },
      query: {},
      rawBody: JSON.stringify({
        event: 'user.created',
        userId: 'usr_123',
        email: 'test@example.com',
      }),
      body: {
        event: 'user.created',
        userId: 'usr_123',
        email: 'test@example.com',
      },
      isJson: true,
      jsonError: null,
      contentType: 'application/json',
      contentLength: 100,
      responseStatus: 200,
      durationMs: 5,
      signature: null,
      replays: [],
    };

    const mutations = generateFuzzMutations(mockEvent);
    expect(mutations.length).toBeGreaterThanOrEqual(5);

    const names = mutations.map((m) => m.name);
    expect(names).toContain('malformed_truncated_json');
    expect(names).toContain('empty_body');
    expect(names).toContain('prototype_pollution_keys');
    expect(names).toContain('null_byte_injection');
    expect(names).toContain('sql_injection_probe');
    expect(names).toContain('oversized_string_field');
  });
});
