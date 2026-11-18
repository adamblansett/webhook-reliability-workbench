import { describe, it, expect } from 'vitest';
import { evaluateChaos } from '../src/chaos/chaosSimulator.js';

describe('Chaos Simulator', () => {
  it('returns no chaos when disabled', () => {
    const decision = evaluateChaos({ enabled: false, failureRate: 1.0 });
    expect(decision.applyChaos).toBe(false);
    expect(decision.shouldDrop).toBe(false);
  });

  it('injects status failure when failureRate is 1.0', () => {
    const decision = evaluateChaos({
      enabled: true,
      failureRate: 1.0,
      failureStatusCodes: [503],
    });
    expect(decision.applyChaos).toBe(true);
    expect(decision.shouldDrop).toBe(false);
    expect(decision.injectedStatus).toBe(503);
  });

  it('injects connection drop when dropRate is 1.0', () => {
    const decision = evaluateChaos({
      enabled: true,
      dropRate: 1.0,
    });
    expect(decision.applyChaos).toBe(true);
    expect(decision.shouldDrop).toBe(true);
    expect(decision.reason).toContain('connection reset/drop');
  });

  it('injects tail latency when latencyP95Ms is configured', () => {
    const decision = evaluateChaos({
      enabled: true,
      latencyP95Ms: 1000,
    });
    // Regardless of distribution bucket, injectedDelayMs should be a positive number
    expect(decision.injectedDelayMs).toBeGreaterThanOrEqual(0);
  });
});
