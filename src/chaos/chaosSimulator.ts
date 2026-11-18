export interface ChaosOptions {
  enabled?: boolean;
  failureRate?: number; // 0.0 to 1.0 (e.g. 0.25 = 25% failure)
  latencyP95Ms?: number; // e.g. 2000ms
  dropRate?: number; // 0.0 to 1.0 (e.g. 0.05 = 5% socket disconnect)
  failureStatusCodes?: number[];
}

export interface ChaosDecision {
  applyChaos: boolean;
  shouldDrop: boolean;
  injectedStatus?: number;
  injectedDelayMs?: number;
  reason?: string;
}

/**
 * Probabilistic Chaos Simulator for webhook delivery endpoints.
 * Simulates real-world unpredictable network conditions, tail latency, and transient upstream failures.
 */
export function evaluateChaos(options: ChaosOptions = {}): ChaosDecision {
  if (!options.enabled) {
    return { applyChaos: false, shouldDrop: false };
  }

  const failureRate = Math.max(0, Math.min(1, options.failureRate ?? 0));
  const dropRate = Math.max(0, Math.min(1, options.dropRate ?? 0));
  const p95Latency = Math.max(0, options.latencyP95Ms ?? 0);
  const statusCodes =
    options.failureStatusCodes && options.failureStatusCodes.length > 0
      ? options.failureStatusCodes
      : [500, 502, 503, 504];

  // 1. Connection Drop Check
  if (dropRate > 0 && Math.random() < dropRate) {
    return {
      applyChaos: true,
      shouldDrop: true,
      reason: 'Chaos: Probabilistic connection reset/drop injected',
    };
  }

  // 2. HTTP Error Status Check
  let injectedStatus: number | undefined;
  if (failureRate > 0 && Math.random() < failureRate) {
    const randomIndex = Math.floor(Math.random() * statusCodes.length);
    injectedStatus = statusCodes[randomIndex];
  }

  // 3. Latency Check (log-normal distribution approximation)
  let injectedDelayMs: number | undefined;
  if (p95Latency > 0) {
    // 90% of requests have modest latency, 10% experience heavy tail latency up to p95Latency
    if (Math.random() < 0.1) {
      injectedDelayMs = Math.round(p95Latency * (0.8 + Math.random() * 0.4));
    } else {
      injectedDelayMs = Math.round(p95Latency * 0.05 * Math.random());
    }
  }

  const applyChaos =
    injectedStatus !== undefined ||
    (injectedDelayMs !== undefined && injectedDelayMs > 0);

  return {
    applyChaos,
    shouldDrop: false,
    injectedStatus,
    injectedDelayMs,
    reason: applyChaos
      ? `Chaos: Injected ${injectedStatus ? `Status ${injectedStatus}` : ''} ${injectedDelayMs ? `${injectedDelayMs}ms delay` : ''}`.trim()
      : undefined,
  };
}
