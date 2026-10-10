import type { WebhookEvent, EventStore } from '../events/types.js';
import type { RetryTestOptions, RetryAttemptResult, RetryTestSummary } from './types.js';
import { replayWebhookEvent } from '../replay/engine.js';
import { LIMITS } from '../security/limits.js';

/**
 * Executes a simulated multi-attempt retry test of a webhook delivery.
 */
export async function testWebhookRetries(
  event: WebhookEvent,
  options: RetryTestOptions,
  store?: EventStore,
): Promise<RetryTestSummary> {
  const attempts = Math.min(
    Math.max(
      LIMITS.MIN_RETRY_ATTEMPTS,
      options.attempts ?? LIMITS.DEFAULT_RETRY_ATTEMPTS,
    ),
    LIMITS.MAX_RETRY_ATTEMPTS,
  );
  const baseDelayMs = Math.min(
    Math.max(0, options.delayMs ?? LIMITS.DEFAULT_RETRY_DELAY_MS),
    LIMITS.MAX_RETRY_DELAY_MS,
  );
  const maxBackoffMs = Math.min(
    Math.max(baseDelayMs, options.maxBackoffMs ?? LIMITS.DEFAULT_MAX_BACKOFF_MS),
    LIMITS.MAX_RETRY_DELAY_MS,
  );
  const useExponential = options.exponentialBackoff ?? false;

  const attemptResults: RetryAttemptResult[] = [];
  let successfulAttempts = 0;
  let failedAttempts = 0;
  let totalDuration = 0;
  let minDuration = Number.MAX_SAFE_INTEGER;
  let maxDuration = 0;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    let currentDelay = 0;

    if (attempt > 1) {
      if (useExponential) {
        currentDelay = Math.min(baseDelayMs * Math.pow(2, attempt - 2), maxBackoffMs);
      } else {
        currentDelay = baseDelayMs;
      }

      if (currentDelay > 0) {
        await new Promise((resolve) => setTimeout(resolve, currentDelay));
      }
    }

    const replayResult = await replayWebhookEvent(event, options, store);

    if (replayResult.success) {
      successfulAttempts++;
    } else {
      failedAttempts++;
    }

    totalDuration += replayResult.durationMs;
    minDuration = Math.min(minDuration, replayResult.durationMs);
    maxDuration = Math.max(maxDuration, replayResult.durationMs);

    attemptResults.push({
      attempt,
      scheduledDelayMs: currentDelay,
      timestamp: new Date().toISOString(),
      replayResult,
    });
  }

  const avgDurationMs = attempts > 0 ? Math.round(totalDuration / attempts) : 0;

  return {
    eventId: event.id,
    destination: options.url,
    totalAttempts: attempts,
    successfulAttempts,
    failedAttempts,
    minDurationMs: minDuration === Number.MAX_SAFE_INTEGER ? 0 : minDuration,
    maxDurationMs: maxDuration,
    avgDurationMs,
    attempts: attemptResults,
  };
}
