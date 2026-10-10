import type { ReplayOptions, ReplayResult } from '../replay/types.js';

export interface RetryTestOptions extends ReplayOptions {
  /** Number of retry attempts (default: 3, max: 20) */
  attempts?: number;
  /** Base delay between attempts in milliseconds (default: 1000) */
  delayMs?: number;
  /** Use exponential backoff for delays */
  exponentialBackoff?: boolean;
  /** Cap on maximum backoff delay in milliseconds (default: 30000) */
  maxBackoffMs?: number;
}

export interface RetryAttemptResult {
  attempt: number;
  scheduledDelayMs: number;
  timestamp: string;
  replayResult: ReplayResult;
}

export interface RetryTestSummary {
  eventId: string;
  destination: string;
  totalAttempts: number;
  successfulAttempts: number;
  failedAttempts: number;
  minDurationMs: number;
  maxDurationMs: number;
  avgDurationMs: number;
  attempts: RetryAttemptResult[];
}
