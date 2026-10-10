/**
 * Operational limits and boundary constants to protect system resources.
 */
export const LIMITS = {
  /** Default maximum request body size in bytes (1 MiB) */
  DEFAULT_MAX_BODY_SIZE_BYTES: 1024 * 1024,
  /** Absolute ceiling on allowed request body size (50 MiB) */
  MAX_ALLOWED_BODY_SIZE_BYTES: 50 * 1024 * 1024,

  /** Default timeout for replay requests in milliseconds (5 seconds) */
  DEFAULT_REPLAY_TIMEOUT_MS: 5000,
  /** Minimum replay timeout in milliseconds (100 ms) */
  MIN_REPLAY_TIMEOUT_MS: 100,
  /** Maximum replay timeout in milliseconds (60 seconds) */
  MAX_REPLAY_TIMEOUT_MS: 60000,

  /** Default maximum response body size stored/buffered during replay (1 MiB) */
  DEFAULT_MAX_RESPONSE_SIZE_BYTES: 1024 * 1024,
  /** Maximum allowed response body size buffer (10 MiB) */
  MAX_ALLOWED_RESPONSE_SIZE_BYTES: 10 * 1024 * 1024,

  /** Default response delay for simulation (0 ms) */
  DEFAULT_DELAY_MS: 0,
  /** Maximum response delay in milliseconds (30 seconds) */
  MAX_DELAY_MS: 30000,

  /** Default number of retry attempts */
  DEFAULT_RETRY_ATTEMPTS: 3,
  /** Minimum retry attempts */
  MIN_RETRY_ATTEMPTS: 1,
  /** Maximum retry attempts to prevent infinite or DoS loops */
  MAX_RETRY_ATTEMPTS: 20,

  /** Default delay between retry attempts in milliseconds */
  DEFAULT_RETRY_DELAY_MS: 1000,
  /** Maximum delay between retry attempts in milliseconds */
  MAX_RETRY_DELAY_MS: 60000,

  /** Default maximum backoff delay in milliseconds */
  DEFAULT_MAX_BACKOFF_MS: 30000,

  /** Default maximum number of events retained in store */
  DEFAULT_STORE_MAX_EVENTS: 500,
  /** Maximum allowed store capacity */
  MAX_STORE_CAPACITY: 10000,

  /** Maximum redirects followed during replay (if enabled) */
  MAX_REDIRECTS: 3,
} as const;
