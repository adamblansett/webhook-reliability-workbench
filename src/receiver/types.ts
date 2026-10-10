import type { SupportedHmacAlgorithm } from '../signatures/types.js';
import type { EventStore } from '../events/types.js';

export interface ReceiverOptions {
  /** Host to bind (default: '127.0.0.1') */
  host?: string;
  /** Port to listen on (default: 8787, 0 for ephemeral) */
  port?: number;
  /** Specific webhook endpoint path to capture (default: '/' to accept any path) */
  path?: string;
  /** Explicitly allow binding to external interfaces (e.g. 0.0.0.0) */
  allowExternal?: boolean;
  /** Maximum allowed request body size in bytes (default: 1 MiB) */
  maxBodySize?: number;

  /** Simulated response HTTP status code (default: 200) */
  responseStatus?: number;
  /** Simulated response delay in milliseconds (default: 0) */
  delayMs?: number;
  /** Simulated response body string or JSON */
  responseBody?: string;
  /** Simulated custom response headers */
  responseHeaders?: Record<string, string>;

  /** Optional signing secret for automatic incoming signature verification */
  secret?: string;
  /** Header name that contains the HMAC signature */
  signatureHeader?: string;
  /** Expected signature prefix (e.g. 'sha256=') */
  signaturePrefix?: string;
  /** Signature HMAC algorithm */
  algorithm?: SupportedHmacAlgorithm;

  /** EventStore instance to persist captured events */
  store?: EventStore;
  /** Silence console logs during testing */
  silent?: boolean;
}

export interface ReceiverServerInfo {
  host: string;
  port: number;
  url: string;
  path: string;
  pid: number;
}
