import type { SupportedHmacAlgorithm } from '../signatures/types.js';
import type { ReplayRecord } from '../events/types.js';

export interface ReplayOptions {
  /** Target destination URL */
  url: string;
  /** Explicitly allow loopback destination (127.0.0.1, localhost) */
  allowLoopback?: boolean;
  /** Explicitly allow private networks (10.0.0.0/8, etc.) */
  allowPrivate?: boolean;
  /** Specific destination allowlist */
  allowedDestinations?: string[];

  /** Request timeout in milliseconds (default: 5000) */
  timeoutMs?: number;
  /** Maximum response body bytes to buffer (default: 1 MiB) */
  maxResponseSizeBytes?: number;

  /** Whether to follow HTTP 3xx redirects (default: false for security) */
  followRedirects?: boolean;
  /** Maximum number of redirects to follow if enabled (default: 3) */
  maxRedirects?: number;

  /** Header overrides in format "Header-Name: value" or Record<string, string> */
  headerOverrides?: Record<string, string>;
  /** Headers to explicitly remove */
  removeHeaders?: string[];

  /** Keep original signature headers (default: false for security) */
  keepSignatures?: boolean;
  /** Keep original auth headers (default: false for security) */
  keepAuth?: boolean;

  /** Regenerate signature for the destination */
  regenerateSignature?: boolean;
  /** Signing secret for signature regeneration */
  secret?: string;
  /** Signature header name for regeneration (e.g. 'x-hub-signature-256') */
  signatureHeader?: string;
  /** Signature prefix for regeneration (e.g. 'sha256=') */
  signaturePrefix?: string;
  /** Signature algorithm for regeneration */
  algorithm?: SupportedHmacAlgorithm;
}

export interface ReplayResult extends ReplayRecord {
  requestHeadersSent: Record<string, string | string[]>;
  requestMethod: string;
  requestUrl: string;
}
