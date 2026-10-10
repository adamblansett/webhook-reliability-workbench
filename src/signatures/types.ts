export type SupportedHmacAlgorithm = 'sha256' | 'sha512' | 'sha1';

export interface SignatureVerifyOptions {
  /** The shared secret used to sign the payload */
  secret: string;
  /** Header name that contained the signature (for metadata/diagnostics) */
  headerName?: string;
  /** HMAC algorithm to use (default: 'sha256') */
  algorithm?: SupportedHmacAlgorithm;
  /** Expected prefix in the header value, e.g. 'sha256=' or 'v1=' */
  prefix?: string;
  /** Signature encoding: 'hex' (default) or 'base64' */
  encoding?: 'hex' | 'base64';
  /** Tolerance in seconds for timestamp-based signatures (e.g. Stripe t=...,v1=...) */
  toleranceSeconds?: number;
}

export interface SignatureVerificationResult {
  valid: boolean;
  algorithm: string;
  headerName?: string;
  expectedPrefix?: string;
  receivedSignature?: string;
  timestamp?: number;
  reason?: string;
  error?: string;
}
