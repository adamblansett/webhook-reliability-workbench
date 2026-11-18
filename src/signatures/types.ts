export type SupportedHmacAlgorithm = 'sha256' | 'sha512' | 'sha1';
export type SupportedSignatureAlgorithm = SupportedHmacAlgorithm | 'ed25519';

export interface SignatureVerifyOptions {
  /** The shared secret or public key used to sign/verify the payload */
  secret: string;
  /** Header name that contained the signature (for metadata/diagnostics) */
  headerName?: string;
  /** Algorithm to use (default: 'sha256') */
  algorithm?: SupportedSignatureAlgorithm;
  /** Expected prefix in the header value, e.g. 'sha256=', 'v1=', or 'v1,' */
  prefix?: string;
  /** Signature encoding: 'hex' (default) or 'base64' */
  encoding?: 'hex' | 'base64';
  /** Tolerance in seconds for timestamp-based signatures (e.g. Stripe t=...,v1=...) */
  toleranceSeconds?: number;
  /** Explicit timestamp passed from separate header (e.g. webhook-timestamp) */
  timestamp?: number | string;
  /** Message ID from separate header (e.g. webhook-id for Standard Webhooks) */
  messageId?: string;
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
