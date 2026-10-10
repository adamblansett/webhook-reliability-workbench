import crypto from 'node:crypto';
import type {
  SignatureVerifyOptions,
  SignatureVerificationResult,
  SupportedHmacAlgorithm,
} from './types.js';

/**
 * Computes an HMAC digest for a raw body buffer or string.
 */
export function computeHmacDigest(
  rawBody: string | Buffer,
  secret: string,
  algorithm: SupportedHmacAlgorithm = 'sha256',
  encoding: 'hex' | 'base64' = 'hex',
): string {
  const hmac = crypto.createHmac(algorithm, secret);
  hmac.update(rawBody);
  return hmac.digest(encoding);
}

/**
 * Timing-safe comparison between two strings.
 * Hashes both strings with SHA-256 before timingSafeEqual to guarantee
 * identical buffer lengths and prevent RangeError while remaining timing-safe.
 */
export function timingSafeCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const lengthMatch = a.length === b.length;
  const hashA = crypto.createHash('sha256').update(Buffer.from(a, 'utf8')).digest();
  const hashB = crypto.createHash('sha256').update(Buffer.from(b, 'utf8')).digest();
  const hashesEqual = crypto.timingSafeEqual(hashA, hashB);
  return lengthMatch && hashesEqual;
}

/**
 * Parses header value to extract signature and optional timestamp.
 * Handles:
 * - standard prefix e.g. "sha256=abcdef..." -> { signature: "abcdef..." }
 * - Stripe style: "t=1614555,v1=abc,v0=xyz" -> { timestamp: 1614555, signature: "abc" }
 * - plain string: "abcdef..." -> { signature: "abcdef..." }
 */
export function parseSignatureHeader(
  headerValue: string,
  expectedPrefix?: string,
): {
  signature: string;
  signatures: string[];
  timestamp?: number;
  extractedPrefix?: string;
} {
  const trimmed = headerValue.trim();

  // Stripe-style multi-part header: t=...,v1=...
  if (trimmed.includes('t=') && (trimmed.includes('v1=') || trimmed.includes('v0='))) {
    const parts = trimmed.split(',');
    let timestamp: number | undefined;
    const signatures: string[] = [];
    let extractedPrefix = '';

    for (const part of parts) {
      const eqIdx = part.indexOf('=');
      if (eqIdx <= 0) continue;
      const k = part.slice(0, eqIdx).trim();
      const v = part.slice(eqIdx + 1).trim();

      if (k === 't') {
        const parsed = parseInt(v, 10);
        if (!isNaN(parsed)) {
          timestamp = parsed;
        }
      } else if (k === 'v1' || k === 'v0') {
        signatures.push(v);
        extractedPrefix = `${k}=`;
      }
    }

    if (signatures.length > 0) {
      return {
        signature: signatures[0]!,
        signatures,
        timestamp,
        extractedPrefix,
      };
    }
  }

  // Explicit or common prefix: sha256=, sha512=, v1=
  if (expectedPrefix && trimmed.startsWith(expectedPrefix)) {
    const sig = trimmed.slice(expectedPrefix.length).trim();
    return {
      signature: sig,
      signatures: [sig],
      extractedPrefix: expectedPrefix,
    };
  }

  // Auto-detect prefix like "<alg>="
  const prefixMatch = trimmed.match(/^([a-zA-Z0-9_-]+)=(.+)$/);
  if (prefixMatch && prefixMatch[1] && prefixMatch[2]) {
    const sig = prefixMatch[2].trim();
    return {
      signature: sig,
      signatures: [sig],
      extractedPrefix: `${prefixMatch[1]}=`,
    };
  }

  return { signature: trimmed, signatures: [trimmed] };
}

/**
 * Verifies an HMAC signature against the raw request body.
 * Never exposes secrets in results or errors.
 */
export function verifySignature(
  rawBody: string | Buffer,
  options: SignatureVerifyOptions,
  headerValue: string | string[] | undefined,
): SignatureVerificationResult {
  const algorithm = options.algorithm ?? 'sha256';
  const encoding = options.encoding ?? 'hex';

  if (!options.secret) {
    return {
      valid: false,
      algorithm,
      headerName: options.headerName,
      reason: 'No signing secret configured',
      error: 'SIGNING_SECRET_MISSING',
    };
  }

  if (headerValue === undefined) {
    return {
      valid: false,
      algorithm,
      headerName: options.headerName,
      reason: 'Signature header is missing from request',
      error: 'SIGNATURE_HEADER_MISSING',
    };
  }

  const rawHeaderString = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (
    !rawHeaderString ||
    typeof rawHeaderString !== 'string' ||
    rawHeaderString.trim() === ''
  ) {
    return {
      valid: false,
      algorithm,
      headerName: options.headerName,
      reason: 'Signature header is empty or not a string',
      error: 'SIGNATURE_HEADER_EMPTY',
    };
  }

  const { signature, signatures, timestamp, extractedPrefix } = parseSignatureHeader(
    rawHeaderString,
    options.prefix,
  );

  if (!signature) {
    return {
      valid: false,
      algorithm,
      headerName: options.headerName,
      reason: 'Could not extract signature from header value',
      error: 'MALFORMED_SIGNATURE_HEADER',
    };
  }

  // Check prefix match if prefix was explicitly specified
  if (options.prefix && extractedPrefix !== options.prefix) {
    return {
      valid: false,
      algorithm,
      headerName: options.headerName,
      expectedPrefix: options.prefix,
      reason: `Signature header did not match expected prefix "${options.prefix}"`,
      error: 'PREFIX_MISMATCH',
    };
  }

  // If timestamp is present (e.g. Stripe), body to sign is "${timestamp}.${rawBody}"
  let bodyToSign: string | Buffer = rawBody;
  if (timestamp !== undefined) {
    const rawStr = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    bodyToSign = `${timestamp}.${rawStr}`;

    // Tolerance check if requested
    if (options.toleranceSeconds && options.toleranceSeconds > 0) {
      const now = Math.floor(Date.now() / 1000);
      if (Math.abs(now - timestamp) > options.toleranceSeconds) {
        return {
          valid: false,
          algorithm,
          headerName: options.headerName,
          timestamp,
          reason: `Timestamp ${timestamp} outside allowed tolerance of ${options.toleranceSeconds}s`,
          error: 'TIMESTAMP_OUT_OF_TOLERANCE',
        };
      }
    }
  }

  let expectedDigest: string;
  try {
    expectedDigest = computeHmacDigest(bodyToSign, options.secret, algorithm, encoding);
  } catch (err) {
    return {
      valid: false,
      algorithm,
      headerName: options.headerName,
      reason: `HMAC calculation failed: ${err instanceof Error ? err.message : String(err)}`,
      error: 'HMAC_COMPUTATION_ERROR',
    };
  }

  const candidateSignatures =
    signatures && signatures.length > 0 ? signatures : [signature];
  const compareExpected =
    encoding === 'hex' ? expectedDigest.toLowerCase() : expectedDigest;

  const isValid = candidateSignatures.some((cand) => {
    const compareCand = encoding === 'hex' ? cand.toLowerCase() : cand;
    return timingSafeCompare(compareExpected, compareCand);
  });

  return {
    valid: isValid,
    algorithm,
    headerName: options.headerName,
    expectedPrefix: options.prefix,
    receivedSignature:
      signature.length > 8 ? `${signature.slice(0, 4)}...${signature.slice(-4)}` : '****',
    timestamp,
    reason: isValid ? 'Signature verified successfully' : 'Signature digest mismatch',
  };
}
