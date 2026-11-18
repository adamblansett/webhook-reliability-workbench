import crypto from 'node:crypto';
import type {
  SignatureVerifyOptions,
  SignatureVerificationResult,
  SupportedHmacAlgorithm,
  SupportedSignatureAlgorithm,
} from './types.js';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Creates an Ed25519 public key KeyObject from PEM, DER, base64, or hex 32-byte raw key.
 */
export function createEd25519PublicKey(keyInput: string | Buffer): crypto.KeyObject {
  if (Buffer.isBuffer(keyInput)) {
    if (keyInput.length === 32) {
      return crypto.createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, keyInput]),
        format: 'der',
        type: 'spki',
      });
    }
    return crypto.createPublicKey({
      key: keyInput,
      format: 'der',
      type: 'spki',
    });
  }

  const str = keyInput.trim();
  if (str.includes('-----BEGIN PUBLIC KEY-----')) {
    return crypto.createPublicKey(str);
  }

  let rawBuf: Buffer;
  if (/^[0-9a-fA-F]{64}$/.test(str)) {
    rawBuf = Buffer.from(str, 'hex');
  } else {
    try {
      rawBuf = Buffer.from(str, 'base64');
    } catch {
      rawBuf = Buffer.from(str, 'utf8');
    }
  }

  if (rawBuf.length === 32) {
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawBuf]),
      format: 'der',
      type: 'spki',
    });
  }

  return crypto.createPublicKey(str);
}

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
 * Computes a signature (HMAC or Ed25519) for a raw body buffer or string.
 */
export function computeSignature(
  rawBody: string | Buffer,
  secretOrPrivateKey: string | Buffer | crypto.KeyObject,
  algorithm: SupportedSignatureAlgorithm = 'sha256',
  encoding: 'hex' | 'base64' = 'hex',
): string {
  if (algorithm === 'ed25519') {
    const dataBuf = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
    const privateKey =
      typeof secretOrPrivateKey === 'string' || Buffer.isBuffer(secretOrPrivateKey)
        ? crypto.createPrivateKey(secretOrPrivateKey)
        : secretOrPrivateKey;
    const sigBuf = crypto.sign(null, dataBuf, privateKey);
    return sigBuf.toString(encoding);
  }
  return computeHmacDigest(
    rawBody,
    typeof secretOrPrivateKey === 'string'
      ? secretOrPrivateKey
      : secretOrPrivateKey.toString(),
    algorithm,
    encoding,
  );
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
 * - Standard Webhooks / Svix style: "v1,abc v1,def" -> { signature: "abc", signatures: ["abc", "def"] }
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

  // Standard Webhooks / Svix style: "v1,abc v1,def" or "v1,abc"
  if (trimmed.includes('v1,')) {
    const tokens = trimmed.split(/[\s,]+/);
    const signatures: string[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i]!;
      if (token === 'v1' && i + 1 < tokens.length) {
        signatures.push(tokens[i + 1]!);
        i++;
      } else if (token.startsWith('v1,')) {
        signatures.push(token.slice(3).trim());
      }
    }
    if (signatures.length > 0) {
      return {
        signature: signatures[0]!,
        signatures,
        extractedPrefix: 'v1,',
      };
    }
  }

  // Explicit or common prefix: sha256=, sha512=, v1=, v1,
  if (expectedPrefix && trimmed.startsWith(expectedPrefix)) {
    const sig = trimmed.slice(expectedPrefix.length).trim();
    return {
      signature: sig,
      signatures: [sig],
      extractedPrefix: expectedPrefix,
    };
  }

  // Auto-detect prefix like "<alg>=" (e.g. "sha256=...", "v1=...")
  // Restrict prefix to 1-16 chars so base64 padding at the end of raw signatures is never mistaken for a prefix delimiter.
  const prefixMatch = trimmed.match(
    /^([a-zA-Z][a-zA-Z0-9_-]{0,15})=([a-zA-Z0-9+/=_-]+)$/,
  );
  if (prefixMatch && prefixMatch[1] && prefixMatch[2]) {
    const potentialPrefix = prefixMatch[1].toLowerCase();
    const knownPrefixes = [
      'sha256',
      'sha512',
      'sha1',
      'sha224',
      'sha384',
      'ed25519',
      'v1',
      'v0',
      'sig',
      'signature',
      's',
    ];
    if (
      knownPrefixes.includes(potentialPrefix) ||
      (potentialPrefix.length <= 10 && prefixMatch[2].length >= 16)
    ) {
      const sig = prefixMatch[2].trim();
      return {
        signature: sig,
        signatures: [sig],
        extractedPrefix: `${prefixMatch[1]}=`,
      };
    }
  }

  return { signature: trimmed, signatures: [trimmed] };
}

/**
 * Verifies an HMAC or Ed25519 signature against the raw request body.
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

  // Determine effective timestamp
  let effectiveTimestamp = timestamp;
  if (options.timestamp !== undefined) {
    const parsedOptTs =
      typeof options.timestamp === 'string'
        ? parseInt(options.timestamp, 10)
        : options.timestamp;
    if (!isNaN(parsedOptTs)) {
      effectiveTimestamp = parsedOptTs;
    }
  }

  // If timestamp is present (e.g. Stripe or Standard Webhooks)
  let bodyToSign: string | Buffer = rawBody;
  if (effectiveTimestamp !== undefined && !isNaN(effectiveTimestamp)) {
    const rawStr = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    if (options.messageId) {
      bodyToSign = `${options.messageId}.${effectiveTimestamp}.${rawStr}`;
    } else {
      bodyToSign = `${effectiveTimestamp}.${rawStr}`;
    }

    // Tolerance check if requested
    if (options.toleranceSeconds && options.toleranceSeconds > 0) {
      const now = Math.floor(Date.now() / 1000);
      if (Math.abs(now - effectiveTimestamp) > options.toleranceSeconds) {
        return {
          valid: false,
          algorithm,
          headerName: options.headerName,
          timestamp: effectiveTimestamp,
          reason: `Timestamp ${effectiveTimestamp} outside allowed tolerance of ${options.toleranceSeconds}s`,
          error: 'TIMESTAMP_OUT_OF_TOLERANCE',
        };
      }
    }
  }

  const candidateSignatures =
    signatures && signatures.length > 0 ? signatures : [signature];

  // Ed25519 asymmetric verification
  if (algorithm === 'ed25519') {
    let isValid = false;
    try {
      const pubKey = createEd25519PublicKey(options.secret);
      const dataToVerify = Buffer.isBuffer(bodyToSign)
        ? bodyToSign
        : Buffer.from(bodyToSign, 'utf8');

      isValid = candidateSignatures.some((cand) => {
        try {
          const sigBuffer =
            encoding === 'hex' ? Buffer.from(cand, 'hex') : Buffer.from(cand, 'base64');
          return crypto.verify(null, dataToVerify, pubKey, sigBuffer);
        } catch {
          return false;
        }
      });
    } catch (err) {
      return {
        valid: false,
        algorithm,
        headerName: options.headerName,
        reason: `Ed25519 verification error: ${err instanceof Error ? err.message : String(err)}`,
        error: 'ED25519_VERIFICATION_ERROR',
      };
    }

    return {
      valid: isValid,
      algorithm,
      headerName: options.headerName,
      expectedPrefix: options.prefix,
      receivedSignature:
        signature.length > 8
          ? `${signature.slice(0, 4)}...${signature.slice(-4)}`
          : '****',
      timestamp: effectiveTimestamp,
      reason: isValid ? 'Signature verified successfully' : 'Signature digest mismatch',
    };
  }

  // HMAC verification
  let expectedDigest: string;
  try {
    expectedDigest = computeHmacDigest(
      bodyToSign,
      options.secret,
      algorithm as SupportedHmacAlgorithm,
      encoding,
    );
  } catch (err) {
    return {
      valid: false,
      algorithm,
      headerName: options.headerName,
      reason: `HMAC calculation failed: ${err instanceof Error ? err.message : String(err)}`,
      error: 'HMAC_COMPUTATION_ERROR',
    };
  }

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
    timestamp: effectiveTimestamp,
    reason: isValid ? 'Signature verified successfully' : 'Signature digest mismatch',
  };
}
