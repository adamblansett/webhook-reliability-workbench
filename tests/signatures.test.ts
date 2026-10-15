import { describe, it, expect } from 'vitest';
import {
  verifySignature,
  computeHmacDigest,
  timingSafeCompare,
  parseSignatureHeader,
} from '../src/signatures/verifier.js';

describe('HMAC Signature Verification', () => {
  const secret = 'super-secret-webhook-key';
  const payload = JSON.stringify({ event: 'order.completed', id: 12345 });

  it('computes and verifies HMAC-SHA256 signatures successfully', () => {
    const digest = computeHmacDigest(payload, secret, 'sha256');
    const result = verifySignature(payload, { secret, algorithm: 'sha256' }, digest);

    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe('sha256');
    expect(result.reason).toBe('Signature verified successfully');
  });

  it('computes and verifies HMAC-SHA512 signatures successfully', () => {
    const digest = computeHmacDigest(payload, secret, 'sha512');
    const result = verifySignature(payload, { secret, algorithm: 'sha512' }, digest);

    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe('sha512');
  });

  it('computes and verifies HMAC-SHA1 signatures successfully', () => {
    const digest = computeHmacDigest(payload, secret, 'sha1');
    const result = verifySignature(payload, { secret, algorithm: 'sha1' }, digest);

    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe('sha1');
  });

  it('supports GitHub-style prefix "sha256="', () => {
    const digest = computeHmacDigest(payload, secret, 'sha256');
    const headerValue = `sha256=${digest}`;

    const result = verifySignature(
      payload,
      { secret, algorithm: 'sha256', prefix: 'sha256=' },
      headerValue,
    );

    expect(result.valid).toBe(true);
    expect(result.expectedPrefix).toBe('sha256=');
  });

  it('rejects prefix mismatch when prefix is explicitly configured', () => {
    const digest = computeHmacDigest(payload, secret, 'sha256');
    const headerValue = `sha512=${digest}`;

    const result = verifySignature(
      payload,
      { secret, algorithm: 'sha256', prefix: 'sha256=' },
      headerValue,
    );

    expect(result.valid).toBe(false);
    expect(result.error).toBe('PREFIX_MISMATCH');
  });

  it('supports Stripe-style timestamped headers t=...,v1=...', () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const signedPayload = `${timestamp}.${payload}`;
    const digest = computeHmacDigest(signedPayload, secret, 'sha256');
    const headerValue = `t=${timestamp},v1=${digest}`;

    const result = verifySignature(
      payload,
      { secret, algorithm: 'sha256', toleranceSeconds: 300 },
      headerValue,
    );

    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(timestamp);
  });

  it('rejects Stripe-style timestamp when outside tolerance', () => {
    const timestamp = Math.floor(Date.now() / 1000) - 1000; // 1000s ago
    const signedPayload = `${timestamp}.${payload}`;
    const digest = computeHmacDigest(signedPayload, secret, 'sha256');
    const headerValue = `t=${timestamp},v1=${digest}`;

    const result = verifySignature(
      payload,
      { secret, algorithm: 'sha256', toleranceSeconds: 60 },
      headerValue,
    );

    expect(result.valid).toBe(false);
    expect(result.error).toBe('TIMESTAMP_OUT_OF_TOLERANCE');
  });

  it('rejects tampered payload', () => {
    const digest = computeHmacDigest(payload, secret, 'sha256');
    const tamperedPayload = JSON.stringify({ event: 'order.completed', id: 99999 });

    const result = verifySignature(
      tamperedPayload,
      { secret, algorithm: 'sha256' },
      digest,
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Signature digest mismatch');
  });

  it('rejects incorrect secret', () => {
    const digest = computeHmacDigest(payload, 'wrong-secret', 'sha256');
    const result = verifySignature(payload, { secret, algorithm: 'sha256' }, digest);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Signature digest mismatch');
  });

  it('handles missing secret gracefully without leaking secret', () => {
    const result = verifySignature(
      payload,
      { secret: '', algorithm: 'sha256' },
      'some-sig',
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBe('SIGNING_SECRET_MISSING');
  });

  it('handles missing signature header gracefully', () => {
    const result = verifySignature(payload, { secret, algorithm: 'sha256' }, undefined);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('SIGNATURE_HEADER_MISSING');
  });

  it('handles empty signature header gracefully', () => {
    const result = verifySignature(payload, { secret, algorithm: 'sha256' }, '');
    expect(result.valid).toBe(false);
    expect(result.error).toBe('SIGNATURE_HEADER_EMPTY');
  });

  it('handles malformed header without throwing', () => {
    const result = verifySignature(
      payload,
      { secret, algorithm: 'sha256' },
      '===malformed===',
    );
    expect(result.valid).toBe(false);
  });

  it('timing-safe string comparison correctly compares identical and non-identical strings', () => {
    expect(timingSafeCompare('abc123def456', 'abc123def456')).toBe(true);
    expect(timingSafeCompare('abc123def456', 'abc123def457')).toBe(false);
    expect(timingSafeCompare('short', 'much-longer-string')).toBe(false);
    expect(timingSafeCompare('', '')).toBe(true);
  });

  it('verifies exact raw body without altering whitespace or characters', () => {
    const rawWithWhitespace = '  {\n  "raw": true\n}  ';
    const digest = computeHmacDigest(rawWithWhitespace, secret, 'sha256');

    expect(
      verifySignature(rawWithWhitespace, { secret, algorithm: 'sha256' }, digest).valid,
    ).toBe(true);

    // If whitespace is trimmed, verification fails
    expect(
      verifySignature(rawWithWhitespace.trim(), { secret, algorithm: 'sha256' }, digest)
        .valid,
    ).toBe(false);
  });

  it('parses signature header with multiple prefixes and whitespace', () => {
    const parsed1 = parseSignatureHeader('  sha256=abcdef1234  ');
    expect(parsed1.signature).toBe('abcdef1234');
    expect(parsed1.extractedPrefix).toBe('sha256=');

    const parsed2 = parseSignatureHeader('raw-signature-value');
    expect(parsed2.signature).toBe('raw-signature-value');

    const parsed3 = parseSignatureHeader('t=1600000000,v1=sigvalue');
    expect(parsed3.timestamp).toBe(1600000000);
    expect(parsed3.signature).toBe('sigvalue');
  });

  it('preserves base64 padding (= or ==) during parsing and verification', () => {
    const parsed = parseSignatureHeader('sha256=SGVsbG8gV29ybGQ=');
    expect(parsed.signature).toBe('SGVsbG8gV29ybGQ=');

    const parsedDouble = parseSignatureHeader('sha256=SGVsbG8==');
    expect(parsedDouble.signature).toBe('SGVsbG8==');

    const b64Digest = computeHmacDigest(payload, secret, 'sha256', 'base64');
    const result = verifySignature(
      payload,
      { secret, algorithm: 'sha256', encoding: 'base64' },
      b64Digest,
    );
    expect(result.valid).toBe(true);
  });

  it('enforces case-sensitivity for base64 digests and case-insensitivity for hex', () => {
    // Hex is case-insensitive
    const hexDigest = computeHmacDigest(payload, secret, 'sha256', 'hex');
    expect(
      verifySignature(payload, { secret, algorithm: 'sha256' }, hexDigest.toUpperCase())
        .valid,
    ).toBe(true);

    // Base64 is case-sensitive
    const b64Digest = computeHmacDigest(payload, secret, 'sha256', 'base64');
    // Invert casing of first alphabetical character
    const alteredB64 = b64Digest.replace(/[a-zA-Z]/, (c) =>
      c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase(),
    );
    if (alteredB64 !== b64Digest) {
      expect(
        verifySignature(
          payload,
          { secret, algorithm: 'sha256', encoding: 'base64' },
          alteredB64,
        ).valid,
      ).toBe(false);
    }
  });

  it('supports multi-signature headers for seamless secret rotation', () => {
    const oldSecret = 'previous-secret-key-1';
    const newSecret = 'current-secret-key-2';

    const timestamp = Math.floor(Date.now() / 1000);
    const signedPayload = `${timestamp}.${payload}`;
    const oldDigest = computeHmacDigest(signedPayload, oldSecret, 'sha256');
    const newDigest = computeHmacDigest(signedPayload, newSecret, 'sha256');

    // Header containing both old and new signatures
    const multiHeader = `t=${timestamp},v1=${oldDigest},v1=${newDigest}`;

    // Valid with new secret
    const resultWithNew = verifySignature(
      payload,
      { secret: newSecret, algorithm: 'sha256', toleranceSeconds: 300 },
      multiHeader,
    );
    expect(resultWithNew.valid).toBe(true);

    // Valid with old secret
    const resultWithOld = verifySignature(
      payload,
      { secret: oldSecret, algorithm: 'sha256', toleranceSeconds: 300 },
      multiHeader,
    );
    expect(resultWithOld.valid).toBe(true);

    // Invalid with completely unrelated secret
    const resultWithWrong = verifySignature(
      payload,
      { secret: 'unrelated-secret', algorithm: 'sha256', toleranceSeconds: 300 },
      multiHeader,
    );
    expect(resultWithWrong.valid).toBe(false);
  });
});
