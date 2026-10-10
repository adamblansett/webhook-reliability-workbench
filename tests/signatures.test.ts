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
});
