import { describe, it, expect } from 'vitest';
import {
  validateDestinationUrl,
  normalizeIp,
  SsrSecurityError,
} from '../src/security/ssrf.js';
import {
  redactHeaders,
  redactPayload,
  redactQueryParams,
  redactString,
  redactEventForDisplay,
  isSensitiveHeader,
  isSensitiveFieldKey,
  REDACTED_PLACEHOLDER,
} from '../src/security/redaction.js';
import { resolveSafePath, PathSecurityError } from '../src/security/path.js';

describe('Security Safeguards', () => {
  describe('SSRF Protection and Destination Validation', () => {
    it('blocks loopback IP by default', async () => {
      await expect(
        validateDestinationUrl('http://127.0.0.1:8080/webhook'),
      ).rejects.toThrowError(SsrSecurityError);

      try {
        await validateDestinationUrl('http://127.0.0.1:8080/webhook');
      } catch (err: unknown) {
        expect((err as SsrSecurityError).reason).toBe('LOOPBACK_BLOCKED');
      }
    });

    it('blocks localhost hostname by default', async () => {
      await expect(
        validateDestinationUrl('http://localhost:3000/webhook'),
      ).rejects.toThrowError(SsrSecurityError);
    });

    it('permits loopback destination when allowLoopback is true', async () => {
      const validated = await validateDestinationUrl('http://127.0.0.1:8080/webhook', {
        allowLoopback: true,
      });
      expect(validated.isLoopback).toBe(true);
      expect(validated.url.port).toBe('8080');
    });

    it('blocks private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) by default', async () => {
      await expect(
        validateDestinationUrl('http://10.0.0.1/webhook'),
      ).rejects.toThrowError(SsrSecurityError);

      await expect(
        validateDestinationUrl('http://172.20.1.5/webhook'),
      ).rejects.toThrowError(SsrSecurityError);

      await expect(
        validateDestinationUrl('http://192.168.1.100/webhook'),
      ).rejects.toThrowError(SsrSecurityError);
    });

    it('permits private IPv4 ranges when allowPrivate is true', async () => {
      const validated = await validateDestinationUrl(
        'http://192.168.1.100:8000/webhook',
        {
          allowPrivate: true,
        },
      );
      expect(validated.isPrivate).toBe(true);
    });

    it('strictly blocks AWS/GCP cloud metadata IP 169.254.169.254 even with allowLoopback/allowPrivate', async () => {
      await expect(
        validateDestinationUrl('http://169.254.169.254/latest/meta-data/', {
          allowLoopback: true,
          allowPrivate: true,
        }),
      ).rejects.toThrowError(SsrSecurityError);

      try {
        await validateDestinationUrl('http://169.254.169.254/latest/meta-data/', {
          allowLoopback: true,
          allowPrivate: true,
        });
      } catch (err) {
        expect(['LINK_LOCAL_METADATA_BLOCKED', 'METADATA_HOSTNAME_BLOCKED']).toContain(
          (err as SsrSecurityError).reason,
        );
      }
    });

    it('strictly blocks cloud metadata hostnames', async () => {
      await expect(
        validateDestinationUrl('http://metadata.google.internal/computeMetadata/v1/'),
      ).rejects.toThrowError(SsrSecurityError);
    });

    it('rejects unsupported protocols (file, ftp, gopher)', async () => {
      await expect(validateDestinationUrl('file:///etc/passwd')).rejects.toThrowError(
        'Unsupported protocol scheme "file:".',
      );

      await expect(validateDestinationUrl('ftp://example.com/data')).rejects.toThrowError(
        SsrSecurityError,
      );
    });

    it('rejects embedded credentials in destination URL', async () => {
      await expect(
        validateDestinationUrl('http://admin:secret@127.0.0.1:3000/webhook', {
          allowLoopback: true,
        }),
      ).rejects.toThrowError('embedded username or password');
    });

    it('blocks 0.0.0.0 and broadcast addresses', async () => {
      await expect(
        validateDestinationUrl('http://0.0.0.0:8080/webhook', { allowLoopback: true }),
      ).rejects.toThrowError(SsrSecurityError);

      await expect(
        validateDestinationUrl('http://255.255.255.255/webhook'),
      ).rejects.toThrowError(SsrSecurityError);
    });

    it('normalizes IPv4-mapped IPv6 addresses', () => {
      expect(normalizeIp('::ffff:127.0.0.1')).toBe('127.0.0.1');
      expect(normalizeIp('::ffff:192.168.1.1')).toBe('192.168.1.1');
    });

    it('allows destination matching allowedDestinations list', async () => {
      const validated = await validateDestinationUrl(
        'http://127.0.0.1:4000/allowed-hook',
        {
          allowedDestinations: ['http://127.0.0.1:4000/allowed-hook'],
        },
      );
      expect(validated.url.pathname).toBe('/allowed-hook');
    });
  });

  describe('Secret Redaction', () => {
    it('identifies sensitive header names', () => {
      expect(isSensitiveHeader('Authorization')).toBe(true);
      expect(isSensitiveHeader('X-Api-Key')).toBe(true);
      expect(isSensitiveHeader('Stripe-Signature')).toBe(true);
      expect(isSensitiveHeader('X-Hub-Signature-256')).toBe(true);
      expect(isSensitiveHeader('Content-Type')).toBe(false);
      expect(isSensitiveHeader('User-Agent')).toBe(false);
    });

    it('identifies sensitive payload field names', () => {
      expect(isSensitiveFieldKey('password')).toBe(true);
      expect(isSensitiveFieldKey('secretToken')).toBe(true);
      expect(isSensitiveFieldKey('client_secret')).toBe(true);
      expect(isSensitiveFieldKey('orderId')).toBe(false);
    });

    it('redacts sensitive headers while preserving non-sensitive headers', () => {
      const headers = {
        'content-type': 'application/json',
        authorization: 'Bearer super-secret-jwt-token-12345',
        'x-api-key': 'live_key_99887766',
        'user-agent': 'My-App/1.0',
      };

      const redacted = redactHeaders(headers);
      expect(redacted['content-type']).toBe('application/json');
      expect(redacted['authorization']).toBe(REDACTED_PLACEHOLDER);
      expect(redacted['x-api-key']).toBe(REDACTED_PLACEHOLDER);
      expect(redacted['user-agent']).toBe('My-App/1.0');
    });

    it('recursively redacts nested object and array payloads', () => {
      const payload = {
        user: {
          id: 42,
          password: 'plain-text-password-123',
          email: 'test@example.com',
          tokens: ['tok_1', 'tok_2'],
        },
        items: [{ sku: 'ABC', price: 100 }],
        stripe_token: 'tok_abc123',
      };

      const redacted = redactPayload(payload);
      expect(redacted.user.id).toBe(42);
      expect(redacted.user.password).toBe(REDACTED_PLACEHOLDER);
      expect(redacted.user.email).toBe('test@example.com');
      expect(redacted.stripe_token).toBe(REDACTED_PLACEHOLDER);
      expect(redacted.items[0]?.sku).toBe('ABC');
    });

    it('redacts raw strings containing Bearer tokens or secret patterns', () => {
      const raw =
        'Failed auth for Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c on server';
      const redacted = redactString(raw);
      expect(redacted).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(redacted).toContain(REDACTED_PLACEHOLDER);
    });

    it('redacts sensitive query parameters', () => {
      const query = {
        page: '1',
        token: 'secret_token_123',
        api_key: 'key_xyz',
        sort: 'desc',
      };
      const redacted = redactQueryParams(query);
      expect(redacted.page).toBe('1');
      expect(redacted.token).toBe(REDACTED_PLACEHOLDER);
      expect(redacted.api_key).toBe(REDACTED_PLACEHOLDER);
      expect(redacted.sort).toBe('desc');
    });

    it('redactEventForDisplay creates a sanitized clone without mutating the original event', () => {
      const original = {
        id: 'evt_test',
        timestamp: '2026-10-10T00:00:00Z',
        headers: { authorization: 'Bearer topsecret' },
        body: { client_secret: 'secret123', customer: 'alice' },
        rawBody: '{"client_secret":"secret123","customer":"alice"}',
        replays: [],
      };

      const display = redactEventForDisplay(original);

      // Display has redacted values
      expect(display.headers.authorization).toBe(REDACTED_PLACEHOLDER);
      expect((display.body as Record<string, unknown>).client_secret).toBe(
        REDACTED_PLACEHOLDER,
      );

      // Original is unmutated
      expect(original.headers.authorization).toBe('Bearer topsecret');
      expect(original.body.client_secret).toBe('secret123');
    });
  });

  describe('Path Security', () => {
    it('prevents null byte in path', () => {
      expect(() => resolveSafePath('file.json\0.txt')).toThrowError(PathSecurityError);
    });

    it('resolves relative path safely against base directory', () => {
      const resolved = resolveSafePath('fixtures/my-test.json', '/tmp');
      expect(resolved).toBe('/tmp/fixtures/my-test.json');
    });

    it('rejects empty paths', () => {
      expect(() => resolveSafePath('')).toThrowError(PathSecurityError);
      expect(() => resolveSafePath('   ')).toThrowError(PathSecurityError);
    });
  });
});
