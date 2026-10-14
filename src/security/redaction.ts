const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'api-key',
  'apikey',
  'secret',
  'webhook-secret',
  'x-webhook-secret',
  'token',
  'x-auth-token',
  'x-access-token',
  'x-hub-signature',
  'x-hub-signature-256',
  'stripe-signature',
]);

const SENSITIVE_FIELD_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /auth/i,
  /access[_-]?token/i,
  /refresh[_-]?token/i,
  /client[_-]?secret/i,
  /private[_-]?key/i,
  /credentials/i,
  /ssn/i,
  /credit[_-]?card/i,
  /cvv/i,
];

const SENSITIVE_STRING_PATTERNS = [
  // Bearer tokens
  /Bearer\s+[A-Za-z0-9_\-.~+/]+=*/gi,
  // JWT tokens (3 base64 segments)
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-.~+/]+=*/g,
  // Stripe API keys
  /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
  // Generic hex/alphanumeric secrets > 32 chars
  /\b[0-9a-fA-F]{32,64}\b/g,
];

export const REDACTED_PLACEHOLDER = '[REDACTED]';

/**
 * Returns true if a header name is considered sensitive.
 */
export function isSensitiveHeader(headerName: string): boolean {
  const lower = headerName.toLowerCase();
  if (SENSITIVE_HEADER_NAMES.has(lower)) {
    return true;
  }
  return SENSITIVE_FIELD_PATTERNS.some((pattern) => pattern.test(lower));
}

/**
 * Returns true if an object property key is considered sensitive.
 */
export function isSensitiveFieldKey(key: string): boolean {
  return SENSITIVE_FIELD_PATTERNS.some((pattern) => pattern.test(key));
}

/**
 * Redacts known sensitive patterns inside a raw text string.
 */
export function redactString(text: string): string {
  if (!text || typeof text !== 'string') {
    return text;
  }
  let result = text;
  for (const pattern of SENSITIVE_STRING_PATTERNS) {
    result = result.replace(pattern, REDACTED_PLACEHOLDER);
  }
  return result;
}

/**
 * Returns a new headers record with sensitive values replaced with [REDACTED].
 */
export function redactHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};

  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;

    if (isSensitiveHeader(key)) {
      result[key] = Array.isArray(value)
        ? value.map(() => REDACTED_PLACEHOLDER)
        : REDACTED_PLACEHOLDER;
    } else {
      if (Array.isArray(value)) {
        result[key] = value.map((v) => redactString(v));
      } else if (typeof value === 'string') {
        result[key] = redactString(value);
      } else {
        result[key] = value;
      }
    }
  }

  return result;
}

/**
 * Recursively redacts sensitive keys and values in an object or array.
 */
export function redactPayload<T>(value: T): T {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'string') {
    return redactString(value) as unknown as T;
  }

  if (typeof value !== 'object') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactPayload(item)) as unknown as T;
  }

  const obj = value as Record<string, unknown>;
  const result: Record<string, unknown> = {};

  for (const [k, v] of Object.entries(obj)) {
    if (isSensitiveFieldKey(k)) {
      result[k] = REDACTED_PLACEHOLDER;
    } else {
      result[k] = redactPayload(v);
    }
  }

  return result as T;
}

/**
 * Returns a new query parameters record with sensitive keys and values redacted.
 */
export function redactQueryParams(
  query: Record<string, string | string[] | undefined>,
): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};

  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;

    const isSensitive = isSensitiveFieldKey(key) || isSensitiveHeader(key);
    if (isSensitive) {
      result[key] = Array.isArray(value)
        ? value.map(() => REDACTED_PLACEHOLDER)
        : REDACTED_PLACEHOLDER;
    } else {
      if (Array.isArray(value)) {
        result[key] = value.map((v) => redactString(v));
      } else if (typeof value === 'string') {
        result[key] = redactString(value);
      } else {
        result[key] = value;
      }
    }
  }

  return result;
}

/**
 * Creates a redacted shallow/deep clone of a WebhookEvent for terminal display and JSON reports,
 * ensuring sensitive tokens in headers, body, and query are redacted without mutating the store.
 */
export function redactEventForDisplay<
  T extends {
    headers: Record<string, string | string[]>;
    query?: Record<string, string | string[]>;
    body: unknown;
    rawBody: string;
    replays?: Array<{
      responseHeaders?: Record<string, string>;
      responseBodyPreview?: string;
    }>;
  },
>(event: T): T {
  return {
    ...event,
    headers: redactHeaders(event.headers),
    query: event.query ? (redactQueryParams(event.query) as T['query']) : event.query,
    body: event.body ? redactPayload(event.body) : null,
    rawBody: redactString(event.rawBody),
    replays: event.replays
      ? event.replays.map((r) => ({
          ...r,
          responseHeaders: r.responseHeaders
            ? (redactHeaders(r.responseHeaders) as Record<string, string>)
            : undefined,
          responseBodyPreview: r.responseBodyPreview
            ? redactString(r.responseBodyPreview)
            : undefined,
        }))
      : [],
  };
}
