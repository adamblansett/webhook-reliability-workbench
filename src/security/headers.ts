/**
 * HTTP Header Security & Validation utilities.
 * Enforces RFC 7230 / 9110 token constraints to prevent CRLF injection,
 * response splitting, and HTTP request smuggling.
 */

export class HeaderSecurityError extends Error {
  constructor(
    message: string,
    public readonly reason: string,
    public readonly headerName?: string,
  ) {
    super(message);
    this.name = 'HeaderSecurityError';
  }
}

/** RFC 7230 token characters: 1*tchar */
const VALID_HEADER_NAME_REGEX = /^[a-zA-Z0-9!#$%&'*+-.^_`|~]+$/;

/**
 * Validates that an HTTP header name adheres to RFC 7230 token specifications.
 */
export function isValidHeaderName(name: string): boolean {
  if (!name || typeof name !== 'string') return false;
  return VALID_HEADER_NAME_REGEX.test(name);
}

/**
 * Checks whether an HTTP header value contains illegal characters such as CRLF (\r, \n) or null bytes (\0).
 */
export function isValidHeaderValue(value: string): boolean {
  if (typeof value !== 'string') return false;
  // Disallow null bytes and unencoded CR or LF
  return !/[\r\n\0]/.test(value);
}

/**
 * Sanitizes a header value by stripping carriage returns, line feeds, and null bytes.
 */
export function sanitizeHeaderValue(value: string): string {
  if (typeof value !== 'string') return '';
  return value.replace(/[\r\n\0]/g, ' ').trim();
}

/**
 * Validates and sanitizes a dictionary of outgoing headers.
 * Throws HeaderSecurityError in strict mode if invalid header names or unfixable values are detected.
 *
 * @param headers Headers dictionary to sanitize.
 * @param strict If true, throws on invalid headers; if false, drops or sanitizes them.
 */
export function sanitizeHeaders(
  headers: Record<string, string | string[] | undefined>,
  strict = false,
): Record<string, string> {
  const result: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined || value === null) continue;

    const trimmedKey = key.trim();
    if (!isValidHeaderName(trimmedKey)) {
      if (strict) {
        throw new HeaderSecurityError(
          `Invalid HTTP header name "${key}". Header names must only contain RFC 7230 token characters.`,
          'INVALID_HEADER_NAME',
          key,
        );
      }
      continue;
    }

    const lowerKey = trimmedKey.toLowerCase();
    const rawVal = Array.isArray(value) ? value.join(', ') : String(value);

    if (!isValidHeaderValue(rawVal)) {
      if (strict) {
        throw new HeaderSecurityError(
          `Header "${key}" contains forbidden CRLF characters or null bytes (CRLF injection attempt).`,
          'CRLF_INJECTION_DETECTED',
          key,
        );
      }
      result[lowerKey] = sanitizeHeaderValue(rawVal);
    } else {
      result[lowerKey] = rawVal;
    }
  }

  return result;
}
