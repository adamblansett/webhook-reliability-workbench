import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import type { ReplayOptions, ReplayResult } from './types.js';
import type { WebhookEvent, EventStore } from '../events/types.js';
import {
  validateDestinationUrl,
  createSsrfLookup,
  SsrSecurityError,
} from '../security/ssrf.js';
import { LIMITS } from '../security/limits.js';
import { computeHmacDigest } from '../signatures/verifier.js';
import { isSensitiveHeader, redactHeaders, redactString } from '../security/redaction.js';

const DISALLOWED_FORWARD_HEADERS = new Set([
  'host',
  'content-length',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'te',
  'upgrade',
]);

const AUTH_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
]);

const SIGNATURE_HEADERS = new Set([
  'x-hub-signature',
  'x-hub-signature-256',
  'stripe-signature',
  'x-signature',
  'x-webhook-signature',
  'signature',
]);

/**
 * Executes a safe replay of a captured webhook event to a target destination.
 */
export async function replayWebhookEvent(
  event: WebhookEvent,
  options: ReplayOptions,
  store?: EventStore,
): Promise<ReplayResult> {
  const replayId = `rpl_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`;
  const startTime = Date.now();
  const maxRedirects = Math.min(
    Math.max(0, options.maxRedirects ?? LIMITS.MAX_REDIRECTS),
    10,
  );

  let currentUrl = options.url;
  let redirectCount = 0;
  let currentMethod = event.method ?? 'POST';

  const timeoutMs = Math.min(
    Math.max(
      LIMITS.MIN_REPLAY_TIMEOUT_MS,
      options.timeoutMs ?? LIMITS.DEFAULT_REPLAY_TIMEOUT_MS,
    ),
    LIMITS.MAX_REPLAY_TIMEOUT_MS,
  );
  const maxResponseSize = Math.min(
    Math.max(
      1024,
      options.maxResponseSizeBytes ?? LIMITS.DEFAULT_MAX_RESPONSE_SIZE_BYTES,
    ),
    LIMITS.MAX_ALLOWED_RESPONSE_SIZE_BYTES,
  );

  // Prepare outgoing headers
  const outgoingHeaders: Record<string, string> = {
    'user-agent': 'Webhook-Reliability-Workbench/0.1.0',
  };

  for (const [key, value] of Object.entries(event.headers)) {
    const lowerKey = key.toLowerCase();

    // Skip hop-by-hop and connection headers
    if (DISALLOWED_FORWARD_HEADERS.has(lowerKey)) {
      continue;
    }

    // Default: strip authentication headers unless explicitly requested
    if (!options.keepAuth && AUTH_HEADERS.has(lowerKey)) {
      continue;
    }

    // Default: strip signature headers unless explicitly requested
    if (
      !options.keepSignatures &&
      (SIGNATURE_HEADERS.has(lowerKey) || isSensitiveHeader(lowerKey))
    ) {
      continue;
    }

    outgoingHeaders[lowerKey] = Array.isArray(value) ? value.join(', ') : String(value);
  }

  // Remove explicit headers
  if (options.removeHeaders) {
    for (const h of options.removeHeaders) {
      delete outgoingHeaders[h.toLowerCase()];
    }
  }

  // Header overrides
  if (options.headerOverrides) {
    for (const [k, v] of Object.entries(options.headerOverrides)) {
      outgoingHeaders[k.toLowerCase()] = v;
    }
  }

  // Signature regeneration if requested
  if (options.regenerateSignature) {
    if (!options.secret) {
      throw new Error(
        'Signature regeneration requires an explicit --secret option to avoid unsafe assumptions.',
      );
    }
    const sigHeaderName = (
      options.signatureHeader ?? 'x-hub-signature-256'
    ).toLowerCase();
    const algorithm = options.algorithm ?? 'sha256';
    const prefix = options.signaturePrefix ?? (algorithm === 'sha256' ? 'sha256=' : '');

    const digest = computeHmacDigest(event.rawBody, options.secret, algorithm);
    outgoingHeaders[sigHeaderName] = `${prefix}${digest}`;
  }

  // Ensure content type and length
  if (event.contentType && !outgoingHeaders['content-type']) {
    outgoingHeaders['content-type'] = event.contentType;
  }
  const bodyBuffer = Buffer.from(event.rawBody, 'utf8');
  outgoingHeaders['content-length'] = String(bodyBuffer.length);

  while (true) {
    // Validate destination URL against SSRF rules before connection
    const validated = await validateDestinationUrl(currentUrl, {
      allowLoopback: options.allowLoopback,
      allowPrivate: options.allowPrivate,
      allowedDestinations: options.allowedDestinations,
    });

    const targetUrl = validated.url;
    const isHttps = targetUrl.protocol === 'https:';
    const transport = isHttps ? https : http;

    // Use custom DNS lookup that verifies resolved IPs at connect time to eliminate DNS rebinding
    const ssrfLookup = createSsrfLookup({
      allowLoopback: options.allowLoopback,
      allowPrivate: options.allowPrivate,
      allowedDestinations: options.allowedDestinations,
    });

    const cleanHostname = targetUrl.hostname.replace(/^\[|\]$/g, '');
    const requestOptions: http.RequestOptions = {
      method: currentMethod,
      hostname: cleanHostname,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: `${targetUrl.pathname}${targetUrl.search}`,
      headers: outgoingHeaders,
      timeout: timeoutMs,
      lookup: ssrfLookup,
    };

    const responseResult = await new Promise<{
      statusCode: number;
      statusText: string;
      resHeaders: Record<string, string>;
      responseBody: string;
      isTruncated: boolean;
      error?: string;
    }>((resolve) => {
      let responseBody = '';
      let responseBytes = 0;
      let isTruncated = false;

      const req = transport.request(requestOptions, (res) => {
        res.on('data', (chunk: Buffer) => {
          responseBytes += chunk.length;
          if (responseBytes <= maxResponseSize) {
            responseBody += chunk.toString('utf8');
          } else {
            isTruncated = true;
            res.destroy();
          }
        });

        res.on('end', () => {
          const statusCode = res.statusCode ?? 0;
          const statusText =
            res.statusMessage ?? (statusCode >= 200 && statusCode < 300 ? 'OK' : 'Error');

          const resHeaders: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v !== undefined) {
              resHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
            }
          }

          resolve({
            statusCode,
            statusText,
            resHeaders,
            responseBody,
            isTruncated,
          });
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          statusCode: 0,
          statusText: 'Request Timeout',
          resHeaders: {},
          responseBody: '',
          isTruncated: false,
          error: `Request timed out after ${timeoutMs}ms`,
        });
      });

      req.on('error', (err) => {
        resolve({
          statusCode: 0,
          statusText:
            err instanceof SsrSecurityError ? 'Security Error' : 'Network Error',
          resHeaders: {},
          responseBody: '',
          isTruncated: false,
          error:
            err instanceof SsrSecurityError
              ? err.message
              : `Network failure: ${err.message}`,
        });
      });

      if (bodyBuffer.length > 0 && currentMethod !== 'GET' && currentMethod !== 'HEAD') {
        req.write(bodyBuffer);
      }
      req.end();
    });

    // Check for redirects
    const isRedirect =
      responseResult.statusCode >= 300 &&
      responseResult.statusCode < 400 &&
      Boolean(responseResult.resHeaders['location']);

    if (isRedirect && options.followRedirects) {
      if (redirectCount >= maxRedirects) {
        const durationMs = Date.now() - startTime;
        const result: ReplayResult = {
          id: replayId,
          timestamp: new Date().toISOString(),
          destination: currentUrl,
          status: responseResult.statusCode,
          statusText: 'Too Many Redirects',
          durationMs,
          success: false,
          error: `Exceeded maximum redirect limit of ${maxRedirects}`,
          requestHeadersSent: redactHeaders(outgoingHeaders),
          requestMethod: currentMethod,
          requestUrl: currentUrl,
        };
        if (store) await store.addReplay(event.id, result);
        return result;
      }

      redirectCount++;
      const redirectLocation = responseResult.resHeaders['location']!;
      const nextUrl = new URL(redirectLocation, targetUrl);

      // Security: Strip credentials and authorization headers if redirect crosses origins
      if (nextUrl.origin !== targetUrl.origin) {
        for (const h of AUTH_HEADERS) {
          delete outgoingHeaders[h];
        }
        for (const [k] of Object.entries(outgoingHeaders)) {
          if (isSensitiveHeader(k)) {
            delete outgoingHeaders[k];
          }
        }
      }

      // RFC 7231 / 9110: 301, 302, 303 change method to GET
      if (
        responseResult.statusCode === 301 ||
        responseResult.statusCode === 302 ||
        responseResult.statusCode === 303
      ) {
        currentMethod = 'GET';
        delete outgoingHeaders['content-type'];
        delete outgoingHeaders['content-length'];
      }

      currentUrl = nextUrl.toString();
      continue;
    }

    const durationMs = Date.now() - startTime;
    const statusCode = responseResult.statusCode;
    const success = statusCode >= 200 && statusCode < 300;
    const preview = responseResult.isTruncated
      ? `${responseResult.responseBody.slice(0, 1000)}... [Truncated: exceeded ${maxResponseSize} bytes]`
      : responseResult.responseBody.slice(0, 2000);

    const result: ReplayResult = {
      id: replayId,
      timestamp: new Date().toISOString(),
      destination: currentUrl,
      status: statusCode,
      statusText: responseResult.statusText,
      durationMs,
      success,
      error: responseResult.error,
      responseHeaders: redactHeaders(responseResult.resHeaders) as Record<string, string>,
      responseBodyPreview: redactString(preview),
      requestHeadersSent: redactHeaders(outgoingHeaders),
      requestMethod: currentMethod,
      requestUrl: currentUrl,
    };

    if (store) {
      await store.addReplay(event.id, result);
    }

    return result;
  }
}
