import http from 'node:http';
import https from 'node:https';
import type { WebhookEvent } from '../events/types.js';
import { validateDestinationUrl, createSsrfLookup } from '../security/ssrf.js';

export interface FuzzMutation {
  name: string;
  description: string;
  mutatedBody: string;
  headers: Record<string, string>;
}

export interface FuzzMutationResult {
  mutationName: string;
  description: string;
  status?: number;
  durationMs: number;
  handledSafely: boolean;
  error?: string;
  responseSnippet?: string;
}

export interface FuzzReport {
  targetUrl: string;
  totalMutations: number;
  safeCount: number;
  crashedCount: number;
  resilienceScorePercent: number;
  results: FuzzMutationResult[];
}

export interface FuzzTestOptions {
  allowLoopback?: boolean;
  allowPrivate?: boolean;
  timeoutMs?: number;
  secret?: string;
}

/**
 * Generates mutated payload variations to test downstream webhook consumers.
 */
export function generateFuzzMutations(baseEvent: WebhookEvent): FuzzMutation[] {
  const mutations: FuzzMutation[] = [];
  const baseHeaders: Record<string, string> = {};

  for (const [k, v] of Object.entries(baseEvent.headers || {})) {
    if (k.toLowerCase() !== 'content-length' && k.toLowerCase() !== 'host') {
      baseHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
    }
  }

  let parsed: Record<string, unknown> | null = null;
  if (
    baseEvent.body &&
    typeof baseEvent.body === 'object' &&
    !Array.isArray(baseEvent.body)
  ) {
    parsed = JSON.parse(JSON.stringify(baseEvent.body));
  } else {
    try {
      parsed = JSON.parse(baseEvent.rawBody);
    } catch {
      parsed = null;
    }
  }

  // 1. Malformed JSON (truncated syntax)
  mutations.push({
    name: 'malformed_truncated_json',
    description: 'Incomplete JSON body with missing closing braces',
    mutatedBody: baseEvent.rawBody.slice(
      0,
      Math.max(1, Math.floor(baseEvent.rawBody.length * 0.75)),
    ),
    headers: { ...baseHeaders, 'content-type': 'application/json' },
  });

  // 2. Empty Body
  mutations.push({
    name: 'empty_body',
    description: 'Completely empty request body with JSON content-type',
    mutatedBody: '',
    headers: { ...baseHeaders, 'content-type': 'application/json' },
  });

  if (parsed && typeof parsed === 'object') {
    // 3. Prototype Pollution Injection (Safely formatted as JSON string to test consumer without polluting host process)
    const baseJson = JSON.stringify(parsed);
    const mutatedProtoJson = baseJson.startsWith('{')
      ? '{"__proto__":{"isAdmin":true},"constructor":{"prototype":{"polluter":true}},' +
        baseJson.slice(1)
      : '{"__proto__":{"isAdmin":true}}';
    mutations.push({
      name: 'prototype_pollution_keys',
      description: 'Payload containing __proto__ and constructor prototype keys',
      mutatedBody: mutatedProtoJson,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
    });

    // 4. Missing required top-level fields
    const topKeys = Object.keys(parsed);
    for (const key of topKeys.slice(0, 3)) {
      const omitted = { ...parsed };
      delete omitted[key];
      mutations.push({
        name: `missing_key_${key}`,
        description: `Omitted top-level key "${key}"`,
        mutatedBody: JSON.stringify(omitted),
        headers: { ...baseHeaders, 'content-type': 'application/json' },
      });
    }

    // 5. Null Byte Injection in string fields
    const nullInjected = JSON.parse(JSON.stringify(parsed));
    for (const [k, v] of Object.entries(nullInjected)) {
      if (typeof v === 'string') {
        nullInjected[k] = `${v}\u0000_null_injected`;
        break;
      }
    }
    mutations.push({
      name: 'null_byte_injection',
      description: 'Injected null character (\\u0000) into string property',
      mutatedBody: JSON.stringify(nullInjected),
      headers: { ...baseHeaders, 'content-type': 'application/json' },
    });

    // 6. SQL / NoSQL Injection tokens
    const sqlInjected = JSON.parse(JSON.stringify(parsed));
    for (const [k, v] of Object.entries(sqlInjected)) {
      if (typeof v === 'string') {
        sqlInjected[k] = `' OR '1'='1' --`;
        break;
      }
    }
    mutations.push({
      name: 'sql_injection_probe',
      description: "SQL injection condition (' OR '1'='1' --) in text parameter",
      mutatedBody: JSON.stringify(sqlInjected),
      headers: { ...baseHeaders, 'content-type': 'application/json' },
    });

    // 7. Oversized String Property (Buffer stress test)
    const giantInjected = JSON.parse(JSON.stringify(parsed));
    for (const [k, v] of Object.entries(giantInjected)) {
      if (typeof v === 'string') {
        giantInjected[k] = 'A'.repeat(65536); // 64 KiB string
        break;
      }
    }
    mutations.push({
      name: 'oversized_string_field',
      description: '64 KiB string parameter stress test',
      mutatedBody: JSON.stringify(giantInjected),
      headers: { ...baseHeaders, 'content-type': 'application/json' },
    });
  }

  return mutations;
}

/**
 * Runs a fuzz testing suite against an application destination endpoint.
 */
export async function runFuzzTesting(
  targetUrl: string,
  baseEvent: WebhookEvent,
  options: FuzzTestOptions = {},
): Promise<FuzzReport> {
  const validated = await validateDestinationUrl(targetUrl, {
    allowLoopback: options.allowLoopback ?? true,
    allowPrivate: options.allowPrivate ?? false,
  });

  const isHttps = validated.url.protocol === 'https:';
  const transport = isHttps ? https : http;
  const cleanHost = validated.url.hostname.replace(/^\[|\]$/g, '');
  const lookup = createSsrfLookup({
    allowLoopback: options.allowLoopback ?? true,
    allowPrivate: options.allowPrivate ?? false,
  });

  const mutations = generateFuzzMutations(baseEvent);
  const results: FuzzMutationResult[] = [];

  for (const mutation of mutations) {
    const startTime = Date.now();
    try {
      const res = await new Promise<{ status: number; body: string }>(
        (resolve, reject) => {
          const reqOptions: http.RequestOptions = {
            method: 'POST',
            hostname: cleanHost,
            port: validated.url.port || (isHttps ? 443 : 80),
            path: `${validated.url.pathname}${validated.url.search}`,
            headers: {
              ...mutation.headers,
              'content-length': Buffer.byteLength(mutation.mutatedBody),
            },
            lookup,
            timeout: options.timeoutMs ?? 5000,
          };

          const req = transport.request(reqOptions, (httpRes) => {
            let resBody = '';
            httpRes.on('data', (c) => (resBody += c.toString('utf8')));
            httpRes.on('end', () => {
              resolve({ status: httpRes.statusCode ?? 0, body: resBody });
            });
          });

          req.on('error', reject);
          req.on('timeout', () => {
            req.destroy(new Error('Request timed out'));
          });

          req.write(mutation.mutatedBody);
          req.end();
        },
      );

      const durationMs = Date.now() - startTime;
      // Handled safely if target returned a non-500 client rejection (e.g. 400 Bad Request, 422 Unprocessable) or successful handling
      const handledSafely = res.status < 500;

      results.push({
        mutationName: mutation.name,
        description: mutation.description,
        status: res.status,
        durationMs,
        handledSafely,
        responseSnippet: res.body.slice(0, 300),
      });
    } catch (err: unknown) {
      const durationMs = Date.now() - startTime;
      results.push({
        mutationName: mutation.name,
        description: mutation.description,
        durationMs,
        handledSafely: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const safeCount = results.filter((r) => r.handledSafely).length;
  const crashedCount = results.length - safeCount;
  const resilienceScorePercent =
    results.length > 0 ? Math.round((safeCount / results.length) * 100) : 100;

  return {
    targetUrl,
    totalMutations: results.length,
    safeCount,
    crashedCount,
    resilienceScorePercent,
    results,
  };
}

export const runFuzzTest = runFuzzTesting;
