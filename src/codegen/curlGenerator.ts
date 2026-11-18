import type { WebhookEvent } from '../events/types.js';

export interface CurlOptions {
  overrideUrl?: string;
  includeHeaders?: boolean;
}

/**
 * Generates an exact, executable cURL command line string from a captured WebhookEvent.
 */
export function generateCurlCommand(
  event: WebhookEvent,
  options: CurlOptions = {},
): string {
  const targetUrl = options.overrideUrl ?? `http://127.0.0.1:8787${event.path}`;
  const method = event.method.toUpperCase();

  const lines: string[] = [`curl -X ${method} "${targetUrl}"`];

  if (options.includeHeaders !== false && event.headers) {
    for (const [key, val] of Object.entries(event.headers)) {
      // Skip hop-by-hop headers that curl manages itself
      const lower = key.toLowerCase();
      if (lower === 'host' || lower === 'content-length' || lower === 'connection') {
        continue;
      }
      const headerVal = Array.isArray(val) ? val.join(', ') : val;
      const escapedVal = headerVal.replace(/"/g, '\\"');
      lines.push(`  -H "${key}: ${escapedVal}"`);
    }
  }

  if (event.rawBody && event.rawBody.length > 0) {
    const escapedBody = event.rawBody.replace(/'/g, "'\\''");
    lines.push(`  -d '${escapedBody}'`);
  }

  return lines.join(' \\\n');
}
