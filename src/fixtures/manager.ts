import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import type { WebhookEvent } from '../events/types.js';
import { WebhookFixtureSchema, type WebhookFixture } from './schema.js';
import { resolveSafePath, assertFileWriteSafety } from '../security/path.js';
import { redactHeaders } from '../security/redaction.js';

export interface ExportFixtureOptions {
  overwrite?: boolean;
  name?: string;
  description?: string;
  redactAuthHeaders?: boolean;
}

export interface FixtureValidationResult {
  valid: boolean;
  filePath: string;
  schemaVersion?: string;
  fixture?: WebhookFixture;
  errors?: string[];
  summary?: {
    method: string;
    path: string;
    contentType: string | null;
    bodySize: number;
    originalEventId: string;
  };
}

/**
 * Exports a captured WebhookEvent to a portable, standardized JSON fixture file.
 */
export async function exportFixture(
  event: WebhookEvent,
  outputPath: string,
  options: ExportFixtureOptions = {},
): Promise<string> {
  const safePath = resolveSafePath(outputPath);
  await assertFileWriteSafety(safePath, options.overwrite ?? false);

  const parentDir = path.dirname(safePath);
  await fs.mkdir(parentDir, { recursive: true });

  const headers = options.redactAuthHeaders
    ? redactHeaders(event.headers)
    : { ...event.headers };

  const fixture: WebhookFixture = {
    schemaVersion: '1.0.0',
    metadata: {
      name: options.name ?? path.basename(safePath, '.json'),
      description: options.description ?? `Exported webhook event ${event.id}`,
      exportedAt: new Date().toISOString(),
      originalEventId: event.id,
      generator: 'webhook-reliability-workbench',
    },
    request: {
      method: event.method,
      path: event.path,
      headers,
      query: event.query,
      contentType: event.contentType,
      contentLength: event.contentLength,
      rawBody: event.rawBody,
      body: event.body,
      isJson: event.isJson,
    },
  };

  // Validate before writing to disk
  WebhookFixtureSchema.parse(fixture);

  const tmpPath = `${safePath}.tmp.${Date.now()}.${crypto.randomBytes(3).toString('hex')}`;
  await fs.writeFile(tmpPath, JSON.stringify(fixture, null, 2), {
    encoding: 'utf8',
    mode: 0o600,
  });
  await fs.rename(tmpPath, safePath);
  await fs.chmod(safePath, 0o600).catch(() => {});

  return safePath;
}

/**
 * Validates a fixture JSON file against the WebhookFixtureSchema.
 */
export async function validateFixtureFile(
  filePath: string,
): Promise<FixtureValidationResult> {
  const safePath = resolveSafePath(filePath);

  let content: string;
  try {
    content = await fs.readFile(safePath, 'utf8');
  } catch (err) {
    return {
      valid: false,
      filePath: safePath,
      errors: [
        `Unable to read fixture file: ${err instanceof Error ? err.message : String(err)}`,
      ],
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (err) {
    return {
      valid: false,
      filePath: safePath,
      errors: [
        `Invalid JSON in fixture file: ${err instanceof Error ? err.message : String(err)}`,
      ],
    };
  }

  const parseResult = WebhookFixtureSchema.safeParse(parsed);
  if (!parseResult.success) {
    const formattedErrors = parseResult.error.issues.map(
      (issue) => `[${issue.path.join('.') || 'root'}]: ${issue.message}`,
    );
    return {
      valid: false,
      filePath: safePath,
      errors: formattedErrors,
    };
  }

  const fixture = parseResult.data;
  return {
    valid: true,
    filePath: safePath,
    schemaVersion: fixture.schemaVersion,
    fixture,
    summary: {
      method: fixture.request.method,
      path: fixture.request.path,
      contentType: fixture.request.contentType,
      bodySize: fixture.request.contentLength,
      originalEventId: fixture.metadata.originalEventId,
    },
  };
}

/**
 * Converts a validated WebhookFixture back into a WebhookEvent for replaying or testing.
 */
export function fixtureToWebhookEvent(fixture: WebhookFixture): WebhookEvent {
  return {
    id: `evt_fixture_${fixture.metadata.originalEventId}`,
    timestamp: fixture.metadata.exportedAt,
    method: fixture.request.method,
    path: fixture.request.path,
    headers: fixture.request.headers,
    query: fixture.request.query,
    rawBody: fixture.request.rawBody,
    body: fixture.request.body,
    isJson: fixture.request.isJson,
    jsonError: null,
    contentType: fixture.request.contentType,
    contentLength: fixture.request.contentLength,
    responseStatus: 200,
    durationMs: 0,
    signature: null,
    replays: [],
  };
}
