import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  exportFixture,
  validateFixtureFile,
  fixtureToWebhookEvent,
} from '../src/fixtures/manager.js';
import type { WebhookEvent } from '../src/events/types.js';
import { PathSecurityError } from '../src/security/path.js';

describe('Payload Fixtures Manager', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'workbench-fixtures-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  function createSampleEvent(): WebhookEvent {
    return {
      id: 'evt_fixture_orig_123',
      timestamp: '2026-10-10T14:30:00Z',
      method: 'POST',
      path: '/api/v1/stripe',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer secret_live_token',
        'x-stripe-signature': 't=123,v1=sig',
      },
      query: { live: 'false' },
      rawBody: JSON.stringify({ event: 'customer.subscription.created', id: 'sub_999' }),
      body: { event: 'customer.subscription.created', id: 'sub_999' },
      isJson: true,
      jsonError: null,
      contentType: 'application/json',
      contentLength: 60,
      responseStatus: 200,
      durationMs: 8,
      signature: null,
      replays: [],
    };
  }

  it('exports event to a valid fixture JSON file', async () => {
    const event = createSampleEvent();
    const outputPath = path.join(tempDir, 'sub-created.json');

    const savedPath = await exportFixture(event, outputPath, {
      name: 'subscription-created',
      description: 'Test fixture for customer subscription',
    });

    expect(savedPath).toBe(outputPath);

    // File exists with restrictive permissions (0o600)
    const stat = await fs.stat(outputPath);
    expect(stat.isFile()).toBe(true);
    if (process.platform !== 'win32') {
      expect(stat.mode & 0o777).toBe(0o600);
    }

    // Validate exported file
    const validation = await validateFixtureFile(outputPath);
    expect(validation.valid).toBe(true);
    expect(validation.schemaVersion).toBe('1.0.0');
    expect(validation.summary?.originalEventId).toBe(event.id);
    expect(validation.summary?.method).toBe('POST');
    expect(validation.summary?.path).toBe('/api/v1/stripe');
    expect(validation.fixture?.request.rawBody).toBe(event.rawBody);
  });

  it('prevents accidental file overwrite without explicit overwrite flag', async () => {
    const event = createSampleEvent();
    const outputPath = path.join(tempDir, 'existing.json');
    await fs.writeFile(outputPath, '{}', 'utf8');

    await expect(
      exportFixture(event, outputPath, { overwrite: false }),
    ).rejects.toThrowError(PathSecurityError);

    // Can overwrite when explicit
    await exportFixture(event, outputPath, { overwrite: true });
    const content = JSON.parse(await fs.readFile(outputPath, 'utf8'));
    expect(content.schemaVersion).toBe('1.0.0');
  });

  it('redacts sensitive auth headers on export when redactAuthHeaders is true', async () => {
    const event = createSampleEvent();
    const outputPath = path.join(tempDir, 'sanitized.json');

    await exportFixture(event, outputPath, { redactAuthHeaders: true });
    const validation = await validateFixtureFile(outputPath);

    expect(validation.valid).toBe(true);
    expect(validation.fixture?.request.headers['authorization']).toBe('[REDACTED]');
  });

  it('validates and reports schema errors for invalid fixture file', async () => {
    const badPath = path.join(tempDir, 'invalid-schema.json');
    // Missing required fields
    const invalidJson = {
      schemaVersion: '1.0.0',
      metadata: {},
    };
    await fs.writeFile(badPath, JSON.stringify(invalidJson), 'utf8');

    const result = await validateFixtureFile(badPath);
    expect(result.valid).toBe(false);
    expect(result.errors?.length).toBeGreaterThan(0);
  });

  it('reports errors for non-existent or unparseable JSON fixture', async () => {
    const missing = await validateFixtureFile(path.join(tempDir, 'does-not-exist.json'));
    expect(missing.valid).toBe(false);
    expect(missing.errors?.[0]).toContain('Unable to read fixture file');

    const corruptPath = path.join(tempDir, 'corrupt.json');
    await fs.writeFile(corruptPath, '{ not valid json', 'utf8');
    const corrupt = await validateFixtureFile(corruptPath);
    expect(corrupt.valid).toBe(false);
    expect(corrupt.errors?.[0]).toContain('Invalid JSON');
  });

  it('converts a fixture back to a WebhookEvent for replaying', async () => {
    const event = createSampleEvent();
    const outputPath = path.join(tempDir, 'roundtrip.json');
    await exportFixture(event, outputPath);

    const validation = await validateFixtureFile(outputPath);
    expect(validation.valid).toBe(true);

    const restoredEvent = fixtureToWebhookEvent(validation.fixture!);
    expect(restoredEvent.method).toBe(event.method);
    expect(restoredEvent.path).toBe(event.path);
    expect(restoredEvent.rawBody).toBe(event.rawBody);
    expect(restoredEvent.body).toEqual(event.body);
    expect(restoredEvent.isJson).toBe(true);
  });
});
