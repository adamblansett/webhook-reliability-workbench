import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { createProgram } from '../src/cli/index.js';
import { FileEventStore } from '../src/events/store.js';
import type { WebhookEvent } from '../src/events/types.js';

describe('CLI Commands Integration', () => {
  let tempDir: string;
  let storeFile: string;
  let stdoutOutput: string = '';
  let _stderrOutput: string = '';

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'workbench-cli-test-'));
    storeFile = path.join(tempDir, 'events.json');

    stdoutOutput = '';
    _stderrOutput = '';

    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stdoutOutput +=
        typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });

    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      _stderrOutput +=
        typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  function createTestEvent(id: string = 'evt_cli_test_1'): WebhookEvent {
    return {
      id,
      timestamp: new Date().toISOString(),
      method: 'POST',
      path: '/api/v1/webhook',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer secret-jwt',
      },
      query: { q: '1' },
      rawBody: JSON.stringify({ event: 'ping', test: true }),
      body: { event: 'ping', test: true },
      isJson: true,
      jsonError: null,
      contentType: 'application/json',
      contentLength: 28,
      responseStatus: 200,
      durationMs: 4,
      signature: {
        valid: true,
        algorithm: 'sha256',
        headerName: 'x-hub-signature-256',
        reason: 'Signature verified successfully',
      },
      replays: [],
    };
  }

  it('displays version number with --version', async () => {
    const program = createProgram();
    program.exitOverride();

    await expect(
      program.parseAsync(['node', 'webhook-workbench', '--version']),
    ).rejects.toThrow();
    // Commander throws on exitOverride for --version with exitCode 0
  });

  it('displays help menu with --help', async () => {
    const program = createProgram();
    program.exitOverride();

    await expect(
      program.parseAsync(['node', 'webhook-workbench', '--help']),
    ).rejects.toThrow();
  });

  it('runs config show command and outputs json when requested', async () => {
    const program = createProgram();
    program.exitOverride();

    await program.parseAsync(['node', 'webhook-workbench', 'config', 'show', '--json']);

    expect(stdoutOutput).toContain('"receiver"');
    const parsed = JSON.parse(stdoutOutput);
    expect(parsed.receiver.port).toBe(8787);
    expect(parsed.receiver.host).toBe('127.0.0.1');
  });

  it('lists events with human-readable and --json flags', async () => {
    const store = new FileEventStore(storeFile);
    await store.save(createTestEvent('evt_cli_list_1'));

    // Human-readable output
    const program1 = createProgram();
    program1.exitOverride();
    await program1.parseAsync([
      'node',
      'webhook-workbench',
      'events',
      'list',
      '--store',
      storeFile,
    ]);

    expect(stdoutOutput).toContain('evt_cli_list_1');
    expect(stdoutOutput).toContain('POST /api/v1/webhook');

    // JSON output
    stdoutOutput = '';
    const program2 = createProgram();
    program2.exitOverride();
    await program2.parseAsync([
      'node',
      'webhook-workbench',
      'events',
      'list',
      '--store',
      storeFile,
      '--json',
    ]);

    const jsonList = JSON.parse(stdoutOutput);
    expect(Array.isArray(jsonList)).toBe(true);
    expect(jsonList.length).toBe(1);
    expect(jsonList[0].id).toBe('evt_cli_list_1');
    expect(jsonList[0].headers.authorization).toBe('[REDACTED]');
  });

  it('shows detailed event inspection with events show', async () => {
    const store = new FileEventStore(storeFile);
    await store.save(createTestEvent('evt_cli_show_1'));

    const program = createProgram();
    program.exitOverride();
    await program.parseAsync([
      'node',
      'webhook-workbench',
      'events',
      'show',
      'evt_cli_show_1',
      '--store',
      storeFile,
    ]);

    expect(stdoutOutput).toContain('=== Webhook Event: evt_cli_show_1 ===');
    expect(stdoutOutput).toContain('HTTP Method:      POST');
    expect(stdoutOutput).toContain('[REDACTED]');
  });

  it('clears stored events with events clear', async () => {
    const store = new FileEventStore(storeFile);
    await store.save(createTestEvent('evt_to_clear'));

    const program = createProgram();
    program.exitOverride();
    await program.parseAsync([
      'node',
      'webhook-workbench',
      'events',
      'clear',
      '--store',
      storeFile,
    ]);

    expect(await store.count()).toBe(0);
    expect(stdoutOutput).toContain('Cleared all webhook events');
  });

  it('exports and validates payload fixtures via CLI', async () => {
    const store = new FileEventStore(storeFile);
    await store.save(createTestEvent('evt_fixture_cli'));

    const fixtureFile = path.join(tempDir, 'cli-fixture.json');

    // Export fixture
    const programExport = createProgram();
    programExport.exitOverride();
    await programExport.parseAsync([
      'node',
      'webhook-workbench',
      'fixtures',
      'export',
      'evt_fixture_cli',
      '-o',
      fixtureFile,
      '--store',
      storeFile,
    ]);

    expect(stdoutOutput).toContain('Successfully exported event');

    // Validate fixture
    stdoutOutput = '';
    const programValidate = createProgram();
    programValidate.exitOverride();
    await programValidate.parseAsync([
      'node',
      'webhook-workbench',
      'fixtures',
      'validate',
      fixtureFile,
    ]);

    expect(stdoutOutput).toContain('Fixture is valid');
  });

  it('replays captured event via replay command to target server', async () => {
    let targetPort = 0;
    const targetServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    });

    await new Promise<void>((resolve) => {
      targetServer.listen(0, '127.0.0.1', () => {
        targetPort = (targetServer.address() as { port: number }).port;
        resolve();
      });
    });

    try {
      const store = new FileEventStore(storeFile);
      await store.save(createTestEvent('evt_replay_cli'));

      const program = createProgram();
      program.exitOverride();
      await program.parseAsync([
        'node',
        'webhook-workbench',
        'replay',
        'evt_replay_cli',
        '--url',
        `http://127.0.0.1:${targetPort}/receiver`,
        '--allow-loopback',
        '--store',
        storeFile,
      ]);

      expect(stdoutOutput).toContain('=== Webhook Replay Result ===');
      expect(stdoutOutput).toContain('Outcome:');
      expect(stdoutOutput).toContain('200 OK');
    } finally {
      if (typeof targetServer.closeAllConnections === 'function') {
        targetServer.closeAllConnections();
      }
      await new Promise<void>((resolve) => targetServer.close(() => resolve()));
    }
  });

  it('runs retry testing via test-retries CLI command', async () => {
    let targetPort = 0;
    const targetServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    });

    await new Promise<void>((resolve) => {
      targetServer.listen(0, '127.0.0.1', () => {
        targetPort = (targetServer.address() as { port: number }).port;
        resolve();
      });
    });

    try {
      const store = new FileEventStore(storeFile);
      await store.save(createTestEvent('evt_retry_cli'));

      const program = createProgram();
      program.exitOverride();
      await program.parseAsync([
        'node',
        'webhook-workbench',
        'test-retries',
        'evt_retry_cli',
        '--url',
        `http://127.0.0.1:${targetPort}/receiver`,
        '--allow-loopback',
        '--attempts',
        '2',
        '--delay',
        '10',
        '--store',
        storeFile,
      ]);

      expect(stdoutOutput).toContain('=== Webhook Retry Test Summary ===');
      expect(stdoutOutput).toContain('Total Attempts:');
      expect(stdoutOutput).toContain('Attempt #1');
      expect(stdoutOutput).toContain('Attempt #2');
    } finally {
      if (typeof targetServer.closeAllConnections === 'function') {
        targetServer.closeAllConnections();
      }
      await new Promise<void>((resolve) => targetServer.close(() => resolve()));
    }
  });
});
