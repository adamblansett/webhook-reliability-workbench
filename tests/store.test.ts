import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  InMemoryEventStore,
  FileEventStore,
  generateEventId,
} from '../src/events/store.js';
import type { WebhookEvent, ReplayRecord } from '../src/events/types.js';

describe('Event Store', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'workbench-store-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  function createMockEvent(id: string = generateEventId()): WebhookEvent {
    return {
      id,
      timestamp: new Date().toISOString(),
      method: 'POST',
      path: '/webhooks/orders',
      headers: { 'content-type': 'application/json' },
      query: { source: 'test' },
      rawBody: '{"orderId":100}',
      body: { orderId: 100 },
      isJson: true,
      jsonError: null,
      contentType: 'application/json',
      contentLength: 15,
      responseStatus: 200,
      durationMs: 5,
      signature: null,
      replays: [],
    };
  }

  describe('InMemoryEventStore', () => {
    it('saves and retrieves events by id', async () => {
      const store = new InMemoryEventStore();
      const event = createMockEvent();

      await store.save(event);
      const retrieved = await store.get(event.id);

      expect(retrieved).not.toBeNull();
      expect(retrieved?.id).toBe(event.id);
      expect(retrieved?.body).toEqual({ orderId: 100 });
    });

    it('returns null for non-existent event', async () => {
      const store = new InMemoryEventStore();
      const result = await store.get('evt_non_existent');
      expect(result).toBeNull();
    });

    it('lists events with offset and limit', async () => {
      const store = new InMemoryEventStore();
      const e1 = createMockEvent('evt_1');
      const e2 = createMockEvent('evt_2');
      const e3 = createMockEvent('evt_3');

      await store.save(e1);
      await store.save(e2);
      await store.save(e3);

      const all = await store.list();
      expect(all.length).toBe(3);
      // Newest first
      expect(all[0]?.id).toBe('evt_3');

      const limited = await store.list({ limit: 2 });
      expect(limited.length).toBe(2);

      const offset = await store.list({ offset: 1, limit: 1 });
      expect(offset.length).toBe(1);
      expect(offset[0]?.id).toBe('evt_2');
    });

    it('enforces maximum event capacity with FIFO eviction', async () => {
      const store = new InMemoryEventStore(2);
      await store.save(createMockEvent('evt_1'));
      await store.save(createMockEvent('evt_2'));
      await store.save(createMockEvent('evt_3'));

      const count = await store.count();
      expect(count).toBe(2);

      const list = await store.list();
      expect(list.map((e) => e.id)).toEqual(['evt_3', 'evt_2']);
      expect(await store.get('evt_1')).toBeNull();
    });

    it('records replay results for an existing event', async () => {
      const store = new InMemoryEventStore();
      const event = createMockEvent();
      await store.save(event);

      const replay: ReplayRecord = {
        id: 'rpl_1',
        timestamp: new Date().toISOString(),
        destination: 'http://127.0.0.1:3000/webhook',
        status: 200,
        statusText: 'OK',
        durationMs: 25,
        success: true,
      };

      const success = await store.addReplay(event.id, replay);
      expect(success).toBe(true);

      const updated = await store.get(event.id);
      expect(updated?.replays.length).toBe(1);
      expect(updated?.replays[0]?.id).toBe('rpl_1');
    });

    it('clears all events', async () => {
      const store = new InMemoryEventStore();
      await store.save(createMockEvent());
      await store.clear();
      expect(await store.count()).toBe(0);
    });
  });

  describe('FileEventStore', () => {
    it('persists and loads events from disk', async () => {
      const filePath = path.join(tempDir, 'events.json');
      const store1 = new FileEventStore(filePath);
      const event = createMockEvent();

      await store1.save(event);

      // Create new instance pointing to same file
      const store2 = new FileEventStore(filePath);
      const retrieved = await store2.get(event.id);

      expect(retrieved).not.toBeNull();
      expect(retrieved?.id).toBe(event.id);
      expect(retrieved?.method).toBe('POST');
    });

    it('maintains bounded capacity on disk', async () => {
      const filePath = path.join(tempDir, 'events.json');
      const store = new FileEventStore(filePath, 2);

      await store.save(createMockEvent('evt_1'));
      await store.save(createMockEvent('evt_2'));
      await store.save(createMockEvent('evt_3'));

      expect(await store.count()).toBe(2);
      expect(await store.get('evt_1')).toBeNull();
      expect(await store.get('evt_3')).not.toBeNull();
    });

    it('adds replay history persistently', async () => {
      const filePath = path.join(tempDir, 'events.json');
      const store = new FileEventStore(filePath);
      const event = createMockEvent();

      await store.save(event);

      const replay: ReplayRecord = {
        id: 'rpl_persistent_1',
        timestamp: new Date().toISOString(),
        destination: 'http://127.0.0.1:4000/hook',
        status: 200,
        statusText: 'OK',
        durationMs: 40,
        success: true,
      };

      await store.addReplay(event.id, replay);

      const reloaded = await new FileEventStore(filePath).get(event.id);
      expect(reloaded?.replays.length).toBe(1);
      expect(reloaded?.replays[0]?.id).toBe('rpl_persistent_1');
    });

    it('handles empty or missing file gracefully', async () => {
      const filePath = path.join(tempDir, 'non-existent.json');
      const store = new FileEventStore(filePath);

      expect(await store.count()).toBe(0);
      expect(await store.list()).toEqual([]);
      expect(await store.get('any')).toBeNull();
    });

    it('backs up corrupted JSON file to events.json.corrupted.<timestamp> and recovers gracefully', async () => {
      const filePath = path.join(tempDir, 'events.json');
      const corruptData = '{ "invalid_json": true, incomplete...';
      await fs.writeFile(filePath, corruptData, 'utf8');

      const store = new FileEventStore(filePath);
      const list = await store.list();
      expect(list).toEqual([]);

      // Check that a corrupted backup file was created
      const dirFiles = await fs.readdir(tempDir);
      const corruptedBackup = dirFiles.find((f) =>
        f.startsWith('events.json.corrupted.'),
      );
      expect(corruptedBackup).toBeDefined();

      const backupContent = await fs.readFile(
        path.join(tempDir, corruptedBackup!),
        'utf8',
      );
      expect(backupContent).toBe(corruptData);

      // Subsequent saves work cleanly
      const newEvent = createMockEvent('evt_new');
      await store.save(newEvent);
      expect(await store.count()).toBe(1);
    });

    it('enforces restrictive file and directory permissions (0o600 / 0o700)', async () => {
      const nestedDir = path.join(tempDir, 'secure-store');
      const filePath = path.join(nestedDir, 'events.json');
      const store = new FileEventStore(filePath);

      await store.save(createMockEvent());

      const dirStat = await fs.stat(nestedDir);
      // Check POSIX directory permissions (0o700)
      if (process.platform !== 'win32') {
        expect(dirStat.mode & 0o777).toBe(0o700);

        const fileStat = await fs.stat(filePath);
        // Check POSIX file permissions (0o600)
        expect(fileStat.mode & 0o777).toBe(0o600);
      }
    });
  });
});
