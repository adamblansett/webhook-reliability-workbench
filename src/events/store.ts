import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { EventStore, WebhookEvent, ReplayRecord } from './types.js';
import { LIMITS } from '../security/limits.js';

/**
 * Generates a collision-resistant unique event ID.
 */
export function generateEventId(): string {
  const timestamp = Date.now().toString(36);
  const randomPart = crypto.randomBytes(4).toString('hex');
  return `evt_${timestamp}_${randomPart}`;
}

/**
 * In-memory implementation of EventStore.
 * Non-persistent across process restarts; ideal for unit tests and ephemeral runs.
 */
export class InMemoryEventStore implements EventStore {
  private events: WebhookEvent[] = [];
  private readonly maxEvents: number;

  constructor(maxEvents: number = LIMITS.DEFAULT_STORE_MAX_EVENTS) {
    this.maxEvents = Math.min(Math.max(1, maxEvents), LIMITS.MAX_STORE_CAPACITY);
  }

  async save(event: WebhookEvent): Promise<void> {
    const existingIndex = this.events.findIndex((e) => e.id === event.id);
    if (existingIndex >= 0) {
      this.events[existingIndex] = event;
    } else {
      this.events.unshift(event);
      if (this.events.length > this.maxEvents) {
        this.events.length = this.maxEvents;
      }
    }
  }

  async get(id: string): Promise<WebhookEvent | null> {
    const found = this.events.find((e) => e.id === id);
    return found ? structuredClone(found) : null;
  }

  async list(options: { limit?: number; offset?: number } = {}): Promise<WebhookEvent[]> {
    const offset = Math.max(0, options.offset ?? 0);
    const limit = Math.max(1, options.limit ?? this.events.length);
    const slice = this.events.slice(offset, offset + limit);
    return structuredClone(slice);
  }

  async addReplay(eventId: string, replay: ReplayRecord): Promise<boolean> {
    const event = this.events.find((e) => e.id === eventId);
    if (!event) return false;
    event.replays.unshift(replay);
    return true;
  }

  async clear(): Promise<void> {
    this.events = [];
  }

  async count(): Promise<number> {
    return this.events.length;
  }
}

/**
 * File-backed implementation of EventStore.
 * Safely persists events to a JSON file using atomic writes and bounded capacity.
 * Enables sharing events between a background receiver and CLI commands.
 */
export class FileEventStore implements EventStore {
  private readonly filePath: string;
  private readonly maxEvents: number;

  constructor(
    filePath: string = path.join(process.cwd(), '.workbench', 'events.json'),
    maxEvents: number = LIMITS.DEFAULT_STORE_MAX_EVENTS,
  ) {
    this.filePath = path.resolve(filePath);
    this.maxEvents = Math.min(Math.max(1, maxEvents), LIMITS.MAX_STORE_CAPACITY);
  }

  private async loadEvents(): Promise<WebhookEvent[]> {
    let data: string;
    try {
      data = await fs.readFile(this.filePath, 'utf8');
    } catch (err: unknown) {
      if (
        err &&
        typeof err === 'object' &&
        'code' in err &&
        (err as { code: string }).code === 'ENOENT'
      ) {
        return [];
      }
      throw err;
    }

    try {
      const parsed = JSON.parse(data);
      if (Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // File exists but contains corrupted JSON: back it up to prevent permanent data loss
      try {
        const backupPath = `${this.filePath}.corrupted.${Date.now()}`;
        await fs.rename(this.filePath, backupPath);
        process.stderr.write(
          `[Workbench Warning] Corrupted store file detected at "${this.filePath}". Backed up to "${backupPath}".\n`,
        );
      } catch {
        // Ignore backup failure
      }
      return [];
    }
    return [];
  }

  private async persistEvents(events: WebhookEvent[]): Promise<void> {
    const dir = path.dirname(this.filePath);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    await fs.chmod(dir, 0o700).catch(() => {});

    const tmpFile = `${this.filePath}.tmp.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`;
    const serialized = JSON.stringify(events, null, 2);

    await fs.writeFile(tmpFile, serialized, { encoding: 'utf8', mode: 0o600 });
    await fs.rename(tmpFile, this.filePath);
    await fs.chmod(this.filePath, 0o600).catch(() => {});
  }

  async save(event: WebhookEvent): Promise<void> {
    const events = await this.loadEvents();
    const existingIndex = events.findIndex((e) => e.id === event.id);

    if (existingIndex >= 0) {
      events[existingIndex] = event;
    } else {
      events.unshift(event);
      if (events.length > this.maxEvents) {
        events.length = this.maxEvents;
      }
    }

    await this.persistEvents(events);
  }

  async get(id: string): Promise<WebhookEvent | null> {
    const events = await this.loadEvents();
    const found = events.find((e) => e.id === id);
    return found ? structuredClone(found) : null;
  }

  async list(options: { limit?: number; offset?: number } = {}): Promise<WebhookEvent[]> {
    const events = await this.loadEvents();
    const offset = Math.max(0, options.offset ?? 0);
    const limit = Math.max(1, options.limit ?? events.length);
    const slice = events.slice(offset, offset + limit);
    return structuredClone(slice);
  }

  async addReplay(eventId: string, replay: ReplayRecord): Promise<boolean> {
    const events = await this.loadEvents();
    const event = events.find((e) => e.id === eventId);
    if (!event) return false;
    event.replays.unshift(replay);
    await this.persistEvents(events);
    return true;
  }

  async clear(): Promise<void> {
    await this.persistEvents([]);
  }

  async count(): Promise<number> {
    const events = await this.loadEvents();
    return events.length;
  }
}

interface SqliteDatabase {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...params: unknown[]): void;
    all(...params: unknown[]): Array<Record<string, unknown>>;
    get(...params: unknown[]): Record<string, unknown> | undefined;
  };
  close(): void;
}

/**
 * SQLite-backed implementation of EventStore.
 * Provides high-throughput atomic writes, zero file rewrite lock contention,
 * and indexed queries.
 */
export class SqliteEventStore implements EventStore {
  private db: SqliteDatabase | null = null;
  private readonly filePath: string;
  private readonly maxEvents: number;

  constructor(filePath?: string, maxEvents: number = LIMITS.DEFAULT_STORE_MAX_EVENTS) {
    this.filePath = filePath ?? path.join(process.cwd(), '.workbench', 'events.sqlite');
    this.maxEvents = Math.min(Math.max(1, maxEvents), LIMITS.MAX_STORE_CAPACITY);
  }

  private async getDb(): Promise<SqliteDatabase> {
    if (this.db) return this.db;

    const dir = path.dirname(this.filePath);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });

    let sqliteModule: { DatabaseSync: new (path: string) => SqliteDatabase };
    try {
      sqliteModule = (await import('node:sqlite' as string)) as typeof sqliteModule;
    } catch {
      throw new Error(
        `SQLite store requires the built-in node:sqlite module (Node.js >= 22.5). Current runtime: ${process.version}. Use the file or memory store instead.`,
      );
    }

    try {
      const db = new sqliteModule.DatabaseSync(this.filePath);

      db.exec(`
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY,
          timestamp TEXT NOT NULL,
          method TEXT NOT NULL,
          path TEXT NOT NULL,
          data TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);
      `);

      this.db = db;
      return db;
    } catch (err) {
      throw new Error(
        `Failed to initialize SQLite store: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  async save(event: WebhookEvent): Promise<void> {
    const db = await this.getDb();
    const dataStr = JSON.stringify(event);
    const createdAt = new Date(event.timestamp).getTime() || Date.now();

    const insertStmt = db.prepare(`
      INSERT INTO events (id, timestamp, method, path, data, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        timestamp = excluded.timestamp,
        method = excluded.method,
        path = excluded.path,
        data = excluded.data
    `);
    insertStmt.run(
      event.id,
      event.timestamp,
      event.method,
      event.path,
      dataStr,
      createdAt,
    );

    const pruneStmt = db.prepare(`
      DELETE FROM events WHERE rowid NOT IN (
        SELECT rowid FROM events ORDER BY rowid DESC LIMIT ?
      )
    `);
    pruneStmt.run(this.maxEvents);
  }

  async get(id: string): Promise<WebhookEvent | null> {
    const db = await this.getDb();
    const stmt = db.prepare('SELECT data FROM events WHERE id = ?');
    const row = stmt.get(id);
    if (!row || typeof row.data !== 'string') return null;
    try {
      return JSON.parse(row.data) as WebhookEvent;
    } catch {
      return null;
    }
  }

  async list(options: { limit?: number; offset?: number } = {}): Promise<WebhookEvent[]> {
    const db = await this.getDb();
    const limit = Math.max(1, options.limit ?? this.maxEvents);
    const offset = Math.max(0, options.offset ?? 0);

    const stmt = db.prepare(
      'SELECT data FROM events ORDER BY rowid DESC LIMIT ? OFFSET ?',
    );
    const rows = stmt.all(limit, offset);
    const results: WebhookEvent[] = [];
    for (const row of rows) {
      if (typeof row.data === 'string') {
        try {
          results.push(JSON.parse(row.data) as WebhookEvent);
        } catch {
          // Skip corrupt rows
        }
      }
    }
    return results;
  }

  async addReplay(eventId: string, replay: ReplayRecord): Promise<boolean> {
    const event = await this.get(eventId);
    if (!event) return false;
    event.replays.unshift(replay);
    await this.save(event);
    return true;
  }

  async clear(): Promise<void> {
    const db = await this.getDb();
    db.exec('DELETE FROM events');
  }

  async count(): Promise<number> {
    const db = await this.getDb();
    const stmt = db.prepare('SELECT COUNT(*) as count FROM events');
    const row = stmt.get() as { count: number } | undefined;
    return row?.count ?? 0;
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
}

export function createDefaultStore(options?: {
  type?: 'memory' | 'file' | 'sqlite';
  filePath?: string;
  maxEvents?: number;
}): EventStore {
  if (options?.type === 'memory') {
    return new InMemoryEventStore(options.maxEvents);
  }
  if (options?.type === 'sqlite') {
    return new SqliteEventStore(options.filePath, options.maxEvents);
  }
  return new FileEventStore(options?.filePath, options?.maxEvents);
}
