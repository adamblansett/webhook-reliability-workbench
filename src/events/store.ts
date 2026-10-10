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

export function createDefaultStore(options?: {
  type?: 'memory' | 'file';
  filePath?: string;
  maxEvents?: number;
}): EventStore {
  if (options?.type === 'memory') {
    return new InMemoryEventStore(options.maxEvents);
  }
  return new FileEventStore(options?.filePath, options?.maxEvents);
}
