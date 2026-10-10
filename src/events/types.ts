import type { SignatureVerificationResult } from '../signatures/types.js';

export interface ReplayRecord {
  id: string;
  timestamp: string;
  destination: string;
  status: number;
  statusText: string;
  durationMs: number;
  success: boolean;
  error?: string;
  responseHeaders?: Record<string, string>;
  responseBodyPreview?: string;
}

export interface WebhookEvent {
  id: string;
  timestamp: string;
  method: string;
  path: string;
  headers: Record<string, string | string[]>;
  query: Record<string, string | string[]>;
  rawBody: string;
  body: unknown | null;
  isJson: boolean;
  jsonError: string | null;
  contentType: string | null;
  contentLength: number;
  responseStatus: number;
  durationMs: number;
  signature: SignatureVerificationResult | null;
  replays: ReplayRecord[];
}

export interface EventStore {
  save(event: WebhookEvent): Promise<void>;
  get(id: string): Promise<WebhookEvent | null>;
  list(options?: { limit?: number; offset?: number }): Promise<WebhookEvent[]>;
  addReplay(eventId: string, replay: ReplayRecord): Promise<boolean>;
  clear(): Promise<void>;
  count(): Promise<number>;
}
