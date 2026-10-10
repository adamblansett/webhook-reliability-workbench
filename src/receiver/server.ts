import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { ReceiverOptions, ReceiverServerInfo } from './types.js';
import type { EventStore, WebhookEvent } from '../events/types.js';
import { createDefaultStore, generateEventId } from '../events/store.js';
import { isLoopbackIp } from '../security/ssrf.js';
import { LIMITS } from '../security/limits.js';
import { verifySignature } from '../signatures/verifier.js';

export class ReceiverSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReceiverSecurityError';
  }
}

export interface ReceiverInstance {
  server: http.Server;
  start(): Promise<ReceiverServerInfo>;
  stop(): Promise<void>;
  getInfo(): ReceiverServerInfo | null;
  store: EventStore;
}

/**
 * Creates and configures the local webhook receiver HTTP server.
 */
export function createReceiver(options: ReceiverOptions = {}): ReceiverInstance {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 8787;
  const webhookPath = options.path
    ? options.path.startsWith('/')
      ? options.path
      : `/${options.path}`
    : '/';
  const allowExternal = options.allowExternal ?? false;
  const maxBodySize = Math.min(
    Math.max(1024, options.maxBodySize ?? LIMITS.DEFAULT_MAX_BODY_SIZE_BYTES),
    LIMITS.MAX_ALLOWED_BODY_SIZE_BYTES,
  );
  const responseStatus = options.responseStatus ?? 200;
  const delayMs = Math.min(
    Math.max(0, options.delayMs ?? LIMITS.DEFAULT_DELAY_MS),
    LIMITS.MAX_DELAY_MS,
  );
  const responseBody = options.responseBody;
  const customHeaders = options.responseHeaders ?? {};

  // Verify host binding security
  const isLoopback = isLoopbackIp(host) || host === 'localhost';
  if (!isLoopback && !allowExternal) {
    throw new ReceiverSecurityError(
      `Binding to externally accessible interface "${host}" requires explicit --allow-external confirmation.`,
    );
  }

  const store = options.store ?? createDefaultStore();
  let serverInfo: ReceiverServerInfo | null = null;
  let isShuttingDown = false;

  const server = http.createServer(async (req, res) => {
    const startTime = Date.now();

    // Health check endpoint
    if (req.method === 'GET' && req.url === '/__workbench/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'healthy',
          pid: process.pid,
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    // Path filtering: if a specific path was configured (and isn't root '/'), reject other paths
    const reqUrl = new URL(req.url ?? '/', `http://${host}:${port}`);
    if (webhookPath !== '/' && reqUrl.pathname !== webhookPath) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Not Found',
          message: `Receiver is listening only on "${webhookPath}". Request was to "${reqUrl.pathname}".`,
        }),
      );
      return;
    }

    // Validate Content-Length upfront if present
    const contentLengthHeader = req.headers['content-length'];
    if (contentLengthHeader !== undefined) {
      const parsedLen = parseInt(contentLengthHeader, 10);
      if (isNaN(parsedLen) || parsedLen < 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Bad Request',
            message: 'Invalid Content-Length header',
          }),
        );
        return;
      }
      if (parsedLen > maxBodySize) {
        res.writeHead(413, {
          'Content-Type': 'application/json',
          Connection: 'close',
        });
        res.end(
          JSON.stringify({
            error: 'Payload Too Large',
            message: `Content-Length ${parsedLen} exceeds maximum allowed limit of ${maxBodySize} bytes.`,
            limitBytes: maxBodySize,
          }),
        );
        req.destroy();
        return;
      }
    }

    // Buffer request body with size limits
    const chunks: Buffer[] = [];
    let receivedBytes = 0;
    let bodyExceeded = false;

    try {
      await new Promise<void>((resolve, reject) => {
        let isDone = false;
        const cleanup = () => {
          req.removeListener('data', onData);
          req.removeListener('end', onEnd);
          req.removeListener('error', onError);
          req.removeListener('close', onClose);
        };

        const onData = (chunk: Buffer) => {
          receivedBytes += chunk.length;
          if (receivedBytes > maxBodySize) {
            bodyExceeded = true;
            req.pause();
            isDone = true;
            cleanup();
            resolve();
            return;
          }
          chunks.push(chunk);
        };

        const onEnd = () => {
          if (!isDone) {
            isDone = true;
            cleanup();
            resolve();
          }
        };

        const onError = (err: Error) => {
          if (!isDone) {
            isDone = true;
            cleanup();
            reject(err);
          }
        };

        const onClose = () => {
          if (!isDone && !req.readableEnded) {
            isDone = true;
            cleanup();
            reject(new Error('Client aborted connection before request finished'));
          }
        };

        req.on('data', onData);
        req.on('end', onEnd);
        req.on('error', onError);
        req.on('close', onClose);
      });
    } catch {
      if (!res.headersSent) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to read request body stream' }));
      }
      return;
    }

    if (bodyExceeded) {
      res.writeHead(413, {
        'Content-Type': 'application/json',
        Connection: 'close',
      });
      res.end(
        JSON.stringify({
          error: 'Payload Too Large',
          message: `Request body exceeded maximum allowed limit of ${maxBodySize} bytes.`,
          limitBytes: maxBodySize,
        }),
      );
      req.destroy();
      return;
    }

    const rawBuffer = Buffer.concat(chunks);
    const rawBody = rawBuffer.toString('utf8');
    const contentType = req.headers['content-type'] ?? null;

    // Parse JSON if applicable
    let parsedBody: unknown = null;
    let isJson = false;
    let jsonError: string | null = null;

    if (rawBody.trim().length > 0) {
      const isJsonContentType =
        contentType &&
        (contentType.includes('application/json') || contentType.includes('+json'));

      if (
        isJsonContentType ||
        rawBody.trim().startsWith('{') ||
        rawBody.trim().startsWith('[')
      ) {
        try {
          parsedBody = JSON.parse(rawBody);
          isJson = true;
        } catch (err) {
          isJson = false;
          jsonError = err instanceof Error ? err.message : 'Invalid JSON';
        }
      }
    }

    // Query parameters
    const queryParams: Record<string, string | string[]> = {};
    for (const [key, value] of reqUrl.searchParams.entries()) {
      const current = queryParams[key];
      if (current === undefined) {
        queryParams[key] = value;
      } else if (Array.isArray(current)) {
        current.push(value);
      } else {
        queryParams[key] = [current, value];
      }
    }

    // Request headers normalization
    const headers: Record<string, string | string[]> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (value !== undefined) {
        headers[key] = value;
      }
    }

    // Signature verification if secret configured
    let signatureResult = null;
    if (options.secret) {
      const sigHeaderName = options.signatureHeader ?? 'x-hub-signature-256';
      const sigValue = req.headers[sigHeaderName.toLowerCase()];
      signatureResult = verifySignature(
        rawBuffer,
        {
          secret: options.secret,
          headerName: sigHeaderName,
          algorithm: options.algorithm ?? 'sha256',
          prefix: options.signaturePrefix,
        },
        sigValue,
      );
    }

    // Delay simulation
    if (delayMs > 0) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, delayMs);
        req.on('close', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }

    // Check if client disconnected during delay or response closed
    if (res.writableEnded || res.destroyed) {
      return;
    }

    const durationMs = Date.now() - startTime;
    const eventId = generateEventId();

    const event: WebhookEvent = {
      id: eventId,
      timestamp: new Date().toISOString(),
      method: req.method ?? 'POST',
      path: reqUrl.pathname,
      headers,
      query: queryParams,
      rawBody,
      body: parsedBody,
      isJson,
      jsonError,
      contentType: typeof contentType === 'string' ? contentType : null,
      contentLength: rawBuffer.length,
      responseStatus,
      durationMs,
      signature: signatureResult,
      replays: [],
    };

    try {
      await store.save(event);
    } catch (saveErr) {
      if (!options.silent) {
        process.stderr.write(
          `[Workbench] Warning: Failed to persist event: ${String(saveErr)}\n`,
        );
      }
    }

    // Send HTTP response
    const finalHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Workbench-Event-Id': eventId,
      ...customHeaders,
    };

    res.writeHead(responseStatus, finalHeaders);

    const defaultResponseBody = JSON.stringify({
      status: 'received',
      eventId,
      timestamp: event.timestamp,
    });

    res.end(responseBody ?? defaultResponseBody);

    if (!options.silent) {
      const statusColor = responseStatus >= 400 ? '!' : '✓';
      const sigNotice = signatureResult
        ? ` (Signature: ${signatureResult.valid ? 'VALID' : 'INVALID'})`
        : '';
      process.stdout.write(
        `[Workbench] ${statusColor} ${req.method} ${reqUrl.pathname} -> ${responseStatus} (${durationMs}ms) [ID: ${eventId}]${sigNotice}\n`,
      );
    }
  });

  const stateFilePath = path.join(process.cwd(), '.workbench', 'receiver.json');

  const start = async (): Promise<ReceiverServerInfo> => {
    return new Promise((resolve, reject) => {
      server.once('error', reject);

      server.listen(port, host, async () => {
        server.removeListener('error', reject);
        const address = server.address();
        const actualPort = typeof address === 'object' && address ? address.port : port;

        serverInfo = {
          host,
          port: actualPort,
          url: `http://${host}:${actualPort}${webhookPath}`,
          path: webhookPath,
          pid: process.pid,
        };

        // Persist receiver state file for other CLI processes
        try {
          await fs.mkdir(path.dirname(stateFilePath), { recursive: true });
          await fs.writeFile(stateFilePath, JSON.stringify(serverInfo, null, 2), 'utf8');
        } catch {
          // Non-fatal if state file cannot be written
        }

        if (!options.silent) {
          if (!isLoopback) {
            process.stdout.write(
              `\n[Workbench SECURITY WARNING] Server bound to non-loopback interface ${host}. This receiver is externally accessible.\n`,
            );
          }
          process.stdout.write(
            `[Workbench] Receiver listening on http://${host}:${actualPort}${webhookPath}\n`,
          );
          process.stdout.write(
            `[Workbench] Ready to capture incoming webhooks (PID: ${process.pid})\n`,
          );
        }

        resolve(serverInfo);
      });
    });
  };

  const stop = async (): Promise<void> => {
    if (isShuttingDown) return;
    isShuttingDown = true;

    try {
      await fs.unlink(stateFilePath);
    } catch {
      // Ignore if state file already deleted
    }

    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }

    return new Promise((resolve, reject) => {
      server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  };

  return {
    server,
    start,
    stop,
    getInfo: () => serverInfo,
    store,
  };
}
