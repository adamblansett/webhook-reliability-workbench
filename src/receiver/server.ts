import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import type { ReceiverOptions, ReceiverServerInfo } from './types.js';
import type { EventStore, WebhookEvent } from '../events/types.js';
import { createDefaultStore, generateEventId } from '../events/store.js';
import { isLoopbackIp } from '../security/ssrf.js';
import { LIMITS } from '../security/limits.js';
import { verifySignature } from '../signatures/verifier.js';
import { getProviderPreset } from '../signatures/presets.js';
import { redactEventForDisplay } from '../security/redaction.js';
import { replayWebhookEvent } from '../replay/engine.js';
import { renderInspectorHtml } from './ui.js';
import { evaluateChaos } from '../chaos/chaosSimulator.js';
import { validateJsonSchema, loadSchemaFromFile } from '../schema/validator.js';
import { startTunnel, type TunnelInstance } from '../tunnel/manager.js';
import { TerminalDashboard } from '../tui/dashboard.js';

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
  const sseClients = new Set<http.ServerResponse>();
  let activeSchema: Record<string, unknown> | null = options.schema ?? null;
  let tunnelInstance: TunnelInstance | null = null;
  let tuiDashboard: TerminalDashboard | null = null;

  // Preset configuration
  const preset = options.preset ? getProviderPreset(options.preset) : undefined;
  const signatureHeader =
    options.signatureHeader ?? preset?.signatureHeader ?? 'x-hub-signature-256';
  const signaturePrefix = options.signaturePrefix ?? preset?.signaturePrefix;
  const algorithm = options.algorithm ?? preset?.algorithm ?? 'sha256';
  const encoding = preset?.encoding ?? 'hex';
  const toleranceSeconds = preset?.toleranceSeconds;

  const sessionToken = crypto.randomBytes(24).toString('hex');

  const server = http.createServer(async (req, res) => {
    const startTime = Date.now();
    const reqUrl = new URL(req.url ?? '/', `http://${host}:${port}`);

    // Host Header Validation / DNS Rebinding Protection
    if (!allowExternal) {
      const rawHostHeader = req.headers.host;
      if (rawHostHeader) {
        const hostWithoutPort = rawHostHeader.startsWith('[')
          ? rawHostHeader.slice(1, rawHostHeader.indexOf(']'))
          : rawHostHeader.split(':')[0]!.toLowerCase();

        let tunnelHost: string | null = null;
        if (tunnelInstance?.url) {
          try {
            tunnelHost = new URL(tunnelInstance.url).hostname.toLowerCase();
          } catch {
            // Ignore invalid tunnel URL
          }
        }

        const isAllowedHost =
          hostWithoutPort === 'localhost' ||
          hostWithoutPort === '127.0.0.1' ||
          hostWithoutPort === '::1' ||
          hostWithoutPort === host.toLowerCase() ||
          (tunnelHost !== null && hostWithoutPort === tunnelHost);

        if (!isAllowedHost) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: 'Bad Request',
              message: `Untrusted Host header "${rawHostHeader}". DNS rebinding protection rejected this request.`,
            }),
          );
          return;
        }
      }
    }

    // Health check endpoint
    if (req.method === 'GET' && reqUrl.pathname === '/__workbench/health') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end(
        JSON.stringify({
          status: 'healthy',
          pid: process.pid,
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    // Server-Sent Events stream endpoint for live monitoring
    if (req.method === 'GET' && reqUrl.pathname === '/__workbench/stream') {
      if (req.headers['sec-fetch-site'] === 'cross-site') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Cross-site SSE requests are forbidden' }));
        return;
      }

      const origin = req.headers['origin'];
      if (origin) {
        try {
          const originHost = new URL(origin).hostname.toLowerCase();
          const isAllowedOrigin =
            isLoopbackIp(originHost) ||
            originHost === 'localhost' ||
            originHost === host.toLowerCase();
          if (!isAllowedOrigin && !allowExternal) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                error: 'Cross-origin access from external web origin is forbidden',
              }),
            );
            return;
          }
        } catch {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid Origin header' }));
          return;
        }
      }

      const clientToken =
        reqUrl.searchParams.get('token') || req.headers['x-workbench-token'];
      if (clientToken && clientToken !== sessionToken) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Forbidden: Invalid workbench session token' }));
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Content-Type-Options': 'nosniff',
      });
      res.write(': connected\n\n');
      sseClients.add(res);

      req.on('close', () => {
        sseClients.delete(res);
      });
      return;
    }

    // Embedded Web Inspector UI
    if (req.method === 'GET' && reqUrl.pathname === '/__workbench/ui') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy':
          "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none';",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      });
      res.end(renderInspectorHtml({ sessionToken }));
      return;
    }

    // Replay endpoint for UI or programmatic triggers
    if (req.method === 'POST' && reqUrl.pathname === '/__workbench/replay') {
      if (req.headers['sec-fetch-site'] === 'cross-site') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Cross-site replay requests are forbidden' }));
        return;
      }

      const origin = req.headers['origin'];
      if (origin) {
        try {
          const originHost = new URL(origin).hostname.toLowerCase();
          const isAllowedOrigin =
            isLoopbackIp(originHost) ||
            originHost === 'localhost' ||
            originHost === host.toLowerCase();
          if (!isAllowedOrigin && !allowExternal) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                error: 'Cross-origin access from external web origin is forbidden',
              }),
            );
            return;
          }
        } catch {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid Origin header' }));
          return;
        }
      }

      let bodyText = '';
      req.on('data', (c) => (bodyText += c.toString('utf8')));
      req.on('end', async () => {
        try {
          const payload = JSON.parse(bodyText);
          const reqToken = req.headers['x-workbench-token'] || payload.token;
          if (reqToken && reqToken !== sessionToken) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Forbidden: Invalid workbench token' }));
            return;
          }

          const event = await store.get(payload.eventId);
          if (!event) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Event not found' }));
            return;
          }
          const replayRes = await replayWebhookEvent(
            event,
            {
              url: payload.destination,
              allowLoopback: payload.allowLoopback ?? true,
              allowPrivate: payload.allowPrivate ?? false,
              keepAuth: payload.keepAuth ?? true,
              keepSignatures: payload.keepSignatures ?? true,
            },
            store,
          );
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(replayRes));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({ error: err instanceof Error ? err.message : String(err) }),
          );
        }
      });
      return;
    }

    // Path filtering: if a specific path was configured (and isn't root '/'), reject other paths
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
      const sigValue = req.headers[signatureHeader.toLowerCase()];
      const timestampHeaderName = preset?.timestampHeader;
      const explicitTimestamp = timestampHeaderName
        ? (req.headers[timestampHeaderName.toLowerCase()] as string | undefined)
        : undefined;
      const idHeaderName = preset?.idHeader;
      const explicitId = idHeaderName
        ? (req.headers[idHeaderName.toLowerCase()] as string | undefined)
        : undefined;

      signatureResult = verifySignature(
        rawBuffer,
        {
          secret: options.secret,
          headerName: signatureHeader,
          algorithm,
          prefix: signaturePrefix,
          encoding,
          toleranceSeconds,
          timestamp: explicitTimestamp,
          messageId: explicitId,
        },
        sigValue,
      );
    }

    // Evaluate Chaos simulation
    const chaos = evaluateChaos({
      enabled: options.chaos,
      failureRate: options.chaosFailureRate,
      latencyP95Ms: options.chaosLatencyP95Ms,
      dropRate: options.chaosDropRate,
    });

    if (chaos.shouldDrop) {
      req.destroy();
      return;
    }

    const effectiveResponseStatus = chaos.injectedStatus ?? responseStatus;
    const effectiveDelayMs = delayMs + (chaos.injectedDelayMs ?? 0);

    // Delay simulation
    if (effectiveDelayMs > 0) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, effectiveDelayMs);
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

    // Schema Validation if schema configured
    let schemaValidationResult = null;
    if (activeSchema && parsedBody) {
      const valRes = validateJsonSchema(parsedBody, activeSchema);
      schemaValidationResult = {
        valid: valRes.valid,
        errors: valRes.errors,
        schemaPath: options.schemaPath,
      };
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
      responseStatus: effectiveResponseStatus,
      durationMs,
      signature: signatureResult,
      replays: [],
      schemaValidation: schemaValidationResult,
      chaosInjected: chaos.applyChaos
        ? {
            dropped: chaos.shouldDrop,
            injectedStatus: chaos.injectedStatus,
            injectedDelayMs: chaos.injectedDelayMs,
            reason: chaos.reason,
          }
        : null,
    };

    try {
      await store.save(event);
      tuiDashboard?.onNewEvent(event);
    } catch (saveErr) {
      if (!options.silent) {
        process.stderr.write(
          `[Workbench] Warning: Failed to persist event: ${String(saveErr)}\n`,
        );
      }
    }

    // Broadcast captured event to SSE stream subscribers
    if (sseClients.size > 0) {
      const ssePayload = JSON.stringify(redactEventForDisplay(event));
      for (const client of sseClients) {
        try {
          client.write(`data: ${ssePayload}\n\n`);
        } catch {
          sseClients.delete(client);
        }
      }
    }

    // Transparent proxy forwarding if configured
    if (options.forwardTo) {
      try {
        const forwardResult = await replayWebhookEvent(
          event,
          {
            url: options.forwardTo,
            allowLoopback: options.forwardAllowLoopback ?? true,
            allowPrivate: options.forwardAllowPrivate ?? false,
            keepAuth: true,
            keepSignatures: true,
            timeoutMs: 10000,
          },
          store,
        );
        event.forwardResult = {
          id: forwardResult.id,
          timestamp: forwardResult.timestamp,
          destination: forwardResult.destination,
          status: forwardResult.status,
          statusText: forwardResult.statusText,
          durationMs: forwardResult.durationMs,
          success: forwardResult.success,
          error: forwardResult.error,
          responseHeaders: forwardResult.responseHeaders,
          responseBodyPreview: forwardResult.responseBodyPreview,
        };
        await store.save(event);

        if (!options.silent) {
          process.stdout.write(
            `  ↳ [Forwarded] -> ${options.forwardTo} [${forwardResult.status} ${forwardResult.statusText}] (${forwardResult.durationMs}ms)\n`,
          );
        }
      } catch (fwdErr) {
        if (!options.silent) {
          process.stderr.write(
            `  ↳ [Forward Error] Failed to forward to ${options.forwardTo}: ${fwdErr instanceof Error ? fwdErr.message : String(fwdErr)}\n`,
          );
        }
      }
    }

    // Send HTTP response
    const finalHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Workbench-Event-Id': eventId,
      ...customHeaders,
    };

    res.writeHead(effectiveResponseStatus, finalHeaders);

    const defaultResponseBody = JSON.stringify({
      status: 'received',
      eventId,
      timestamp: event.timestamp,
    });

    res.end(responseBody ?? defaultResponseBody);

    if (!options.silent) {
      const statusColor = effectiveResponseStatus >= 400 ? '!' : '✓';
      const sigNotice = signatureResult
        ? ` (Signature: ${signatureResult.valid ? 'VALID' : 'INVALID'})`
        : '';
      const schemaNotice = schemaValidationResult
        ? ` [Schema: ${schemaValidationResult.valid ? 'VALID' : 'INVALID'}]`
        : '';
      process.stdout.write(
        `[Workbench] ${statusColor} ${req.method} ${reqUrl.pathname} -> ${effectiveResponseStatus} (${durationMs}ms) [ID: ${eventId}]${sigNotice}${schemaNotice}\n`,
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
          sessionToken,
        };

        // Load schema from file if configured
        if (options.schemaPath && !activeSchema) {
          try {
            activeSchema = await loadSchemaFromFile(options.schemaPath);
            if (!options.silent) {
              process.stdout.write(
                `[Workbench] Loaded schema contract from "${options.schemaPath}"\n`,
              );
            }
          } catch (err: unknown) {
            if (!options.silent) {
              process.stderr.write(
                `[Workbench Warning] Could not load schema: ${err instanceof Error ? err.message : String(err)}\n`,
              );
            }
          }
        }

        // Establish ephemeral ingress tunnel if configured
        if (options.tunnel) {
          try {
            tunnelInstance = await startTunnel({
              port: actualPort,
              provider: options.tunnelProvider ?? 'auto',
            });
            serverInfo.tunnelUrl = tunnelInstance.url;
            if (!options.silent) {
              process.stdout.write(
                `[Workbench Ingress] Public tunnel URL: ${tunnelInstance.url}\n`,
              );
            }
          } catch (tunnelErr: unknown) {
            if (!options.silent) {
              process.stderr.write(
                `[Workbench Ingress Warning] Failed to establish tunnel: ${tunnelErr instanceof Error ? tunnelErr.message : String(tunnelErr)}\n`,
              );
            }
          }
        }

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
          if (serverInfo.tunnelUrl) {
            process.stdout.write(
              `[Workbench Ingress] Forwarding public traffic from: ${serverInfo.tunnelUrl}\n`,
            );
          }
          process.stdout.write(
            `[Workbench] Ready to capture incoming webhooks (PID: ${process.pid})\n`,
          );
        }

        // Launch Terminal UI if requested
        if (options.tui) {
          tuiDashboard = new TerminalDashboard({
            port: actualPort,
            host,
            path: webhookPath,
            tunnelUrl: serverInfo.tunnelUrl,
            forwardUrl: options.forwardTo,
            store,
          });
          await tuiDashboard.start();
        }

        resolve(serverInfo);
      });
    });
  };

  const stop = async (): Promise<void> => {
    if (isShuttingDown) return;
    isShuttingDown = true;

    if (tuiDashboard) {
      tuiDashboard.stop();
      tuiDashboard = null;
    }

    if (tunnelInstance) {
      try {
        await tunnelInstance.stop();
      } catch {
        // Ignore
      }
      tunnelInstance = null;
    }

    for (const client of sseClients) {
      try {
        client.end();
      } catch {
        // Ignore
      }
    }
    sseClients.clear();

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
