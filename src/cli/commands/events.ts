import { Command } from 'commander';
import http from 'node:http';
import { createDefaultStore } from '../../events/store.js';
import {
  formatEventList,
  formatEventDetail,
  formatJson,
} from '../../output/formatter.js';
import { diffEvents } from '../../output/diff.js';
import { ExitCode } from '../../config/exit-codes.js';
import { redactEventForDisplay } from '../../security/redaction.js';

export function createEventsCommand(): Command {
  const eventsCmd = new Command('events');
  eventsCmd.description('Inspect captured webhook events');

  eventsCmd
    .command('list')
    .description('List captured webhook events')
    .option(
      '-l, --limit <number>',
      'Maximum number of events to list',
      (v) => parseInt(v, 10),
      20,
    )
    .option('--json', 'Output machine-readable JSON format')
    .option('--store <filePath>', 'Path to file-backed event store')
    .action(async (opts) => {
      const store = createDefaultStore({
        type: 'file',
        filePath: opts.store,
      });

      try {
        const events = await store.list({ limit: opts.limit });
        if (opts.json) {
          const redacted = events.map((e) => redactEventForDisplay(e));
          process.stdout.write(formatJson(redacted) + '\n');
        } else {
          process.stdout.write(formatEventList(events) + '\n');
        }
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  eventsCmd
    .command('show <eventId>')
    .description('Show detailed inspection of a specific captured event')
    .option('--raw', 'Show raw body without redaction or JSON pretty printing')
    .option('--json', 'Output machine-readable JSON format')
    .option('--store <filePath>', 'Path to file-backed event store')
    .action(async (eventId: string, opts) => {
      const store = createDefaultStore({
        type: 'file',
        filePath: opts.store,
      });

      try {
        const event = await store.get(eventId);
        if (!event) {
          process.stderr.write(
            `[Workbench ERROR] Event "${eventId}" not found in store.\n`,
          );
          process.exit(ExitCode.NOT_FOUND);
        }

        if (opts.json) {
          const outputData = opts.raw ? event : redactEventForDisplay(event);
          process.stdout.write(formatJson(outputData) + '\n');
        } else {
          process.stdout.write(formatEventDetail(event, opts.raw) + '\n');
        }
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  eventsCmd
    .command('clear')
    .description('Clear all stored webhook events')
    .option('--store <filePath>', 'Path to file-backed event store')
    .option('--json', 'Output machine-readable JSON format')
    .action(async (opts) => {
      const store = createDefaultStore({
        type: 'file',
        filePath: opts.store,
      });

      try {
        await store.clear();
        if (opts.json) {
          process.stdout.write(formatJson({ cleared: true }) + '\n');
        } else {
          process.stdout.write('Cleared all webhook events from store.\n');
        }
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  eventsCmd
    .command('diff <eventIdA> <eventIdB>')
    .description('Compare headers and payloads between two captured webhook events')
    .option('--store <filePath>', 'Path to file-backed event store')
    .action(async (idA: string, idB: string, opts) => {
      const store = createDefaultStore({
        type: 'file',
        filePath: opts.store,
      });

      try {
        const eventA = await store.get(idA);
        if (!eventA) {
          process.stderr.write(`[Workbench ERROR] Event "${idA}" not found in store.\n`);
          process.exit(ExitCode.NOT_FOUND);
        }
        const eventB = await store.get(idB);
        if (!eventB) {
          process.stderr.write(`[Workbench ERROR] Event "${idB}" not found in store.\n`);
          process.exit(ExitCode.NOT_FOUND);
        }

        process.stdout.write(diffEvents(eventA, eventB));
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  eventsCmd
    .command('tail')
    .description('Stream incoming captured webhook events in real-time from receiver')
    .option(
      '--url <streamUrl>',
      'Receiver SSE stream URL',
      'http://127.0.0.1:8787/__workbench/stream',
    )
    .option('--json', 'Output incoming events as raw JSON lines', false)
    .action((opts) => {
      const streamUrl = new URL(opts.url);
      process.stdout.write(
        `[Workbench] Connecting to live webhook stream at ${streamUrl.href}...\n`,
      );

      const req = http.request(
        streamUrl,
        {
          headers: { Accept: 'text/event-stream' },
        },
        (res) => {
          if (res.statusCode !== 200) {
            process.stderr.write(
              `[Workbench ERROR] Stream endpoint returned HTTP ${res.statusCode}.\nIs the receiver running?\n`,
            );
            process.exit(ExitCode.RECEIVER_ERROR);
          }

          process.stdout.write(
            `[Workbench] Live stream active. Waiting for events (Ctrl+C to stop)...\n`,
          );

          let buffer = '';
          res.on('data', (chunk: Buffer) => {
            buffer += chunk.toString('utf8');
            const lines = buffer.split('\n\n');
            buffer = lines.pop() ?? '';

            for (const block of lines) {
              for (const line of block.split('\n')) {
                if (line.startsWith('data: ')) {
                  const dataStr = line.slice(6);
                  if (opts.json) {
                    process.stdout.write(dataStr + '\n');
                  } else {
                    try {
                      const evt = JSON.parse(dataStr);
                      const sigNotice = evt.signature
                        ? evt.signature.valid
                          ? ' [HMAC: VALID]'
                          : ' [HMAC: INVALID]'
                        : '';
                      process.stdout.write(
                        `[${evt.timestamp}] ${evt.method} ${evt.path} -> ${evt.responseStatus} (${evt.durationMs}ms) [ID: ${evt.id}]${sigNotice}\n`,
                      );
                    } catch {
                      process.stdout.write(dataStr + '\n');
                    }
                  }
                }
              }
            }
          });
        },
      );

      req.on('error', (err) => {
        process.stderr.write(
          `[Workbench ERROR] Connection failed: ${err.message}. Is "webhook-workbench listen" running?\n`,
        );
        process.exit(ExitCode.RECEIVER_ERROR);
      });

      req.end();
    });

  return eventsCmd;
}
