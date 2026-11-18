import { Command } from 'commander';
import http from 'node:http';
import fs from 'node:fs/promises';
import pc from 'picocolors';
import { createDefaultStore } from '../../events/store.js';
import {
  formatEventList,
  formatEventDetail,
  formatJson,
} from '../../output/formatter.js';
import { diffEvents } from '../../output/diff.js';
import { ExitCode } from '../../config/exit-codes.js';
import { redactEventForDisplay } from '../../security/redaction.js';
import { generateCurlCommand } from '../../codegen/curlGenerator.js';
import {
  generateTypeScriptTypes,
  generateZodSchema,
} from '../../codegen/typeGenerator.js';
import { validateJsonSchema, loadSchemaFromFile } from '../../schema/validator.js';

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

  eventsCmd
    .command('curl <eventId>')
    .description(
      'Generate ready-to-run executable cURL command line for a captured event',
    )
    .option('--url <destinationUrl>', 'Override target URL in generated curl command')
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

        const curl = generateCurlCommand(event, { overrideUrl: opts.url });
        process.stdout.write(curl + '\n');
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  eventsCmd
    .command('types <eventId>')
    .description(
      'Infer and generate TypeScript interfaces or Zod schemas from captured JSON payload',
    )
    .option(
      '--format <format>',
      'Output format: "ts" for TypeScript or "zod" for Zod schema',
      'ts',
    )
    .option('--name <typeName>', 'Root interface or schema name', 'WebhookPayload')
    .option('-o, --output <filePath>', 'Write generated types to file instead of stdout')
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

        const dataToInfer =
          event.body ?? (event.rawBody ? JSON.parse(event.rawBody) : null);
        if (!dataToInfer || typeof dataToInfer !== 'object') {
          process.stderr.write(
            `[Workbench ERROR] Event "${eventId}" does not contain a JSON body.\n`,
          );
          process.exit(ExitCode.INVALID_ARGUMENT);
        }

        const generatedCode =
          opts.format === 'zod'
            ? generateZodSchema(dataToInfer, opts.name)
            : generateTypeScriptTypes(dataToInfer, opts.name);

        if (opts.output) {
          await fs.writeFile(opts.output, generatedCode + '\n', 'utf8');
          process.stdout.write(
            pc.green(
              `✓ Generated ${opts.format.toUpperCase()} definitions written to ${opts.output}\n`,
            ),
          );
        } else {
          process.stdout.write(generatedCode + '\n');
        }
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  eventsCmd
    .command('validate <eventId>')
    .description('Validate a captured event payload against a JSON Schema file')
    .requiredOption('--schema <schemaPath>', 'Path to JSON Schema file')
    .option('--store <filePath>', 'Path to file-backed event store')
    .option('--json', 'Output validation result as machine-readable JSON', false)
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

        const schema = await loadSchemaFromFile(opts.schema);
        const dataToValidate =
          event.body ?? (event.rawBody ? JSON.parse(event.rawBody) : null);
        const res = validateJsonSchema(dataToValidate, schema);

        if (opts.json) {
          process.stdout.write(JSON.stringify(res, null, 2) + '\n');
          process.exit(res.valid ? ExitCode.SUCCESS : ExitCode.VALIDATION_ERROR);
        }

        if (res.valid) {
          process.stdout.write(
            pc.green(`✓ Event "${eventId}" conforms to schema "${opts.schema}"\n`),
          );
          process.exit(ExitCode.SUCCESS);
        } else {
          process.stderr.write(
            pc.red(
              `✗ Event "${eventId}" failed schema validation against "${opts.schema}":\n`,
            ),
          );
          for (const err of res.errors) {
            process.stderr.write(pc.red(`  • ${err}\n`));
          }
          process.exit(ExitCode.VALIDATION_ERROR);
        }
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  return eventsCmd;
}
