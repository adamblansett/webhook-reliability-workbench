import { Command } from 'commander';
import { createDefaultStore } from '../../events/store.js';
import {
  formatEventList,
  formatEventDetail,
  formatJson,
} from '../../output/formatter.js';
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

  return eventsCmd;
}
