import { Command } from 'commander';
import { createDefaultStore } from '../../events/store.js';
import { testWebhookRetries } from '../../retries/tester.js';
import { formatRetrySummary, formatJson } from '../../output/formatter.js';
import { ExitCode } from '../../config/exit-codes.js';
import { SsrSecurityError } from '../../security/ssrf.js';

export function createTestRetriesCommand(): Command {
  const cmd = new Command('test-retries');

  cmd
    .description(
      'Test delivery retries and duplicate handling by replaying an event multiple times',
    )
    .argument('<eventId>', 'ID of the captured event to test retries with')
    .requiredOption('-u, --url <destinationUrl>', 'Destination endpoint URL')
    .option(
      '-n, --attempts <number>',
      'Number of delivery attempts (1-20)',
      (v) => parseInt(v, 10),
      3,
    )
    .option(
      '-d, --delay <ms>',
      'Delay between attempts in milliseconds',
      (v) => parseInt(v, 10),
      1000,
    )
    .option(
      '--exponential-backoff',
      'Apply exponential backoff multiplier between attempts',
      false,
    )
    .option(
      '--max-backoff <ms>',
      'Maximum backoff delay ceiling in milliseconds',
      (v) => parseInt(v, 10),
      30000,
    )
    .option(
      '--allow-loopback',
      'Explicitly permit loopback destinations (127.0.0.1, localhost)',
      false,
    )
    .option('--allow-private', 'Explicitly permit private network destinations', false)
    .option(
      '--timeout <ms>',
      'Per-request timeout in milliseconds',
      (v) => parseInt(v, 10),
      5000,
    )
    .option('--store <filePath>', 'Path to file-backed event store')
    .option('--json', 'Output machine-readable JSON format')
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

        const summary = await testWebhookRetries(
          event,
          {
            url: opts.url,
            attempts: opts.attempts,
            delayMs: opts.delay,
            exponentialBackoff: opts.exponentialBackoff,
            maxBackoffMs: opts.maxBackoff,
            allowLoopback: opts.allowLoopback,
            allowPrivate: opts.allowPrivate,
            timeoutMs: opts.timeout,
          },
          store,
        );

        if (opts.json) {
          process.stdout.write(formatJson(summary) + '\n');
        } else {
          process.stdout.write(formatRetrySummary(summary) + '\n');
        }

        if (summary.failedAttempts > 0) {
          process.exit(ExitCode.REPLAY_FAILED);
        }
      } catch (err) {
        if (err instanceof SsrSecurityError) {
          process.stderr.write(`[Workbench SECURITY ERROR] ${err.message}\n`);
          process.exit(ExitCode.SECURITY_ERROR);
        }

        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  return cmd;
}
