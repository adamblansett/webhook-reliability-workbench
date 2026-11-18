import { Command } from 'commander';
import pc from 'picocolors';
import { createDefaultStore } from '../../events/store.js';
import { runFuzzTesting } from '../../fuzz/fuzzer.js';
import { ExitCode } from '../../config/exit-codes.js';

export function createFuzzCommand(): Command {
  const cmd = new Command('fuzz');

  cmd
    .description(
      'Run payload mutation stress testing against a downstream webhook consumer endpoint',
    )
    .argument('<eventId>', 'Captured event ID to use as the base mutation template')
    .requiredOption('--url <targetUrl>', 'Target endpoint URL to fuzz test')
    .option(
      '--allow-loopback',
      'Allow targeting loopback addresses (127.0.0.1, localhost)',
      true,
    )
    .option('--allow-private', 'Allow targeting private network addresses', false)
    .option(
      '--timeout <ms>',
      'Timeout per mutation request in milliseconds',
      (v) => parseInt(v, 10),
      5000,
    )
    .option('--store <filePath>', 'Path to file-backed event store')
    .option('--json', 'Output fuzz report as machine-readable JSON', false)
    .action(async (eventId: string, opts) => {
      const store = createDefaultStore({
        type: 'file',
        filePath: opts.store,
      });

      try {
        const event = await store.get(eventId);
        if (!event) {
          process.stderr.write(
            `${pc.red('Error:')} Event "${eventId}" not found in store.\n`,
          );
          process.exit(ExitCode.NOT_FOUND);
        }

        process.stdout.write(
          pc.bold(`\nStarting Webhook Consumer Fuzz Testing against ${opts.url}...\n`),
        );
        process.stdout.write(
          pc.gray(
            '──────────────────────────────────────────────────────────────────────\n',
          ),
        );

        const report = await runFuzzTesting(opts.url, event, {
          allowLoopback: opts.allowLoopback,
          allowPrivate: opts.allowPrivate,
          timeoutMs: opts.timeout,
        });

        if (opts.json) {
          process.stdout.write(JSON.stringify(report, null, 2) + '\n');
          process.exit(
            report.crashedCount === 0 ? ExitCode.SUCCESS : ExitCode.GENERAL_ERROR,
          );
        }

        for (const res of report.results) {
          const statusBadge = res.handledSafely
            ? pc.green(`[SAFE ${res.status ?? 'ERR'}]`)
            : pc.red(`[CRASH ${res.status ?? 'FAIL'}]`);
          process.stdout.write(
            `${statusBadge} ${pc.bold(res.mutationName)} (${res.durationMs}ms)\n` +
              `  ↳ ${pc.gray(res.description)}\n`,
          );
          if (res.error) {
            process.stdout.write(`    ${pc.red(`Error: ${res.error}`)}\n`);
          }
        }

        process.stdout.write(
          pc.gray(
            '──────────────────────────────────────────────────────────────────────\n',
          ),
        );
        const scoreColor =
          report.resilienceScorePercent >= 90
            ? pc.green
            : report.resilienceScorePercent >= 70
              ? pc.yellow
              : pc.red;

        process.stdout.write(
          pc.bold(`Resilience Score: `) +
            scoreColor(`${report.resilienceScorePercent}%`) +
            ` (${report.safeCount}/${report.totalMutations} mutations handled safely)\n\n`,
        );

        process.exit(
          report.crashedCount === 0 ? ExitCode.SUCCESS : ExitCode.GENERAL_ERROR,
        );
      } catch (err: unknown) {
        process.stderr.write(
          `${pc.red('Fuzzing Error:')} ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  return cmd;
}
