import { Command } from 'commander';
import { resolveConfig } from '../../config/schema.js';
import { formatJson } from '../../output/formatter.js';
import { ExitCode } from '../../config/exit-codes.js';

export function createConfigCommand(): Command {
  const configCmd = new Command('config');
  configCmd.description('Display resolved configuration and runtime defaults');

  configCmd
    .command('show', { isDefault: true })
    .description('Show active configuration parameters')
    .option('-c, --config <file>', 'Path to custom configuration file')
    .option('--json', 'Output machine-readable JSON format')
    .action(async (opts) => {
      try {
        const config = await resolveConfig(opts.config);

        if (opts.json) {
          process.stdout.write(formatJson(config) + '\n');
        } else {
          process.stdout.write('=== Webhook Reliability Workbench Configuration ===\n');
          process.stdout.write(formatJson(config) + '\n');
        }
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.CONFIG_ERROR);
      }
    });

  return configCmd;
}
