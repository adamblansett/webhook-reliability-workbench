import { Command } from 'commander';
import { createDefaultStore } from '../../events/store.js';
import {
  exportFixture,
  validateFixtureFile,
  fixtureToWebhookEvent,
} from '../../fixtures/manager.js';
import { formatFixtureValidation, formatJson } from '../../output/formatter.js';
import { ExitCode } from '../../config/exit-codes.js';
import { PathSecurityError } from '../../security/path.js';

export function createFixturesCommand(): Command {
  const fixturesCmd = new Command('fixtures');
  fixturesCmd.description('Export and validate portable webhook payload fixtures');

  fixturesCmd
    .command('export <eventId>')
    .description('Export a captured webhook event to a JSON fixture file')
    .requiredOption(
      '-o, --output <filePath>',
      'Destination output file path for the fixture',
    )
    .option('--overwrite', 'Allow overwriting target file if it already exists', false)
    .option('--name <name>', 'Descriptive fixture name')
    .option('--description <desc>', 'Detailed description of the fixture')
    .option(
      '--redact-auth',
      'Redact sensitive authorization and cookie headers in exported fixture',
      false,
    )
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

        const savedPath = await exportFixture(event, opts.output, {
          overwrite: opts.overwrite,
          name: opts.name,
          description: opts.description,
          redactAuthHeaders: opts.redactAuth,
        });

        process.stdout.write(
          `Successfully exported event ${eventId} to fixture: ${savedPath}\n`,
        );
      } catch (err) {
        if (err instanceof PathSecurityError) {
          process.stderr.write(`[Workbench SECURITY ERROR] ${err.message}\n`);
          process.exit(ExitCode.SECURITY_ERROR);
        }

        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  fixturesCmd
    .command('validate <filePath>')
    .description('Validate a fixture JSON file against the Workbench schema')
    .option('--json', 'Output machine-readable JSON format')
    .action(async (filePath: string, opts) => {
      try {
        const result = await validateFixtureFile(filePath);

        if (opts.json) {
          process.stdout.write(formatJson(result) + '\n');
        } else {
          process.stdout.write(formatFixtureValidation(result) + '\n');
        }

        if (!result.valid) {
          process.exit(ExitCode.INVALID_ARGUMENT);
        }
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  fixturesCmd
    .command('import <filePath>')
    .description('Import a fixture JSON file as a new captured event in the local store')
    .option('--store <filePath>', 'Path to file-backed event store')
    .option('--json', 'Output machine-readable JSON format')
    .action(async (filePath: string, opts) => {
      const store = createDefaultStore({
        type: 'file',
        filePath: opts.store,
      });

      try {
        const validation = await validateFixtureFile(filePath);
        if (!validation.valid || !validation.fixture) {
          process.stderr.write(
            `[Workbench ERROR] Cannot import invalid fixture: ${filePath}\n`,
          );
          if (validation.errors) {
            validation.errors.forEach((e) => process.stderr.write(`  - ${e}\n`));
          }
          process.exit(ExitCode.INVALID_ARGUMENT);
        }

        const event = fixtureToWebhookEvent(validation.fixture);
        await store.save(event);

        if (opts.json) {
          process.stdout.write(formatJson({ imported: true, eventId: event.id }) + '\n');
        } else {
          process.stdout.write(`Successfully imported fixture as event: ${event.id}\n`);
        }
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  return fixturesCmd;
}
