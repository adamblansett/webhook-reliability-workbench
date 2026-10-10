#!/usr/bin/env node
import { Command, CommanderError } from 'commander';
import pc from 'picocolors';
import { createListenCommand } from './commands/listen.js';
import { createEventsCommand } from './commands/events.js';
import { createReplayCommand } from './commands/replay.js';
import { createTestRetriesCommand } from './commands/test-retries.js';
import { createFixturesCommand } from './commands/fixtures.js';
import { createConfigCommand } from './commands/config.js';
import { ExitCode } from '../config/exit-codes.js';

export function createProgram(): Command {
  const program = new Command('webhook-workbench');

  program
    .version('0.1.0')
    .description(
      'Local-first developer tool for capturing, inspecting, validating, replaying, and testing webhook integrations',
    );

  program.addCommand(createListenCommand());
  program.addCommand(createEventsCommand());
  program.addCommand(createReplayCommand());
  program.addCommand(createTestRetriesCommand());
  program.addCommand(createFixturesCommand());
  program.addCommand(createConfigCommand());

  return program;
}

export async function main(args: string[] = process.argv): Promise<void> {
  const program = createProgram();
  program.exitOverride();

  try {
    await program.parseAsync(args);
  } catch (err: unknown) {
    if (err instanceof CommanderError) {
      if (err.exitCode === 0) {
        process.exit(ExitCode.SUCCESS);
      }
      process.stderr.write(pc.red(`Error: ${err.message}\n`));
      process.exit(ExitCode.INVALID_ARGUMENT);
    }

    process.stderr.write(
      pc.red(`Fatal Error: ${err instanceof Error ? err.message : String(err)}\n`),
    );
    process.exit(ExitCode.GENERAL_ERROR);
  }
}

// Auto-run if executed as main CLI binary
const isMainScript =
  import.meta.url === `file://${process.argv[1]}` ||
  (process.argv[1] && process.argv[1].endsWith('webhook-workbench'));

if (isMainScript) {
  main().catch((err) => {
    process.stderr.write(`Unhandled exception: ${String(err)}\n`);
    process.exit(ExitCode.GENERAL_ERROR);
  });
}
