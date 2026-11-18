import { Command } from 'commander';
import pc from 'picocolors';
import { createDefaultStore } from '../../events/store.js';
import { loadScenarioFile, executeScenarioSuite } from '../../testing/suite.js';
import { ExitCode } from '../../config/exit-codes.js';

export function createTestSuiteCommand(): Command {
  const cmd = new Command('test-suite');

  cmd
    .description(
      'Run declarative webhook integration & idempotency scenario test suites for CI/CD',
    )
    .argument('<scenarioFile>', 'Path to scenario file (.json or .yaml)')
    .option('--target <url>', 'Override target destination URL in scenario')
    .option('--allow-private', 'Allow dispatching to private network addresses', false)
    .option('--store <filePath>', 'Path to file-backed event store')
    .option('--json', 'Output results as machine-readable JSON', false)
    .action(async (scenarioFile: string, opts) => {
      const store = createDefaultStore({
        type: 'file',
        filePath: opts.store,
      });

      try {
        const scenario = await loadScenarioFile(scenarioFile);
        if (opts.target) {
          scenario.target = opts.target;
        }
        if (opts.allowPrivate !== undefined) {
          scenario.allowPrivate = opts.allowPrivate;
        }

        if (!opts.json) {
          process.stdout.write(
            pc.bold(`\nExecuting Webhook Test Suite: ${pc.cyan(scenario.name)}\n`),
          );
          if (scenario.description) {
            process.stdout.write(pc.gray(`${scenario.description}\n`));
          }
          process.stdout.write(
            pc.gray(
              '──────────────────────────────────────────────────────────────────────\n',
            ),
          );
        }

        const suiteResult = await executeScenarioSuite(scenario, store);

        if (opts.json) {
          process.stdout.write(JSON.stringify(suiteResult, null, 2) + '\n');
          process.exit(
            suiteResult.allPassed ? ExitCode.SUCCESS : ExitCode.VALIDATION_ERROR,
          );
        }

        for (const step of suiteResult.stepResults) {
          const icon = step.passed ? pc.green('✓') : pc.red('✗');
          const stepNum = pc.gray(`[Step ${step.stepIndex}]`);
          const duration = pc.gray(`(${step.durationMs}ms)`);
          const status = step.status ? pc.cyan(`HTTP ${step.status}`) : '';

          process.stdout.write(
            `${icon} ${stepNum} ${pc.bold(step.name)} ${status} ${duration}\n`,
          );

          for (const failure of step.failures) {
            process.stdout.write(
              `    ${pc.red(`Assertion Failed:`)} ${failure.message}\n`,
            );
          }

          if (step.error) {
            process.stdout.write(`    ${pc.red(`Error:`)} ${step.error}\n`);
          }
        }

        process.stdout.write(
          pc.gray(
            '──────────────────────────────────────────────────────────────────────\n',
          ),
        );

        if (suiteResult.allPassed) {
          process.stdout.write(
            pc.green(
              pc.bold(
                `✓ All ${suiteResult.totalSteps} scenario steps passed in ${suiteResult.durationMs}ms\n\n`,
              ),
            ),
          );
          process.exit(ExitCode.SUCCESS);
        } else {
          process.stderr.write(
            pc.red(
              pc.bold(
                `✗ ${suiteResult.failedSteps}/${suiteResult.totalSteps} steps failed in ${suiteResult.durationMs}ms\n\n`,
              ),
            ),
          );
          process.exit(ExitCode.VALIDATION_ERROR);
        }
      } catch (err: unknown) {
        process.stderr.write(
          `${pc.red('Test Suite Execution Error:')} ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.GENERAL_ERROR);
      }
    });

  return cmd;
}
