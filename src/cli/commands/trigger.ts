import { Command } from 'commander';
import http from 'node:http';
import https from 'node:https';
import pc from 'picocolors';
import {
  generateSyntheticWebhook,
  listAvailableTemplates,
} from '../../testing/generator.js';
import { validateDestinationUrl, createSsrfLookup } from '../../security/ssrf.js';
import { ExitCode } from '../../config/exit-codes.js';

export function createTriggerCommand(): Command {
  const cmd = new Command('trigger');

  cmd
    .description('Generate and dispatch synthetic mock webhooks with valid signatures')
    .argument('[provider]', 'Webhook provider (stripe, github, shopify, slack, svix)')
    .argument(
      '[event]',
      'Event type (e.g. payment_intent.succeeded, push, orders/create)',
    )
    .option('--list', 'List all available provider event templates', false)
    .option(
      '--url <destinationUrl>',
      'Destination URL to dispatch the synthetic webhook to',
    )
    .option('--secret <secret>', 'Secret key to sign the webhook with')
    .option(
      '--allow-loopback',
      'Allow dispatching to loopback (127.0.0.1, localhost)',
      false,
    )
    .option('--allow-private', 'Allow dispatching to private network addresses', false)
    .option('--print-curl', 'Print ready-to-run curl command', false)
    .option('--json', 'Output generated event as JSON', false)
    .action(async (provider, event, opts) => {
      if (opts.list || (!provider && !event)) {
        const templates = listAvailableTemplates();
        process.stdout.write(pc.bold('\nAvailable Synthetic Webhook Templates:\n'));
        process.stdout.write(
          '──────────────────────────────────────────────────────────────────────\n',
        );
        for (const t of templates) {
          process.stdout.write(`${pc.cyan(pc.bold(t.provider))}:\n`);
          for (const e of t.eventTypes) {
            process.stdout.write(`  • ${e}\n`);
          }
        }
        process.stdout.write(
          '──────────────────────────────────────────────────────────────────────\n',
        );
        process.stdout.write(
          `Run: ${pc.yellow('webhook-workbench trigger <provider> <event> --url <endpoint>')}\n\n`,
        );
        process.exit(ExitCode.SUCCESS);
      }

      if (!provider || !event) {
        process.stderr.write(
          `${pc.red('Error:')} Both provider and event arguments are required.\nRun ${pc.yellow('webhook-workbench trigger --list')} to see available options.\n`,
        );
        process.exit(ExitCode.INVALID_ARGUMENT);
      }

      let synthetic;
      try {
        synthetic = generateSyntheticWebhook(provider, event, {
          secret: opts.secret,
        });
      } catch (genErr) {
        process.stderr.write(
          `${pc.red('Generation Error:')} ${genErr instanceof Error ? genErr.message : String(genErr)}\n`,
        );
        process.exit(ExitCode.INVALID_ARGUMENT);
      }

      // If --json requested
      if (opts.json) {
        process.stdout.write(JSON.stringify(synthetic, null, 2) + '\n');
        return;
      }

      // If --print-curl requested
      const curlHeaders = Object.entries(synthetic.headers)
        .map(([k, v]) => `-H "${k}: ${v}"`)
        .join(' \\\n  ');
      const escapedBody = synthetic.rawBody.replace(/'/g, "'\\''");
      const targetUrl = opts.url ?? 'http://127.0.0.1:8787/';
      const curlCmd = `curl -X POST "${targetUrl}" \\\n  ${curlHeaders} \\\n  -d '${escapedBody}'`;

      if (opts.printCurl) {
        process.stdout.write(curlCmd + '\n');
        return;
      }

      // If --url provided, dispatch request with SSRF validation
      if (opts.url) {
        try {
          const validated = await validateDestinationUrl(opts.url, {
            allowLoopback: opts.allowLoopback,
            allowPrivate: opts.allowPrivate,
          });

          const isHttps = validated.url.protocol === 'https:';
          const transport = isHttps ? https : http;
          const cleanHost = validated.url.hostname.replace(/^\[|\]$/g, '');

          const lookup = createSsrfLookup({
            allowLoopback: opts.allowLoopback,
            allowPrivate: opts.allowPrivate,
          });

          const startTime = Date.now();
          const reqOptions: http.RequestOptions = {
            method: 'POST',
            hostname: cleanHost,
            port: validated.url.port || (isHttps ? 443 : 80),
            path: `${validated.url.pathname}${validated.url.search}`,
            headers: {
              ...synthetic.headers,
              'content-length': Buffer.byteLength(synthetic.rawBody),
            },
            lookup,
            timeout: 10000,
          };

          await new Promise<void>((resolve, reject) => {
            const req = transport.request(reqOptions, (res) => {
              let resBody = '';
              res.on('data', (c) => (resBody += c.toString('utf8')));
              res.on('end', () => {
                const duration = Date.now() - startTime;
                const statusColor = (res.statusCode ?? 0) < 400 ? pc.green : pc.red;
                process.stdout.write(
                  `[Trigger] ${pc.cyan(synthetic.provider)}.${pc.bold(synthetic.eventType)} -> ${opts.url} ${statusColor(String(res.statusCode) + ' ' + (res.statusMessage ?? ''))} (${duration}ms)\n`,
                );
                if (resBody && resBody.trim().length > 0) {
                  process.stdout.write(`Response preview: ${resBody.slice(0, 500)}\n`);
                }
                resolve();
              });
            });

            req.on('error', reject);
            req.write(synthetic.rawBody);
            req.end();
          });
        } catch (dispatchErr) {
          process.stderr.write(
            `${pc.red('Dispatch Error:')} ${dispatchErr instanceof Error ? dispatchErr.message : String(dispatchErr)}\n`,
          );
          process.exit(ExitCode.REPLAY_FAILED);
        }
      } else {
        // Output summary and ready-to-run curl
        process.stdout.write(
          pc.bold(`\nGenerated ${synthetic.provider} Webhook: ${synthetic.eventType}\n`),
        );
        process.stdout.write(
          '──────────────────────────────────────────────────────────────────────\n',
        );
        process.stdout.write(pc.cyan('Headers:\n'));
        for (const [k, v] of Object.entries(synthetic.headers)) {
          process.stdout.write(`  ${pc.bold(k)}: ${v}\n`);
        }
        process.stdout.write(pc.cyan('\nPayload:\n'));
        process.stdout.write(`${synthetic.rawBody}\n`);
        process.stdout.write(
          '──────────────────────────────────────────────────────────────────────\n',
        );
        process.stdout.write(pc.bold('Ready-to-run curl:\n'));
        process.stdout.write(`${curlCmd}\n\n`);
      }
    });

  return cmd;
}
