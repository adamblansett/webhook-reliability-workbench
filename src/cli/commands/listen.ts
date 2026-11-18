import { Command } from 'commander';
import { createReceiver } from '../../receiver/server.js';
import { createDefaultStore } from '../../events/store.js';
import { ExitCode } from '../../config/exit-codes.js';
import type { SupportedSignatureAlgorithm } from '../../signatures/types.js';

export function createListenCommand(): Command {
  const cmd = new Command('listen');

  cmd
    .description('Start the local webhook receiver HTTP server')
    .option('-p, --port <number>', 'Port to listen on', (val) => parseInt(val, 10), 8787)
    .option('-h, --host <host>', 'Host address to bind', '127.0.0.1')
    .option('--path <path>', 'Webhook endpoint path to accept', '/')
    .option(
      '--allow-external',
      'Allow binding to external/non-loopback network interfaces',
      false,
    )
    .option(
      '--response-status <status>',
      'HTTP response status code to return',
      (v) => parseInt(v, 10),
      200,
    )
    .option(
      '--delay-ms <ms>',
      'Artificial response delay in milliseconds',
      (v) => parseInt(v, 10),
      0,
    )
    .option('--response-body <bodyString>', 'Custom response body payload')
    .option(
      '--preset <provider>',
      'Use provider preset (stripe, github, shopify, slack, svix)',
    )
    .option(
      '--secret <signingSecret>',
      'Shared HMAC secret or public key for verifying incoming signatures',
    )
    .option('--signature-header <name>', 'Header name containing the HMAC signature')
    .option(
      '--signature-prefix <prefix>',
      'Expected signature prefix (e.g. "sha256=", "v1,")',
    )
    .option(
      '--algorithm <alg>',
      'Signature algorithm (sha256, sha512, sha1, ed25519)',
      'sha256',
    )
    .option(
      '--forward-to <url>',
      'Transparently proxy captured webhooks to target application URL',
    )
    .option('--forward-allow-loopback', 'Allow forwarding to loopback destinations', true)
    .option(
      '--forward-allow-private',
      'Allow forwarding to private network destinations',
      false,
    )
    .option(
      '--ui',
      'Enable embedded Web Inspector UI (accessible at /__workbench/ui)',
      false,
    )
    .option(
      '--max-body-size <bytes>',
      'Maximum request body size in bytes',
      (v) => parseInt(v, 10),
      1024 * 1024,
    )
    .option('--store <filePath>', 'Path to file-backed event store')
    .action(async (opts) => {
      const store = createDefaultStore({
        type: 'file',
        filePath: opts.store,
      });

      try {
        const receiver = createReceiver({
          host: opts.host,
          port: opts.port,
          path: opts.path,
          allowExternal: opts.allowExternal,
          responseStatus: opts.responseStatus,
          delayMs: opts.delayMs,
          responseBody: opts.responseBody,
          preset: opts.preset,
          secret: opts.secret,
          signatureHeader: opts.signatureHeader,
          signaturePrefix: opts.signaturePrefix,
          algorithm: opts.algorithm as SupportedSignatureAlgorithm,
          forwardTo: opts.forwardTo,
          forwardAllowLoopback: opts.forwardAllowLoopback,
          forwardAllowPrivate: opts.forwardAllowPrivate,
          enableUi: opts.ui,
          maxBodySize: opts.maxBodySize,
          store,
        });

        const shutdown = async () => {
          process.stdout.write('\n[Workbench] Gracefully stopping receiver...\n');
          await receiver.stop();
          process.exit(ExitCode.SUCCESS);
        };

        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);

        const info = await receiver.start();
        if (opts.ui) {
          process.stdout.write(
            `[Workbench] Web Inspector UI available at http://${info.host}:${info.port}/__workbench/ui\n`,
          );
        }
        if (opts.forwardTo) {
          process.stdout.write(
            `[Workbench] Proxy mode enabled: Forwarding webhooks to ${opts.forwardTo}\n`,
          );
        }
      } catch (err) {
        process.stderr.write(
          `[Workbench ERROR] ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(ExitCode.RECEIVER_ERROR);
      }
    });

  return cmd;
}
