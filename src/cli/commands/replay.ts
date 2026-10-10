import { Command } from 'commander';
import { createDefaultStore } from '../../events/store.js';
import { replayWebhookEvent } from '../../replay/engine.js';
import { formatReplayResult, formatJson } from '../../output/formatter.js';
import { ExitCode } from '../../config/exit-codes.js';
import { SsrSecurityError } from '../../security/ssrf.js';
import type { SupportedHmacAlgorithm } from '../../signatures/types.js';

export function createReplayCommand(): Command {
  const cmd = new Command('replay');

  cmd
    .description('Replay a captured webhook event to a target destination')
    .argument('<eventId>', 'ID of the captured event to replay')
    .requiredOption(
      '-u, --url <destinationUrl>',
      'Destination URL to send the replayed webhook to',
    )
    .option(
      '--allow-loopback',
      'Explicitly permit loopback destinations (127.0.0.1, localhost)',
      false,
    )
    .option(
      '--allow-private',
      'Explicitly permit private network destinations (RFC 1918)',
      false,
    )
    .option(
      '--timeout <ms>',
      'Request timeout in milliseconds',
      (v) => parseInt(v, 10),
      5000,
    )
    .option(
      '--max-response-size <bytes>',
      'Maximum response body size to buffer',
      (v) => parseInt(v, 10),
      1024 * 1024,
    )
    .option(
      '--header <headers...>',
      'Header override in Name=Value or Name: Value format',
    )
    .option('--remove-header <headers...>', 'Header name to strip before sending')
    .option('--keep-signatures', 'Do not strip original webhook signature headers', false)
    .option('--keep-auth', 'Do not strip original authorization / cookie headers', false)
    .option(
      '--regenerate-signature',
      'Regenerate a fresh HMAC signature for the replayed request',
      false,
    )
    .option('--secret <signingSecret>', 'Signing secret for HMAC signature regeneration')
    .option(
      '--signature-header <name>',
      'Header name for signature regeneration',
      'x-hub-signature-256',
    )
    .option('--signature-prefix <prefix>', 'Signature prefix (e.g. "sha256=")')
    .option(
      '--algorithm <alg>',
      'HMAC algorithm for signature regeneration (sha256, sha512, sha1)',
      'sha256',
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

        // Parse header overrides
        const headerOverrides: Record<string, string> = {};
        if (opts.header && Array.isArray(opts.header)) {
          for (const item of opts.header) {
            const separatorIdx = item.includes(':')
              ? item.indexOf(':')
              : item.indexOf('=');
            if (separatorIdx > 0) {
              const k = item.slice(0, separatorIdx).trim();
              const v = item.slice(separatorIdx + 1).trim();
              headerOverrides[k] = v;
            }
          }
        }

        const result = await replayWebhookEvent(
          event,
          {
            url: opts.url,
            allowLoopback: opts.allowLoopback,
            allowPrivate: opts.allowPrivate,
            timeoutMs: opts.timeout,
            maxResponseSizeBytes: opts.maxResponseSize,
            headerOverrides,
            removeHeaders: opts.removeHeader,
            keepSignatures: opts.keepSignatures,
            keepAuth: opts.keepAuth,
            regenerateSignature: opts.regenerateSignature,
            secret: opts.secret,
            signatureHeader: opts.signatureHeader,
            signaturePrefix: opts.signaturePrefix,
            algorithm: opts.algorithm as SupportedHmacAlgorithm,
          },
          store,
        );

        if (opts.json) {
          process.stdout.write(formatJson(result) + '\n');
        } else {
          process.stdout.write(formatReplayResult(result) + '\n');
        }

        if (!result.success) {
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
