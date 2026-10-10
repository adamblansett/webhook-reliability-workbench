import { z } from 'zod';
import fs from 'node:fs/promises';
import path from 'node:path';
import { LIMITS } from '../security/limits.js';

export const WorkbenchConfigSchema = z.object({
  receiver: z
    .object({
      host: z.string().default('127.0.0.1'),
      port: z.number().int().min(0).max(65535).default(8787),
      path: z.string().default('/'),
      allowExternal: z.boolean().default(false),
      maxBodySizeBytes: z
        .number()
        .int()
        .min(1024)
        .max(LIMITS.MAX_ALLOWED_BODY_SIZE_BYTES)
        .default(LIMITS.DEFAULT_MAX_BODY_SIZE_BYTES),
      responseStatus: z.number().int().min(100).max(599).default(200),
      delayMs: z.number().int().min(0).max(LIMITS.MAX_DELAY_MS).default(0),
      responseBody: z.string().optional(),
    })
    .default({}),
  signatures: z
    .object({
      headerName: z.string().default('x-hub-signature-256'),
      algorithm: z.enum(['sha256', 'sha512', 'sha1']).default('sha256'),
      prefix: z.string().optional(),
    })
    .default({}),
  replay: z
    .object({
      timeoutMs: z
        .number()
        .int()
        .min(LIMITS.MIN_REPLAY_TIMEOUT_MS)
        .max(LIMITS.MAX_REPLAY_TIMEOUT_MS)
        .default(LIMITS.DEFAULT_REPLAY_TIMEOUT_MS),
      maxResponseSizeBytes: z
        .number()
        .int()
        .min(1024)
        .max(LIMITS.MAX_ALLOWED_RESPONSE_SIZE_BYTES)
        .default(LIMITS.DEFAULT_MAX_RESPONSE_SIZE_BYTES),
      allowLoopback: z.boolean().default(false),
      allowPrivate: z.boolean().default(false),
    })
    .default({}),
  store: z
    .object({
      type: z.enum(['memory', 'file']).default('file'),
      filePath: z.string().default(path.join(process.cwd(), '.workbench', 'events.json')),
      maxEvents: z
        .number()
        .int()
        .min(1)
        .max(LIMITS.MAX_STORE_CAPACITY)
        .default(LIMITS.DEFAULT_STORE_MAX_EVENTS),
    })
    .default({}),
});

export type WorkbenchConfig = z.infer<typeof WorkbenchConfigSchema>;

/**
 * Loads configuration by merging:
 * Defaults < Config File (.workbenchrc.json) < Environment Variables < CLI Flags
 */
export async function loadConfigFile(
  configPath?: string,
): Promise<Partial<WorkbenchConfig>> {
  const targetPath = configPath
    ? path.resolve(configPath)
    : path.resolve(process.cwd(), '.workbenchrc.json');

  try {
    const raw = await fs.readFile(targetPath, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed;
  } catch (err: unknown) {
    if (
      err &&
      typeof err === 'object' &&
      'code' in err &&
      (err as { code: string }).code === 'ENOENT'
    ) {
      // Config file is optional
      return {};
    }
    throw new Error(
      `Failed to parse configuration file at "${targetPath}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Maps environment variables to partial configuration.
 */
export function loadEnvConfig(): Partial<WorkbenchConfig> {
  const env = process.env;
  const partial: Record<string, unknown> = {};

  if (env['WORKBENCH_PORT']) {
    partial['receiver'] = {
      ...(partial['receiver'] as object),
      port: parseInt(env['WORKBENCH_PORT'], 10),
    };
  }
  if (env['WORKBENCH_HOST']) {
    partial['receiver'] = {
      ...(partial['receiver'] as object),
      host: env['WORKBENCH_HOST'],
    };
  }
  if (env['WORKBENCH_PATH']) {
    partial['receiver'] = {
      ...(partial['receiver'] as object),
      path: env['WORKBENCH_PATH'],
    };
  }
  if (env['WORKBENCH_SIGNATURE_HEADER']) {
    partial['signatures'] = {
      ...(partial['signatures'] as object),
      headerName: env['WORKBENCH_SIGNATURE_HEADER'],
    };
  }
  if (env['WORKBENCH_STORE_FILE']) {
    partial['store'] = {
      ...(partial['store'] as object),
      filePath: env['WORKBENCH_STORE_FILE'],
    };
  }

  return partial as Partial<WorkbenchConfig>;
}

/**
 * Resolves full configuration with Zod validation.
 */
export async function resolveConfig(
  fileConfigPath?: string,
  cliOverrides: Partial<WorkbenchConfig> = {},
): Promise<WorkbenchConfig> {
  const fileConfig = await loadConfigFile(fileConfigPath);
  const envConfig = loadEnvConfig();

  const merged = {
    ...fileConfig,
    ...envConfig,
    ...cliOverrides,
    receiver: {
      ...fileConfig.receiver,
      ...envConfig.receiver,
      ...cliOverrides.receiver,
    },
    signatures: {
      ...fileConfig.signatures,
      ...envConfig.signatures,
      ...cliOverrides.signatures,
    },
    replay: {
      ...fileConfig.replay,
      ...envConfig.replay,
      ...cliOverrides.replay,
    },
    store: {
      ...fileConfig.store,
      ...envConfig.store,
      ...cliOverrides.store,
    },
  };

  return WorkbenchConfigSchema.parse(merged);
}
