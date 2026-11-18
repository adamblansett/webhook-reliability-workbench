// Receiver
export {
  createReceiver,
  ReceiverSecurityError,
  type ReceiverInstance,
} from './receiver/server.js';
export type { ReceiverOptions, ReceiverServerInfo } from './receiver/types.js';

// Events & Storage
export {
  InMemoryEventStore,
  FileEventStore,
  SqliteEventStore,
  createDefaultStore,
  generateEventId,
} from './events/store.js';
export type { WebhookEvent, EventStore, ReplayRecord } from './events/types.js';

// Signatures & Presets
export {
  verifySignature,
  computeHmacDigest,
  computeSignature,
  timingSafeCompare,
  parseSignatureHeader,
  createEd25519PublicKey,
} from './signatures/verifier.js';
export {
  getProviderPreset,
  listProviderPresets,
  PROVIDER_PRESETS,
  type WebhookProviderPreset,
} from './signatures/presets.js';
export type {
  SignatureVerifyOptions,
  SignatureVerificationResult,
  SupportedHmacAlgorithm,
  SupportedSignatureAlgorithm,
} from './signatures/types.js';

// Synthetic Webhook Generator
export {
  generateSyntheticWebhook,
  listAvailableTemplates,
  TEMPLATES,
  type GeneratedWebhook,
  type GenerateWebhookOptions,
} from './testing/generator.js';

// Diff & Inspection
export { diffEvents } from './output/diff.js';
export { renderInspectorHtml } from './receiver/ui.js';

// Replay
export { replayWebhookEvent } from './replay/engine.js';
export type { ReplayOptions, ReplayResult } from './replay/types.js';

// Retries
export { testWebhookRetries } from './retries/tester.js';
export type {
  RetryTestOptions,
  RetryAttemptResult,
  RetryTestSummary,
} from './retries/types.js';

// Fixtures
export {
  exportFixture,
  validateFixtureFile,
  fixtureToWebhookEvent,
  type ExportFixtureOptions,
  type FixtureValidationResult,
} from './fixtures/manager.js';
export { WebhookFixtureSchema, type WebhookFixture } from './fixtures/schema.js';

// Security
export {
  validateDestinationUrl,
  isLoopbackIp,
  isPrivateIp,
  isLinkLocalOrMetadataIp,
  isSpecialOrRestrictedIp,
  normalizeIp,
  SsrSecurityError,
  type SsrValidationOptions,
  type ValidatedDestination,
} from './security/ssrf.js';

export {
  redactHeaders,
  redactPayload,
  redactString,
  redactEventForDisplay,
  isSensitiveHeader,
  isSensitiveFieldKey,
  REDACTED_PLACEHOLDER,
} from './security/redaction.js';

export {
  resolveSafePath,
  assertFileWriteSafety,
  PathSecurityError,
} from './security/path.js';

export { LIMITS } from './security/limits.js';

// Config & Exit Codes
export {
  resolveConfig,
  loadConfigFile,
  loadEnvConfig,
  WorkbenchConfigSchema,
  type WorkbenchConfig,
} from './config/schema.js';
export { ExitCode, type ExitCodeType } from './config/exit-codes.js';

// Output Formatter
export {
  formatEventList,
  formatEventDetail,
  formatReplayResult,
  formatRetrySummary,
  formatFixtureValidation,
  formatJson,
} from './output/formatter.js';
