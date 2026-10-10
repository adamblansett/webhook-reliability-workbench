import pc from 'picocolors';
import type { WebhookEvent } from '../events/types.js';
import type { ReplayResult } from '../replay/types.js';
import type { RetryTestSummary } from '../retries/types.js';
import type { FixtureValidationResult } from '../fixtures/manager.js';
import {
  redactHeaders,
  redactPayload,
  redactQueryParams,
} from '../security/redaction.js';

export function formatJson(data: unknown): string {
  return JSON.stringify(data, null, 2);
}

export function formatEventListItem(event: WebhookEvent): string {
  const statusColor =
    event.responseStatus >= 400
      ? pc.red(String(event.responseStatus))
      : pc.green(String(event.responseStatus));

  const methodColor =
    event.method === 'POST'
      ? pc.blue(event.method)
      : event.method === 'GET'
        ? pc.cyan(event.method)
        : pc.yellow(event.method);

  let sigText = '';
  if (event.signature) {
    sigText = event.signature.valid ? pc.green('[SIG: VALID]') : pc.red('[SIG: INVALID]');
  }

  const replaysCount =
    event.replays && event.replays.length > 0
      ? pc.gray(`(${event.replays.length} replays)`)
      : '';

  return `${pc.bold(event.id)}  ${pc.gray(event.timestamp)}  ${methodColor} ${event.path} -> ${statusColor} (${event.durationMs}ms) ${sigText} ${replaysCount}`.trim();
}

export function formatEventList(events: WebhookEvent[]): string {
  if (events.length === 0) {
    return pc.gray('No webhook events recorded in store.');
  }

  const lines = [
    pc.bold(`Captured Webhook Events (${events.length}):`),
    pc.gray('─'.repeat(70)),
    ...events.map(formatEventListItem),
    pc.gray('─'.repeat(70)),
  ];

  return lines.join('\n');
}

export function formatEventDetail(event: WebhookEvent, rawMode = false): string {
  const safeHeaders = redactHeaders(event.headers);
  const safeQuery = rawMode ? event.query : redactQueryParams(event.query);
  const safeBody = rawMode ? event.rawBody : redactPayload(event.body ?? event.rawBody);

  const lines = [
    pc.bold(`\n=== Webhook Event: ${event.id} ===`),
    `${pc.bold('Timestamp:')}        ${event.timestamp}`,
    `${pc.bold('HTTP Method:')}      ${event.method}`,
    `${pc.bold('Path:')}             ${event.path}`,
    `${pc.bold('Response Status:')}  ${event.responseStatus}`,
    `${pc.bold('Duration:')}         ${event.durationMs}ms`,
    `${pc.bold('Content Type:')}     ${event.contentType ?? 'none'}`,
    `${pc.bold('Content Length:')}   ${event.contentLength} bytes`,
  ];

  if (Object.keys(safeQuery).length > 0) {
    lines.push('\n' + pc.bold('Query Parameters (Sensitive Values Redacted):'));
    for (const [k, v] of Object.entries(safeQuery)) {
      lines.push(`  ${pc.cyan(k)}: ${Array.isArray(v) ? v.join(', ') : v}`);
    }
  }

  lines.push('\n' + pc.bold('Headers (Sensitive Values Redacted):'));
  for (const [k, v] of Object.entries(safeHeaders)) {
    lines.push(`  ${pc.cyan(k)}: ${Array.isArray(v) ? v.join(', ') : v}`);
  }

  if (event.signature) {
    lines.push('\n' + pc.bold('Signature Verification:'));
    lines.push(
      `  Status:    ${event.signature.valid ? pc.green('VALID') : pc.red('INVALID')}`,
    );
    lines.push(`  Algorithm: ${event.signature.algorithm}`);
    if (event.signature.headerName)
      lines.push(`  Header:    ${event.signature.headerName}`);
    if (event.signature.reason) lines.push(`  Reason:    ${event.signature.reason}`);
    if (event.signature.error)
      lines.push(`  Error:     ${pc.red(event.signature.error)}`);
  }

  lines.push('\n' + pc.bold('Payload Body:'));
  if (typeof safeBody === 'object' && safeBody !== null) {
    lines.push(JSON.stringify(safeBody, null, 2));
  } else {
    lines.push(String(safeBody));
  }

  if (event.jsonError) {
    lines.push(pc.yellow(`[Note: Body is malformed JSON - ${event.jsonError}]`));
  }

  if (event.replays && event.replays.length > 0) {
    lines.push('\n' + pc.bold(`Replay History (${event.replays.length}):`));
    for (const r of event.replays) {
      const outcome = r.success ? pc.green('SUCCESS') : pc.red('FAILED');
      lines.push(
        `  ${r.timestamp} -> ${r.destination} | Status: ${r.status} (${outcome}, ${r.durationMs}ms)`,
      );
      if (r.error) {
        lines.push(`    Error: ${pc.red(r.error)}`);
      }
    }
  }

  lines.push('');
  return lines.join('\n');
}

export function formatReplayResult(result: ReplayResult): string {
  const outcome = result.success ? pc.green('SUCCESS') : pc.red('FAILED');
  const lines = [
    pc.bold('\n=== Webhook Replay Result ==='),
    `${pc.bold('Outcome:')}        ${outcome}`,
    `${pc.bold('Destination:')}    ${result.destination}`,
    `${pc.bold('HTTP Status:')}    ${result.status} ${result.statusText}`,
    `${pc.bold('Duration:')}       ${result.durationMs}ms`,
    `${pc.bold('Replay ID:')}      ${result.id}`,
    `${pc.bold('Timestamp:')}      ${result.timestamp}`,
  ];

  if (result.error) {
    lines.push(`${pc.bold('Error Detail:')}   ${pc.red(result.error)}`);
  }

  if (result.responseBodyPreview) {
    lines.push('\n' + pc.bold('Response Body Preview:'));
    lines.push(result.responseBodyPreview);
  }

  lines.push('');
  return lines.join('\n');
}

export function formatRetrySummary(summary: RetryTestSummary): string {
  const lines = [
    pc.bold('\n=== Webhook Retry Test Summary ==='),
    `${pc.bold('Event ID:')}           ${summary.eventId}`,
    `${pc.bold('Destination:')}        ${summary.destination}`,
    `${pc.bold('Total Attempts:')}      ${summary.totalAttempts}`,
    `${pc.bold('Successful:')}          ${pc.green(String(summary.successfulAttempts))}`,
    `${pc.bold('Failed:')}              ${pc.red(String(summary.failedAttempts))}`,
    `${pc.bold('Latency (Min/Avg/Max):')} ${summary.minDurationMs}ms / ${summary.avgDurationMs}ms / ${summary.maxDurationMs}ms`,
    '\n' + pc.bold('Attempt Breakdown:'),
    pc.gray('─'.repeat(70)),
  ];

  for (const item of summary.attempts) {
    const outcome = item.replayResult.success ? pc.green('SUCCESS') : pc.red('FAILED');
    const delayNotice =
      item.scheduledDelayMs > 0 ? ` (after ${item.scheduledDelayMs}ms delay)` : '';
    lines.push(
      `Attempt #${item.attempt}${delayNotice}: Status ${item.replayResult.status} [${outcome}] (${item.replayResult.durationMs}ms)`,
    );
    if (item.replayResult.error) {
      lines.push(`  Error: ${pc.red(item.replayResult.error)}`);
    }
  }

  lines.push(pc.gray('─'.repeat(70)));
  lines.push('');
  return lines.join('\n');
}

export function formatFixtureValidation(result: FixtureValidationResult): string {
  if (result.valid && result.summary) {
    return [
      pc.green('✓ Fixture is valid!'),
      `${pc.bold('File:')}             ${result.filePath}`,
      `${pc.bold('Schema Version:')}   ${result.schemaVersion}`,
      `${pc.bold('Original Event ID:')} ${result.summary.originalEventId}`,
      `${pc.bold('Method & Path:')}    ${result.summary.method} ${result.summary.path}`,
      `${pc.bold('Payload Size:')}     ${result.summary.bodySize} bytes`,
    ].join('\n');
  }

  return [
    pc.red('✗ Fixture validation failed:'),
    `${pc.bold('File:')} ${result.filePath}`,
    pc.bold('\nErrors:'),
    ...(result.errors ?? []).map((e) => `  - ${pc.red(e)}`),
  ].join('\n');
}
