import pc from 'picocolors';
import type { WebhookEvent } from '../events/types.js';

export function diffEvents(eventA: WebhookEvent, eventB: WebhookEvent): string {
  const lines: string[] = [];
  lines.push(pc.bold(`\n=== Comparing Event [A] ${eventA.id} vs [B] ${eventB.id} ===`));
  lines.push('──────────────────────────────────────────────────────────────────────');

  // Metadata comparison
  lines.push(pc.cyan(pc.bold('Metadata:')));
  if (eventA.method !== eventB.method) {
    lines.push(
      `  Method: ${pc.red('- ' + eventA.method)} -> ${pc.green('+ ' + eventB.method)}`,
    );
  } else {
    lines.push(`  Method: ${eventA.method}`);
  }

  if (eventA.path !== eventB.path) {
    lines.push(
      `  Path: ${pc.red('- ' + eventA.path)} -> ${pc.green('+ ' + eventB.path)}`,
    );
  } else {
    lines.push(`  Path: ${eventA.path}`);
  }

  lines.push(`  Timestamp A: ${eventA.timestamp}`);
  lines.push(`  Timestamp B: ${eventB.timestamp}`);

  // Headers diff
  lines.push(pc.cyan(pc.bold('\nHeaders Diff:')));
  const allHeaderKeys = Array.from(
    new Set([...Object.keys(eventA.headers), ...Object.keys(eventB.headers)]),
  ).sort();

  let headerDiffFound = false;
  for (const k of allHeaderKeys) {
    const valA = eventA.headers[k];
    const valB = eventB.headers[k];
    const strA =
      valA !== undefined ? (Array.isArray(valA) ? valA.join(', ') : valA) : undefined;
    const strB =
      valB !== undefined ? (Array.isArray(valB) ? valB.join(', ') : valB) : undefined;

    if (strA === undefined && strB !== undefined) {
      lines.push(`  ${pc.green(`+ ${k}: ${strB}`)}`);
      headerDiffFound = true;
    } else if (strA !== undefined && strB === undefined) {
      lines.push(`  ${pc.red(`- ${k}: ${strA}`)}`);
      headerDiffFound = true;
    } else if (strA !== strB) {
      lines.push(
        `  ${pc.yellow(`~ ${k}:`)} ${pc.red(strA ?? '')} -> ${pc.green(strB ?? '')}`,
      );
      headerDiffFound = true;
    }
  }
  if (!headerDiffFound) {
    lines.push('  (Identical headers)');
  }

  // Payload diff
  lines.push(pc.cyan(pc.bold('\nPayload Diff:')));
  const jsonA = eventA.body ? JSON.stringify(eventA.body, null, 2) : eventA.rawBody;
  const jsonB = eventB.body ? JSON.stringify(eventB.body, null, 2) : eventB.rawBody;

  if (jsonA === jsonB) {
    lines.push('  (Identical payloads)');
  } else {
    const linesA = jsonA.split('\n');
    const linesB = jsonB.split('\n');
    const max = Math.max(linesA.length, linesB.length);
    for (let i = 0; i < max; i++) {
      const lineA = linesA[i];
      const lineB = linesB[i];
      if (lineA === lineB) {
        lines.push(`   ${lineA}`);
      } else {
        if (lineA !== undefined) lines.push(pc.red(` - ${lineA}`));
        if (lineB !== undefined) lines.push(pc.green(` + ${lineB}`));
      }
    }
  }

  lines.push('──────────────────────────────────────────────────────────────────────\n');
  return lines.join('\n');
}
