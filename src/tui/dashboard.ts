import readline from 'node:readline';
import pc from 'picocolors';
import type { EventStore, WebhookEvent } from '../events/types.js';
import { generateCurlCommand } from '../codegen/curlGenerator.js';
import { replayWebhookEvent } from '../replay/engine.js';

export interface TuiOptions {
  port: number;
  host: string;
  path: string;
  tunnelUrl?: string;
  forwardUrl?: string;
  store: EventStore;
}

export class TerminalDashboard {
  private store: EventStore;
  private options: TuiOptions;
  private events: WebhookEvent[] = [];
  private selectedIndex = 0;
  private isRunning = false;
  private statusMessage = '';
  private statusMessageTimeout: NodeJS.Timeout | null = null;

  constructor(options: TuiOptions) {
    this.options = options;
    this.store = options.store;
  }

  public async start(): Promise<void> {
    if (!process.stdin.isTTY) {
      process.stdout.write(
        pc.yellow('[TUI] Non-interactive TTY detected. TUI mode disabled.\n'),
      );
      return;
    }

    this.isRunning = true;

    // Switch to alternate screen buffer and hide cursor
    process.stdout.write('\x1b[?1049h\x1b[?25l');

    // Setup keypress listener
    readline.emitKeypressEvents(process.stdin);
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
    }

    process.stdin.on('keypress', this.handleKeypress.bind(this));
    process.stdout.on('resize', () => this.render());

    // Initial load and periodic refresh
    await this.refreshEvents();
    this.render();

    const interval = setInterval(async () => {
      if (!this.isRunning) {
        clearInterval(interval);
        return;
      }
      await this.refreshEvents();
      this.render();
    }, 1000);
  }

  public stop(): void {
    if (!this.isRunning) return;
    this.isRunning = false;

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false);
    }
    process.stdin.removeListener('keypress', this.handleKeypress.bind(this));

    // Restore main screen buffer and show cursor
    process.stdout.write('\x1b[?1049l\x1b[?25h');
  }

  public onNewEvent(event: WebhookEvent): void {
    this.events.unshift(event);
    if (this.events.length > 50) this.events.pop();
    this.render();
  }

  private async refreshEvents(): Promise<void> {
    try {
      const list = await this.store.list({ limit: 50 });
      this.events = list;
      if (this.selectedIndex >= this.events.length) {
        this.selectedIndex = Math.max(0, this.events.length - 1);
      }
    } catch {
      // Ignore
    }
  }

  private async handleKeypress(_str: string, key: readline.Key): Promise<void> {
    if (!this.isRunning) return;

    if (key.ctrl && key.name === 'c') {
      this.stop();
      process.exit(0);
      return;
    }

    if (key.name === 'q') {
      this.stop();
      process.exit(0);
      return;
    }

    if (key.name === 'up') {
      if (this.selectedIndex > 0) {
        this.selectedIndex--;
        this.render();
      }
      return;
    }

    if (key.name === 'down') {
      if (this.selectedIndex < this.events.length - 1) {
        this.selectedIndex++;
        this.render();
      }
      return;
    }

    // Replay active event: 'r'
    if (key.name === 'r') {
      const activeEvent = this.events[this.selectedIndex];
      if (activeEvent) {
        this.setStatus('Replaying event...');
        const targetUrl = this.options.forwardUrl ?? 'http://127.0.0.1:3000/api/webhooks';
        try {
          const res = await replayWebhookEvent(
            activeEvent,
            {
              url: targetUrl,
              allowLoopback: true,
              allowPrivate: true,
            },
            this.store,
          );
          this.setStatus(
            `Replayed to ${targetUrl}: HTTP ${res.status} (${res.durationMs}ms)`,
          );
        } catch (err: unknown) {
          this.setStatus(
            `Replay failed: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
      return;
    }

    // Copy cURL: 'c'
    if (key.name === 'c') {
      const activeEvent = this.events[this.selectedIndex];
      if (activeEvent) {
        const curl = generateCurlCommand(activeEvent);
        // Write to terminal temporary notice
        this.setStatus(`cURL command generated! (${curl.slice(0, 40)}...)`);
      }
      return;
    }
  }

  private setStatus(msg: string): void {
    this.statusMessage = msg;
    if (this.statusMessageTimeout) clearTimeout(this.statusMessageTimeout);
    this.statusMessageTimeout = setTimeout(() => {
      this.statusMessage = '';
      this.render();
    }, 4000);
    this.render();
  }

  public render(): void {
    if (!this.isRunning) return;

    const cols = process.stdout.columns || 100;
    const rows = process.stdout.rows || 30;

    let buf = '\x1b[H\x1b[2J'; // Clear screen & home cursor

    // 1. Header Bar
    const title = pc.bold(pc.cyan('⚡ Webhook Reliability Workbench'));
    const listener = pc.white(
      `http://${this.options.host}:${this.options.port}${this.options.path}`,
    );
    const tunnel = this.options.tunnelUrl
      ? pc.green(` | Ingress: ${this.options.tunnelUrl}`)
      : '';
    const count = pc.yellow(`[Captured: ${this.events.length}]`);
    buf += `${title} — ${listener}${tunnel} ${count}\n`;
    buf += pc.gray('─'.repeat(cols)) + '\n';

    // 2. Split Screen Panes
    const leftWidth = Math.max(30, Math.floor(cols * 0.38));
    const rightWidth = cols - leftWidth - 2;
    const mainHeight = rows - 5;

    const leftLines: string[] = [];
    for (let i = 0; i < mainHeight; i++) {
      const evt = this.events[i];
      if (evt) {
        const isSelected = i === this.selectedIndex;
        const pointer = isSelected ? pc.cyan('❯ ') : '  ';
        const method = pc.bold(evt.method.padEnd(5));
        const status =
          evt.responseStatus >= 400
            ? pc.red(String(evt.responseStatus))
            : pc.green(String(evt.responseStatus));
        const sig = evt.signature
          ? evt.signature.valid
            ? pc.green('✓')
            : pc.red('✗')
          : pc.gray('·');
        const time = pc.gray(new Date(evt.timestamp).toLocaleTimeString());

        let line = `${pointer}${status} ${method} ${sig} ${time}`;
        if (line.length > leftWidth) line = line.slice(0, leftWidth);
        leftLines.push(
          isSelected ? pc.bgBlue(line.padEnd(leftWidth)) : line.padEnd(leftWidth),
        );
      } else {
        leftLines.push(' '.repeat(leftWidth));
      }
    }

    const rightLines: string[] = [];
    const active = this.events[this.selectedIndex];
    if (active) {
      rightLines.push(pc.bold(pc.white(`Event Details: ${active.id}`)));
      rightLines.push(
        pc.gray(`Timestamp: ${active.timestamp} | Size: ${active.contentLength} bytes`),
      );

      const sigStatus = active.signature
        ? active.signature.valid
          ? pc.green(`Valid HMAC (${active.signature.algorithm})`)
          : pc.red(`Invalid HMAC: ${active.signature.reason}`)
        : pc.gray('No signature verified');
      rightLines.push(pc.bold('Signature: ') + sigStatus);

      if (active.forwardResult) {
        const fwdColor = active.forwardResult.status >= 400 ? pc.red : pc.green;
        rightLines.push(
          pc.bold('Forwarded To: ') +
            `${active.forwardResult.destination} [${fwdColor(String(active.forwardResult.status))}] (${active.forwardResult.durationMs}ms)`,
        );
      }

      rightLines.push(pc.gray('─'.repeat(rightWidth)));
      rightLines.push(pc.bold(pc.cyan('Headers:')));
      for (const [k, v] of Object.entries(active.headers || {}).slice(0, 6)) {
        const valStr = Array.isArray(v) ? v.join(', ') : String(v);
        rightLines.push(`  ${pc.gray(k)}: ${valStr.slice(0, rightWidth - k.length - 6)}`);
      }

      rightLines.push(pc.gray('─'.repeat(rightWidth)));
      rightLines.push(pc.bold(pc.cyan('Body:')));
      const bodyPreview = active.body
        ? JSON.stringify(active.body, null, 2)
        : active.rawBody || '(empty body)';
      for (const line of bodyPreview
        .split('\n')
        .slice(0, mainHeight - rightLines.length - 2)) {
        rightLines.push(`  ${line.slice(0, rightWidth - 4)}`);
      }
    } else {
      rightLines.push(pc.gray('Waiting for incoming webhook events...'));
    }

    // Combine Left and Right columns
    for (let r = 0; r < mainHeight; r++) {
      const left = leftLines[r] ?? ' '.repeat(leftWidth);
      const right = rightLines[r] ?? '';
      buf += `${left} ${pc.gray('│')} ${right}\n`;
    }

    // 3. Status Bar & Footer
    buf += pc.gray('─'.repeat(cols)) + '\n';
    if (this.statusMessage) {
      buf += pc.yellow(`⚡ ${this.statusMessage}`.padEnd(cols)) + '\n';
    } else {
      buf +=
        pc.gray('[↑/↓] Select   [r] Replay   [c] cURL   [q] Quit'.padEnd(cols)) + '\n';
    }

    process.stdout.write(buf);
  }
}
