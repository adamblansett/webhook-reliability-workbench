import { spawn, ChildProcess } from 'node:child_process';

export interface TunnelOptions {
  port: number;
  provider?: 'cloudflare' | 'localtunnel' | 'auto';
  customCommand?: string;
  timeoutMs?: number;
}

export interface TunnelInstance {
  url: string;
  provider: string;
  process?: ChildProcess;
  stop(): Promise<void>;
}

/**
 * Spawns and manages an ephemeral public ingress tunnel for local webhook testing.
 */
export async function startTunnel(options: TunnelOptions): Promise<TunnelInstance> {
  const port = options.port;
  const timeoutMs = options.timeoutMs ?? 15000;
  const provider = options.provider ?? 'auto';

  if (options.customCommand) {
    return launchCustomTunnel(options.customCommand, port, timeoutMs);
  }

  // Provider: Cloudflare Quick Tunnel (Preferred - zero account/token required)
  if (provider === 'cloudflare' || provider === 'auto') {
    try {
      return await launchCloudflareTunnel(port, timeoutMs);
    } catch (cfErr) {
      if (provider === 'cloudflare') throw cfErr;
      // Fallback to localtunnel if auto
    }
  }

  // Provider: Localtunnel
  if (provider === 'localtunnel' || provider === 'auto') {
    return launchLocaltunnel(port, timeoutMs);
  }

  throw new Error(`Unsupported tunnel provider: ${provider}`);
}

async function launchCloudflareTunnel(
  port: number,
  timeoutMs: number,
): Promise<TunnelInstance> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        try {
          child.kill('SIGKILL');
        } catch {
          // Ignore kill errors
        }
        reject(
          new Error(`Cloudflare tunnel initialization timed out after ${timeoutMs}ms.`),
        );
      }
    }, timeoutMs);

    // Try cloudflared binary
    const child = spawn('cloudflared', ['tunnel', '--url', `http://127.0.0.1:${port}`], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let detectedUrl = '';

    const checkOutput = (data: Buffer) => {
      const text = data.toString('utf8');
      // Match https://[subdomain].trycloudflare.com
      const match = text.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
      if (match && !settled) {
        settled = true;
        clearTimeout(timeout);
        detectedUrl = match[0];
        resolve({
          url: detectedUrl,
          provider: 'cloudflare',
          process: child,
          stop: async () => {
            child.kill('SIGTERM');
          },
        });
      }
    };

    child.stdout.on('data', checkOutput);
    child.stderr.on('data', checkOutput);

    child.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`Failed to launch cloudflared: ${err.message}`));
      }
    });

    child.on('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`cloudflared exited prematurely with code ${code}`));
      }
    });
  });
}

async function launchLocaltunnel(
  port: number,
  timeoutMs: number,
): Promise<TunnelInstance> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        try {
          child.kill('SIGKILL');
        } catch {
          // Ignore kill errors
        }
        reject(new Error(`Localtunnel initialization timed out after ${timeoutMs}ms.`));
      }
    }, timeoutMs);

    const child = spawn('npx', ['--yes', 'localtunnel', '--port', String(port)], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const checkOutput = (data: Buffer) => {
      const text = data.toString('utf8');
      const match = text.match(/https:\/\/[a-zA-Z0-9-]+\.loca\.lt/);
      if (match && !settled) {
        settled = true;
        clearTimeout(timeout);
        resolve({
          url: match[0],
          provider: 'localtunnel',
          process: child,
          stop: async () => {
            child.kill('SIGTERM');
          },
        });
      }
    };

    child.stdout.on('data', checkOutput);
    child.stderr.on('data', checkOutput);

    child.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`Failed to launch localtunnel: ${err.message}`));
      }
    });

    child.on('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`localtunnel exited with code ${code}`));
      }
    });
  });
}

async function launchCustomTunnel(
  commandStr: string,
  port: number,
  timeoutMs: number,
): Promise<TunnelInstance> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let childProcess: ChildProcess | null = null;

    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        try {
          if (childProcess) childProcess.kill('SIGKILL');
        } catch {
          // Ignore kill errors
        }
        reject(new Error(`Custom tunnel command timed out after ${timeoutMs}ms.`));
      }
    }, timeoutMs);

    const replaced = commandStr.replace(/\{port\}/g, String(port));
    const parts = replaced.split(' ');
    const bin = parts[0] ?? 'node';
    const args = parts.slice(1);
    const child: ChildProcess = spawn(bin, args);
    childProcess = child;

    const checkOutput = (data: Buffer) => {
      const text = data.toString('utf8');
      const match = text.match(/https:\/\/[^\s]+/);
      if (match && !settled) {
        settled = true;
        clearTimeout(timeout);
        resolve({
          url: match[0],
          provider: 'custom',
          process: child,
          stop: async () => {
            child.kill('SIGTERM');
          },
        });
      }
    };

    if (child.stdout) child.stdout.on('data', checkOutput);
    if (child.stderr) child.stderr.on('data', checkOutput);

    child.on('error', (err: Error) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`Failed to execute custom tunnel command: ${err.message}`));
      }
    });
  });
}
