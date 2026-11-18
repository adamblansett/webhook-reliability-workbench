import { describe, it, expect } from 'vitest';
import { startTunnel } from '../src/tunnel/manager.js';

describe('Ingress Tunnel Manager', () => {
  it('launches and parses URL from custom tunnel command', async () => {
    // Spawn a node one-liner that outputs an https tunnel URL
    const nodeCmd = `node -e console.log("https://test-subdomain.mocktunnel.net")`;
    const tunnel = await startTunnel({
      port: 8787,
      customCommand: nodeCmd,
      timeoutMs: 2000,
    });

    expect(tunnel.url).toBe('https://test-subdomain.mocktunnel.net');
    expect(tunnel.provider).toBe('custom');
    await tunnel.stop();
  });

  it('rejects gracefully when an unknown provider is specified', async () => {
    await expect(
      // @ts-expect-error testing invalid provider
      startTunnel({ port: 8787, provider: 'nonexistent-tunnel' }),
    ).rejects.toThrow('Unsupported tunnel provider');
  });
});
