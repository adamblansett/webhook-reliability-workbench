import { describe, it, expect } from 'vitest';
import { TerminalDashboard } from '../src/tui/dashboard.js';
import { InMemoryEventStore } from '../src/events/store.js';

describe('Terminal Dashboard', () => {
  it('instantiates and handles non-TTY gracefully', async () => {
    const store = new InMemoryEventStore();
    const dashboard = new TerminalDashboard({
      port: 8787,
      host: '127.0.0.1',
      path: '/webhooks',
      store,
    });

    expect(dashboard).toBeDefined();
    // In non-TTY environment (vitest runner), start() returns safely without crashing
    await dashboard.start();
    dashboard.stop();
  });
});
