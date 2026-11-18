/**
 * Embedded Web Inspector UI for Webhook Reliability Workbench.
 * Self-contained HTML/CSS/JavaScript with zero runtime dependencies.
 */
export function renderInspectorHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Webhook Reliability Workbench — Live Inspector</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-hover: #0284c7;
      --success: #22c55e;
      --error: #ef4444;
      --warning: #f59e0b;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      height: 100vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    header {
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      padding: 12px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .logo {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 700;
      font-size: 1.1rem;
      letter-spacing: -0.02em;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.8rem;
      padding: 4px 10px;
      border-radius: 9999px;
      background: rgba(34, 197, 94, 0.15);
      color: var(--success);
      border: 1px solid rgba(34, 197, 94, 0.3);
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: currentColor;
    }
    main {
      flex: 1;
      display: grid;
      grid-template-columns: 380px 1fr;
      overflow: hidden;
    }
    .sidebar {
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      background: rgba(15, 23, 42, 0.5);
    }
    .sidebar-header {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.85rem;
      color: var(--text-muted);
    }
    .event-list {
      flex: 1;
      overflow-y: auto;
      list-style: none;
    }
    .event-item {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      transition: background 0.15s;
    }
    .event-item:hover { background: rgba(51, 65, 85, 0.4); }
    .event-item.active { background: var(--card-bg); border-left: 3px solid var(--accent); }
    .event-item-top {
      display: flex;
      justify-content: space-between;
      margin-bottom: 4px;
      font-size: 0.85rem;
    }
    .method-badge {
      font-weight: 700;
      color: var(--accent);
      font-family: var(--font-mono);
    }
    .path-text { font-family: var(--font-mono); color: var(--text); }
    .event-time { font-size: 0.75rem; color: var(--text-muted); }
    .details {
      padding: 24px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    .details-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px;
    }
    .details-card h3 {
      font-size: 0.95rem;
      margin-bottom: 12px;
      color: var(--accent);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    pre {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-family: var(--font-mono);
      font-size: 0.82rem;
    }
    th, td {
      padding: 8px 10px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    th { color: var(--text-muted); font-weight: 600; width: 35%; }
    .replay-bar {
      display: flex;
      gap: 10px;
      margin-top: 10px;
    }
    input[type="text"] {
      flex: 1;
      background: #090d16;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 0.85rem;
    }
    button {
      background: var(--accent);
      color: #090d16;
      font-weight: 600;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      transition: background 0.15s;
    }
    button:hover { background: var(--accent-hover); }
    .empty-state {
      padding: 40px;
      text-align: center;
      color: var(--text-muted);
    }
  </style>
</head>
<body>
  <header>
    <div class="logo">
      <span>⚡</span> Webhook Reliability Workbench
    </div>
    <div class="status-badge" id="connStatus">
      <span class="status-dot"></span> Live SSE Connected
    </div>
  </header>

  <main>
    <div class="sidebar">
      <div class="sidebar-header">
        <span>Captured Events (<span id="eventCount">0</span>)</span>
        <span style="font-size: 0.75rem;">Auto-scroll enabled</span>
      </div>
      <ul class="event-list" id="eventList">
        <li class="empty-state">Waiting for incoming webhooks...</li>
      </ul>
    </div>

    <div class="details" id="eventDetails">
      <div class="empty-state" style="margin-top: 80px;">
        <h3>Select an event to inspect its headers and payload</h3>
        <p style="margin-top: 8px;">Incoming deliveries will stream here in real-time.</p>
      </div>
    </div>
  </main>

  <script>
    const events = [];
    let selectedEventId = null;
    const eventList = document.getElementById('eventList');
    const eventDetails = document.getElementById('eventDetails');
    const eventCount = document.getElementById('eventCount');

    function renderList() {
      if (events.length === 0) {
        eventList.innerHTML = '<li class="empty-state">Waiting for incoming webhooks...</li>';
        eventCount.textContent = '0';
        return;
      }
      eventCount.textContent = events.length;
      eventList.innerHTML = events.map(evt => {
        const isActive = evt.id === selectedEventId ? 'active' : '';
        const sigBadge = evt.signature ? (evt.signature.valid ? '✓ HMAC' : '✗ Sig') : '';
        return \`
          <li class="event-item \${isActive}" onclick="selectEvent('\${evt.id}')">
            <div class="event-item-top">
              <span class="method-badge">\${evt.method}</span>
              <span class="path-text">\${evt.path}</span>
              <span style="color: \${evt.responseStatus >= 400 ? 'var(--error)' : 'var(--success)'}">\${evt.responseStatus}</span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span class="event-time">\${new Date(evt.timestamp).toLocaleTimeString()}</span>
              \${sigBadge ? \`<span style="font-size: 0.7rem; color: \${evt.signature.valid ? 'var(--success)' : 'var(--error)'}">\${sigBadge}</span>\` : ''}
            </div>
          </li>
        \`;
      }).join('');
    }

    function selectEvent(id) {
      selectedEventId = id;
      renderList();
      const evt = events.find(e => e.id === id);
      if (!evt) return;

      const headerRows = Object.entries(evt.headers || {}).map(([k, v]) => \`
        <tr>
          <th>\${k}</th>
          <td>\${Array.isArray(v) ? v.join(', ') : v}</td>
        </tr>
      \`).join('');

      eventDetails.innerHTML = \`
        <div class="details-card">
          <h3>Event Overview: \${evt.id}</h3>
          <table>
            <tr><th>Timestamp</th><td>\${evt.timestamp}</td></tr>
            <tr><th>HTTP Method</th><td>\${evt.method}</td></tr>
            <tr><th>Path</th><td>\${evt.path}</td></tr>
            <tr><th>Response Code</th><td>\${evt.responseStatus}</td></tr>
            <tr><th>Payload Size</th><td>\${evt.contentLength} bytes</td></tr>
            \${evt.signature ? \`<tr><th>Signature Check</th><td style="color: \${evt.signature.valid ? 'var(--success)' : 'var(--error)'}">\${evt.signature.valid ? 'Valid (' + evt.signature.algorithm + ')' : 'Invalid: ' + evt.signature.reason}</td></tr>\` : ''}
          </table>

          <div style="margin-top: 16px;">
            <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted);">Replay to Destination URL:</label>
            <div class="replay-bar">
              <input type="text" id="replayUrlInput" value="http://127.0.0.1:3000/api/webhooks" />
              <button onclick="triggerReplay('\${evt.id}')">Replay Now</button>
            </div>
            <div id="replayResult" style="margin-top: 8px; font-size: 0.85rem; font-family: var(--font-mono);"></div>
          </div>
        </div>

        <div class="details-card">
          <h3>Request Headers</h3>
          <table>\${headerRows}</table>
        </div>

        <div class="details-card">
          <h3>Payload Body</h3>
          <pre>\${evt.body ? JSON.stringify(evt.body, null, 2) : evt.rawBody || '(empty body)'}</pre>
        </div>
      \`;
    }

    async function triggerReplay(eventId) {
      const url = document.getElementById('replayUrlInput').value.trim();
      const resElem = document.getElementById('replayResult');
      resElem.textContent = 'Replaying...';
      resElem.style.color = 'var(--accent)';

      try {
        const resp = await fetch('/__workbench/replay', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ eventId, destination: url, allowLoopback: true })
        });
        const data = await resp.json();
        if (data.success) {
          resElem.textContent = \`✓ Replayed successfully: Status \${data.status} (\${data.durationMs}ms)\`;
          resElem.style.color = 'var(--success)';
        } else {
          resElem.textContent = \`✗ Replay failed: \${data.statusText || data.error}\`;
          resElem.style.color = 'var(--error)';
        }
      } catch (err) {
        resElem.textContent = \`✗ Replay error: \${err.message}\`;
        resElem.style.color = 'var(--error)';
      }
    }

    // Connect to Server-Sent Events stream
    const sse = new EventSource('/__workbench/stream');
    sse.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data);
        events.unshift(evt);
        if (!selectedEventId) {
          selectEvent(evt.id);
        } else {
          renderList();
        }
      } catch (e) {
        console.error('SSE parse error', e);
      }
    };
    sse.onerror = () => {
      document.getElementById('connStatus').innerHTML = '<span class="status-dot" style="background: var(--error)"></span> Disconnected';
      document.getElementById('connStatus').style.color = 'var(--error)';
    };
  </script>
</body>
</html>`;
}
