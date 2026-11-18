# Webhook Reliability Workbench

> A local-first developer tool for capturing, inspecting, validating, replaying, and testing webhook integrations without relying on third-party webhook services.

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue.svg)](https://www.typescriptlang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

Third-party webhooks (from payment gateways, authentication providers, source control, etc.) are notoriously tricky to integrate and debug. Integration issues frequently arise from:

- **Invalid HMAC signatures** and mismatched signing algorithms or prefixes
- **Malformed payloads** or unexpected headers
- **HTTP error responses** (4xx / 5xx) returned by recipient endpoints
- **Slow responses and timeouts** triggering unpredictable retry loops
- **Retry storms & duplicate deliveries** causing idempotency bugs
- **Changed payload schemas** breaking downstream consumers
- **Misconfigured webhook destinations** leaking events or credentials

**Webhook Reliability Workbench** runs entirely on your local machine. It captures incoming webhook HTTP deliveries, verifies cryptographic HMAC signatures, stores detailed event histories across CLI sessions, exports portable fixtures, simulates integration failures, and safely replays requests to local development endpoints with strict Server-Side Request Forgery (SSRF) protections.

---

## Comparison: Webhook Reliability Workbench vs. API Contract Testers

| Dimension             | API Contract Testing Tools                            | Webhook Reliability Workbench                                            |
| :-------------------- | :---------------------------------------------------- | :----------------------------------------------------------------------- |
| **Primary Direction** | Outgoing API client calls to target REST/GraphQL APIs | Incoming webhook deliveries from external/mock senders                   |
| **Focus**             | Schema contract conformity & response assertion       | Delivery reliability, signature verification, duplicate events & retries |
| **Simulation**        | Mock API responses to client requests                 | Simulated receiver failures (HTTP status codes, latency injection)       |
| **Security Controls** | Client request credential headers                     | SSRF destination safeguards, IP resolution checks, secret redaction      |
| **Workflow**          | CI/CD contract validation test suites                 | Interactive local debugging, event inspection, and replay experiments    |

---

## Prerequisites

- **Node.js**: `v20.0.0` or higher
- **npm**: `v10.0.0` or higher

---

## Installation & Setup

### Development Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/adamblansett/webhook-reliability-workbench.git
cd webhook-reliability-workbench
npm install
```

### Build & Test

```bash
# Typecheck TypeScript codebase
npm run typecheck

# Run linter
npm run lint

# Format check
npm run format:check

# Run Vitest test suite
npm test

# Run test suite with full v8 coverage report
npm run test:coverage

# Build production bundle in ./dist
npm run build

# Run all verification checks
npm run verify
```

---

## CLI Reference

The installed executable is named `webhook-workbench`.

```bash
webhook-workbench [options] [command]
```

### Commands

| Command                      | Description                                                              |
| :--------------------------- | :----------------------------------------------------------------------- |
| `listen`                     | Start local receiver with tunneling, chaos simulation, web/TUI dashboard |
| `events list`                | List captured webhook events in store                                    |
| `events show <eventId>`      | Inspect detailed metadata and payload of an event                        |
| `events diff <id1> <id2>`    | Compare two captured webhook events side-by-side                         |
| `events tail`                | Stream live incoming webhook events via Server-Sent Events (SSE)         |
| `events curl <eventId>`      | Generate executable cURL command line for a captured event               |
| `events types <eventId>`     | Infer and generate TypeScript interfaces or Zod schemas from payload     |
| `events validate <eventId>`  | Validate a captured event payload against a JSON Schema file             |
| `events clear`               | Clear stored event history                                               |
| `trigger <provider> <event>` | Generate and send synthetic provider webhooks or curl commands           |
| `fuzz <eventId>`             | Run payload mutation stress testing against consumer endpoints           |
| `test-suite <scenarioFile>`  | Run declarative webhook integration & idempotency scenario suites        |
| `replay <eventId>`           | Replay a captured event to a destination URL                             |
| `test-retries <eventId>`     | Test retry behavior and duplicate handling across multiple attempts      |
| `fixtures export <eventId>`  | Export a captured event as a portable JSON fixture file                  |
| `fixtures validate <file>`   | Validate a JSON fixture file against the Workbench schema                |
| `fixtures import <file>`     | Import a fixture file as a captured event in local store                 |
| `config show`                | View resolved configuration and runtime defaults                         |

---

## Core Workflows

### 1. Capturing and Inspecting Webhooks

Start the receiver on port `8787`:

```bash
webhook-workbench listen --port 8787 --path /webhooks
```

In another terminal or test script, send a webhook request:

```bash
curl -X POST http://127.0.0.1:8787/webhooks \
  -H "Content-Type: application/json" \
  -H "X-Custom-Token: secret_12345" \
  -d '{"event":"order.created","orderId":"ord_9901","amount":1500}'
```

List captured events:

```bash
webhook-workbench events list
```

Output:

```
Captured Webhook Events (1):
──────────────────────────────────────────────────────────────────────
evt_m1abc9_48fa  2026-10-10T18:23:21.000Z  POST /webhooks -> 200 (4ms)
──────────────────────────────────────────────────────────────────────
```

Inspect the event in detail:

```bash
webhook-workbench events show evt_m1abc9_48fa
```

Output:

```
=== Webhook Event: evt_m1abc9_48fa ===
Timestamp:        2026-10-10T18:23:21.000Z
HTTP Method:      POST
Path:             /webhooks
Response Status:  200
Duration:         4ms
Content Type:     application/json
Content Length:   58 bytes

Headers (Sensitive Values Redacted):
  content-type: application/json
  x-custom-token: [REDACTED]

Payload Body:
{
  "event": "order.created",
  "orderId": "ord_9901",
  "amount": 1500
}
```

View as machine-readable JSON:

```bash
webhook-workbench events show evt_m1abc9_48fa --json
```

---

### 2. Signature Verification & Provider Presets

Workbench supports HMAC (SHA-256, SHA-512, SHA-1), asymmetric Ed25519 digital signatures, and the emerging [Standard Webhooks](https://www.standardwebhooks.com/) specification.

#### Using Built-In Provider Presets

Instead of manually typing header names, prefixes, and algorithms, use `--preset`:

```bash
# Stripe (t=...,v1=... HMAC-SHA256)
webhook-workbench listen --port 8787 --preset stripe --secret "whsec_..."

# GitHub (x-hub-signature-256 sha256=... HMAC-SHA256)
webhook-workbench listen --port 8787 --preset github --secret "github_secret"

# Shopify (x-shopify-hmac-sha256 base64 HMAC-SHA256)
webhook-workbench listen --port 8787 --preset shopify --secret "shopify_secret"

# Slack (x-slack-signature v0=... with x-slack-request-timestamp)
webhook-workbench listen --port 8787 --preset slack --secret "slack_secret"

# Svix / Standard Webhooks (webhook-signature, webhook-timestamp, webhook-id)
webhook-workbench listen --port 8787 --preset svix --secret "whsec_..."
```

#### Manual Signature Configuration & Ed25519

You can also configure custom signature headers and algorithms:

```bash
# Custom HMAC-SHA256
webhook-workbench listen \
  --port 8787 \
  --secret "whsec_test_secret_key" \
  --signature-header "x-custom-signature" \
  --signature-prefix "sha256=" \
  --algorithm sha256

# Asymmetric Ed25519 Public Key Verification
webhook-workbench listen \
  --port 8787 \
  --secret "base64-or-spki-ed25519-public-key" \
  --signature-header "x-signature-ed25519" \
  --algorithm ed25519
```

Supported formats:

- **Prefix format**: `sha256=d3b07384...` (GitHub style)
- **Timestamped multi-part**: `t=1614555555,v1=5257a869...` (Stripe, Standard Webhooks)
- **Raw hex/base64 digests**: `d3b07384...` or `q8...=`
- **Ed25519 asymmetric signatures**: validated using Node crypto `verify(null, payload, publicKey, sig)`

Verification results are recorded using constant-time comparisons (`crypto.timingSafeEqual`) without exposing secret values.

---

### 3. Transparent Forwarding & Web Inspector UI

Act as a transparent reverse proxy between external webhooks and your local development server:

```bash
webhook-workbench listen \
  --port 8787 \
  --forward-to http://127.0.0.1:3000/api/webhooks \
  --forward-allow-loopback \
  --ui
```

- **Transparent Proxy**: Requests delivered to port `8787` are captured in the store and forwarded immediately to your app server. The app's response status code, latency, and body are recorded on the event as `forwardResult`.
- **Web Inspector Dashboard**: Access `http://127.0.0.1:8787/__workbench/ui` in your browser for a live, real-time dashboard of captured webhooks with one-click replaying and syntax highlighting.
- **Server-Sent Events (SSE)**: Connect any custom tool or client to `GET /__workbench/stream` to receive incoming events in real time.

---

### 4. Synthetic Mock Generator & Triggering

Test your application endpoints without needing live external provider accounts:

```bash
# List available provider templates
webhook-workbench trigger --list

# Send a synthetic Stripe payment_intent.succeeded webhook to your app
webhook-workbench trigger stripe payment_intent.succeeded \
  --url http://127.0.0.1:3000/api/webhooks \
  --secret "whsec_test"

# Output as a ready-to-run curl command
webhook-workbench trigger github push \
  --url http://127.0.0.1:3000/api/webhooks \
  --secret "test_secret" \
  --print-curl

# Output synthetic JSON payload directly
webhook-workbench trigger shopify orders/create --json
```

Supported mock templates:

- **Stripe**: `payment_intent.succeeded`, `charge.refunded`, `customer.subscription.created`
- **GitHub**: `push`, `pull_request`, `ping`
- **Shopify**: `orders/create`
- **Slack**: `app_mention`
- **Svix**: `user.created`

Run `webhook-workbench trigger --list` for the authoritative list.

---

### 5. Live Stream & Event Diffing

#### Live CLI Stream

Watch events arrive in real-time from your terminal:

```bash
webhook-workbench events tail --url http://127.0.0.1:8787/__workbench/stream
```

#### Event Diffing

Compare payloads, headers, or metadata between two captured events (e.g. initial attempt vs retry):

```bash
webhook-workbench events diff evt_001 evt_002
```

Displays colorized, side-by-side or contextual diffs for header modifications, timestamps, and payload field mutations.

---

### 6. Probabilistic Chaos Simulation & Ephemeral Ingress Tunnels

#### Chaos Injection

Simulate real-world upstream network instability, tail latency, and transient failures probabilistically:

```bash
# Injected 25% failure rate, 3000ms p95 latency spikes, and 5% abrupt connection drops
webhook-workbench listen \
  --port 8787 \
  --chaos \
  --failure-rate 0.25 \
  --latency-p95 3000 \
  --drop-rate 0.05
```

#### Ephemeral Public Ingress Tunneling

Expose your local workbench receiver to the public internet for webhook providers without manual port forwarding:

```bash
# Automatic Cloudflare Quick Tunnel (no account required)
webhook-workbench listen --port 8787 --tunnel

# Or explicitly select localtunnel
webhook-workbench listen --port 8787 --tunnel localtunnel
```

#### Interactive Terminal Dashboard (TUI)

Launch an interactive curses-style terminal UI:

```bash
webhook-workbench listen --port 8787 --tui
```

Navigate captured webhooks with arrow keys, press `r` to replay instantly to your app, `c` to copy cURL commands, and inspect payload and headers in real-time.

---

### 7. Code Generation & Contract Validation

#### Generate Executable cURL Commands

Extract any captured webhook event into a ready-to-run cURL command:

```bash
webhook-workbench events curl evt_m1abc9_48fa
```

#### Infer TypeScript & Zod Schemas

Automatically infer clean TypeScript interface definitions or Zod validation schemas from captured payloads:

```bash
# Infer TypeScript interfaces
webhook-workbench events types evt_m1abc9_48fa --format ts

# Infer Zod schema
webhook-workbench events types evt_m1abc9_48fa --format zod
```

#### JSON Schema & OpenAPI Contract Validation

Validate captured payloads against a JSON Schema file:

```bash
webhook-workbench events validate evt_m1abc9_48fa --schema schemas/order-event.json
```

---

### 8. Payload Fuzzing & Consumer Resilience Testing

Stress-test how your downstream webhook consumer handles malicious, unexpected, or mutated inputs:

```bash
webhook-workbench fuzz evt_m1abc9_48fa \
  --url http://127.0.0.1:3000/api/webhooks \
  --allow-loopback
```

Tests mutations including:

- Empty payload and malformed JSON
- Null byte injection and Unicode edge cases
- Large nested payloads and integer boundary overflows
- Header tampering and unknown extra fields

Generates a resilience score and identifies unhandled server crashes (HTTP 500) vs safe input rejections (HTTP 400/422).

---

### 9. Declarative Integration Scenario Suites (CI/CD)

Run reproducible, declarative webhook integration and idempotency test scenarios defined in YAML or JSON:

```yaml
# scenarios/payment-flow.yaml
name: Payment Webhook Flow & Idempotency Test
target: http://127.0.0.1:3000/api/webhooks
steps:
  - name: Initial payment succeeded
    action: trigger
    preset: stripe
    event: payment_intent.succeeded
    expect:
      status: 200

  - name: Duplicate delivery (idempotency test)
    action: replay
    expect:
      status: 200
```

Run in CI pipelines:

```bash
webhook-workbench test-suite scenarios/payment-flow.yaml
```

---

### 10. Replaying Captured Events

Replay captured events to local application servers during development:

```bash
webhook-workbench replay evt_m1abc9_48fa \
  --url http://127.0.0.1:3000/api/webhooks \
  --allow-loopback \
  --timeout 5000
```

#### Replay Features & Safeguards

- **SSRF Protection**: Replaying to loopback (`127.0.0.1`, `localhost`) or private networks requires explicit flags (`--allow-loopback`, `--allow-private`).
- **Credential Stripping**: By default, `Authorization`, `Cookie`, and stale signature headers are stripped to prevent credential leakage. Use `--keep-auth` or `--keep-signatures` if needed.
- **Header Overrides**: Add or modify headers using `--header "X-Debug-Mode: true"`.
- **Signature Regeneration**: Generate fresh HMAC signatures for the target using `--regenerate-signature --secret <secret>`.

---

### 11. Retry Testing & Duplicate Delivery

Verify that your application endpoint correctly handles duplicated webhooks and enforces idempotency:

```bash
webhook-workbench test-retries evt_m1abc9_48fa \
  --url http://127.0.0.1:3000/api/webhooks \
  --allow-loopback \
  --attempts 3 \
  --delay 500 \
  --exponential-backoff
```

Output:

```
=== Webhook Retry Test Summary ===
Event ID:            evt_m1abc9_48fa
Destination:         http://127.0.0.1:3000/api/webhooks
Total Attempts:      3
Successful:          3
Failed:              0
Latency (Min/Avg/Max): 12ms / 15ms / 18ms

Attempt Breakdown:
──────────────────────────────────────────────────────────────────────
Attempt #1: Status 200 [SUCCESS] (18ms)
Attempt #2 (after 500ms delay): Status 200 [SUCCESS] (15ms)
Attempt #3 (after 1000ms delay): Status 200 [SUCCESS] (12ms)
──────────────────────────────────────────────────────────────────────
```

---

### 12. Portable Payload Fixtures

Export captured events into version-controlled fixture files for regression testing:

```bash
# Export fixture
webhook-workbench fixtures export evt_m1abc9_48fa \
  --output fixtures/order-created.json \
  --name "order-created" \
  --description "Sample payment webhook event"

# Validate fixture
webhook-workbench fixtures validate fixtures/order-created.json

# Re-import fixture into event store
webhook-workbench fixtures import fixtures/order-created.json
```

---

### 13. SQLite Event Store (Library API)

The CLI uses the file-backed JSON store. When embedding Workbench as a library, you can opt into an indexed SQLite backend:

```ts
import { createDefaultStore } from 'webhook-reliability-workbench';

const store = createDefaultStore({
  type: 'sqlite',
  filePath: '.workbench/events.sqlite',
});
```

Features:

- Backed by Node's built-in `node:sqlite` module (**requires Node.js ≥ 22.5**; `node:sqlite` is still marked experimental). On older runtimes it fails with a clear error — use the file or memory store instead.
- Indexed by event ID and insertion order.
- Automatic FIFO capacity eviction when the maximum event count is reached.
- Not yet selectable from the CLI.

---

## Security Model

Security is a primary design goal:

1. **Loopback Binding by Default**: The receiver binds strictly to `127.0.0.1`. Binding to external interfaces (e.g. `0.0.0.0`) requires `--allow-external` and prints an explicit warning.
2. **SSRF Safeguards on Replay**:
   - Replay destinations are validated with DNS resolution checks.
   - Cloud metadata IPs (`169.254.169.254`, `metadata.google.internal`) are unconditionally blocked.
   - Loopback and private RFC 1918 IPs require explicit opt-in (`--allow-loopback`, `--allow-private`).
   - URLs with embedded credentials (`user:pass@host`) or non-HTTP protocols are rejected.
3. **Sensitive Data Redaction**:
   - Passwords, authorization tokens, API keys, cookies, and signing secrets are redacted (`[REDACTED]`) in terminal output, logs, and exported fixtures.
   - The original event payload is never mutated for display purposes.
4. **Request Body Safety**:
   - Streaming body reader enforces configurable size limits (default: 1 MiB, max: 50 MiB).
   - Rejects oversized payloads with HTTP 413 Payload Too Large.
5. **Path Traversal Protection**:
   - Fixture paths are validated to block directory traversal and null bytes.
   - Overwriting existing files requires `--overwrite`.

---

## Configuration Reference

Workbench resolves configuration in order of precedence:
`CLI Flags > Environment Variables > Config File (.workbenchrc.json) > Defaults`

### Environment Variables

| Variable                     | Description                                      |
| :--------------------------- | :----------------------------------------------- |
| `WORKBENCH_PORT`             | Default receiver listening port (e.g. `8787`)    |
| `WORKBENCH_HOST`             | Default receiver bind address (e.g. `127.0.0.1`) |
| `WORKBENCH_PATH`             | Default webhook path (e.g. `/webhooks`)          |
| `WORKBENCH_SIGNATURE_HEADER` | Default signature header name                    |
| `WORKBENCH_STORE_FILE`       | Path to file-backed event store                  |

---

## Current Limitations & Roadmap

### Current Limitations

- Supports HTTP/HTTPS webhook deliveries and replays (gRPC webhook transports not supported).
- Replays must be HTTP/HTTPS destinations.

### Roadmap

- OpenAPI & JSON Schema validation against captured event bodies
- Full curses/Ink-based interactive terminal UI (TUI)
- Out-of-band alerting (Slack, Discord notification when signature validation fails)

---

## ⚖️ Legal Disclaimer & Limitation of Liability

### 1. "AS IS" and Express Warranty Disclaimer

This software, documentation, receiver daemon, cryptographic signing utilities, and webhook simulation tools are provided on an **"AS IS"** and **"AS AVAILABLE"** basis, **WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND**, either express, implied, statutory, or otherwise. To the maximum extent permitted by applicable law, the author, copyright holders, and contributors expressly disclaim all warranties, including but not limited to implied warranties of merchantability, fitness for a particular purpose, title, quiet enjoyment, and non-infringement.

### 2. Webhook Replay & Duplicate Financial Transaction Warning

- **Side Effects and Financial Impact:** Webhooks commonly trigger downstream state mutations—including payment processing, charge refunds, order creation, inventory allocation, account provisioning, or transactional emails/SMS. Replaying webhooks against live production environments, staging environments connected to live gateways, or non-idempotent endpoints can cause **duplicate credit card charges, unauthorized refunds, duplicate shipments, or corrupted account state**.
- **User Responsibility for Idempotency:** The user is solely responsible for ensuring that any target endpoint implements adequate idempotency controls, and that simulated or replayed events are routed exclusively to safe, authorized development environments.
- The author and contributors shall not be liable for any financial losses, duplicate transactions, billing disputes, inventory discrepancies, or unintended customer communications resulting from replayed or simulated webhook events.

### 3. Network Authorization & SSRF Prevention

- Users must only send, forward, or replay webhooks to network endpoints and IP addresses they own or are explicitly authorized to test.
- This workbench is designed for local development and integration testing; it is **NOT** a distributed, hardened, production-grade message broker (such as Apache Kafka, RabbitMQ, or AWS SQS) and must not be used as an enterprise message queue for mission-critical infrastructure.

### 4. Limitation of Liability

To the maximum extent permitted by applicable law, **IN NO EVENT SHALL THE AUTHOR, COPYRIGHT HOLDERS, OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, PUNITIVE, OR CONSEQUENTIAL DAMAGES** (including, but not limited to, loss of use, data, revenue, profits, business, or goodwill; duplicate financial charges; inventory loss; downtime; or procurement of substitute goods or services), however caused and on any theory of liability, whether in contract, strict liability, tort (including negligence or otherwise), or statute, arising in any way out of the use, reproduction, modification, distribution, or reliance upon this software, even if advised of the possibility of such damages.

### 5. Third-Party Trademarks & Non-Affiliation

All product names, logos, brands, and registered trademarks mentioned within this project (including Stripe, GitHub, Shopify, Slack, Twilio, Node.js, and Vitest) are the property of their respective owners. Mention of these entities does not imply endorsement, sponsorship, or affiliation with the author.

---

## License

[MIT](LICENSE) © 2026 Adam Blansett
