import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { executeScenarioSuite, TestScenario } from '../src/testing/suite.js';

describe('Declarative CI/CD Webhook Test Suite', () => {
  let server: http.Server;
  let serverPort: number;
  let receivedEvents: Array<{ headers: http.IncomingHttpHeaders; body: string }> = [];

  beforeAll(async () => {
    receivedEvents = [];
    server = http.createServer(async (req, res) => {
      let body = '';
      req.on('data', (c) => (body += c.toString('utf8')));
      req.on('end', () => {
        receivedEvents.push({ headers: req.headers, body });

        // Simulate app logic: reject if signature header contains 'invalid'
        const sig = req.headers['stripe-signature'] || req.headers['x-hub-signature-256'];
        if (typeof sig === 'string' && sig.includes('invalid')) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid HMAC signature' }));
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, processed: true }));
      });
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        serverPort = typeof addr === 'object' && addr ? addr.port : 8999;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('executes scenario suite and succeeds when all expectations are met', async () => {
    const scenario: TestScenario = {
      name: 'Stripe Webhook Integration Suite',
      target: `http://127.0.0.1:${serverPort}/webhooks`,
      allowLoopback: true,
      steps: [
        {
          name: 'Step 1: Valid Stripe payment triggers success',
          action: 'trigger',
          preset: 'stripe',
          event: 'payment_intent.succeeded',
          expect: {
            status: 200,
            bodyContains: '"processed":true',
          },
        },
        {
          name: 'Step 2: Short delay step',
          action: 'delay',
          delayMs: 20,
        },
        {
          name: 'Step 3: Tampered signature is rejected with 400',
          action: 'trigger',
          preset: 'stripe',
          event: 'payment_intent.succeeded',
          tamper: {
            signature: 'invalid_tampered_signature',
          },
          expect: {
            status: 400,
            bodyContains: 'Invalid HMAC signature',
          },
        },
      ],
    };

    const result = await executeScenarioSuite(scenario);

    expect(result.allPassed).toBe(true);
    expect(result.totalSteps).toBe(3);
    expect(result.passedSteps).toBe(3);
    expect(result.failedSteps).toBe(0);
  });

  it('accurately reports assertion failures when response does not match expectation', async () => {
    const scenario: TestScenario = {
      name: 'Failing Scenario Test',
      target: `http://127.0.0.1:${serverPort}/webhooks`,
      allowLoopback: true,
      steps: [
        {
          name: 'Step Expecting 500 error',
          action: 'trigger',
          preset: 'github',
          event: 'push',
          expect: {
            status: 500, // actual is 200
          },
        },
      ],
    };

    const result = await executeScenarioSuite(scenario);

    expect(result.allPassed).toBe(false);
    expect(result.passedSteps).toBe(0);
    expect(result.failedSteps).toBe(1);
    expect(result.stepResults[0]?.failures[0]?.expected).toBe(500);
    expect(result.stepResults[0]?.failures[0]?.actual).toBe(200);
  });
});
