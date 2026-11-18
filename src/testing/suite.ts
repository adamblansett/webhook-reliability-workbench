import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import type { EventStore, WebhookEvent } from '../events/types.js';
import { generateSyntheticWebhook } from './generator.js';
import { validateDestinationUrl, createSsrfLookup } from '../security/ssrf.js';
import { resolveSafePath } from '../security/path.js';

export interface TestScenarioExpectation {
  status?: number;
  bodyContains?: string;
  bodyMatch?: Record<string, unknown>;
  maxDurationMs?: number;
}

export interface TestScenarioStep {
  name: string;
  action: 'trigger' | 'replay' | 'delay';
  preset?: string;
  event?: string;
  eventId?: string;
  fixturePath?: string;
  target?: string;
  delayMs?: number;
  secret?: string;
  tamper?: {
    signature?: string;
    body?: string | Record<string, unknown>;
    headers?: Record<string, string>;
  };
  headers?: Record<string, string>;
  expect?: TestScenarioExpectation;
}

export interface TestScenario {
  name: string;
  description?: string;
  target?: string;
  allowLoopback?: boolean;
  allowPrivate?: boolean;
  secret?: string;
  steps: TestScenarioStep[];
}

export interface StepAssertionFailure {
  assertion: string;
  expected: unknown;
  actual: unknown;
  message: string;
}

export interface StepExecutionResult {
  stepIndex: number;
  name: string;
  action: string;
  passed: boolean;
  durationMs: number;
  status?: number;
  responseBodySnippet?: string;
  failures: StepAssertionFailure[];
  error?: string;
}

export interface ScenarioSuiteResult {
  scenarioName: string;
  totalSteps: number;
  passedSteps: number;
  failedSteps: number;
  allPassed: boolean;
  durationMs: number;
  stepResults: StepExecutionResult[];
}

/**
 * Loads a scenario from a JSON or basic YAML file.
 */
export async function loadScenarioFile(filePath: string): Promise<TestScenario> {
  const resolved = resolveSafePath(filePath);
  const raw = await fs.readFile(resolved, 'utf8');

  if (filePath.endsWith('.json')) {
    return JSON.parse(raw) as TestScenario;
  }

  // Basic JSON fallback or parse if JSON syntax
  try {
    return JSON.parse(raw) as TestScenario;
  } catch {
    // If simple YAML, convert key values
    return parseBasicYaml(raw);
  }
}

/**
 * Executes a declarative scenario test suite.
 */
export async function executeScenarioSuite(
  scenario: TestScenario,
  store?: EventStore,
): Promise<ScenarioSuiteResult> {
  const suiteStartTime = Date.now();
  const stepResults: StepExecutionResult[] = [];
  const defaultTarget = scenario.target ?? 'http://127.0.0.1:3000/api/webhooks';
  const allowLoopback = scenario.allowLoopback ?? true;
  const allowPrivate = scenario.allowPrivate ?? false;
  const defaultSecret = scenario.secret ?? 'whsec_test_secret_key_123';

  let lastDispatchedEvent: WebhookEvent | null = null;

  for (let i = 0; i < scenario.steps.length; i++) {
    const step = scenario.steps[i];
    if (!step) continue;
    const stepStartTime = Date.now();
    const failures: StepAssertionFailure[] = [];

    // Action 1: Delay
    if (step.action === 'delay') {
      const ms = step.delayMs ?? 1000;
      await new Promise((resolve) => setTimeout(resolve, ms));
      stepResults.push({
        stepIndex: i + 1,
        name: step.name,
        action: 'delay',
        passed: true,
        durationMs: Date.now() - stepStartTime,
        failures: [],
      });
      continue;
    }

    // Resolve target and payload
    const targetUrl = step.target ?? defaultTarget;
    let requestHeaders: Record<string, string> = { ...step.headers };
    let requestBody = '';

    try {
      if (step.action === 'trigger') {
        const provider = step.preset ?? 'stripe';
        const eventType = step.event ?? 'payment_intent.succeeded';
        const synthetic = generateSyntheticWebhook(provider, eventType, {
          secret: step.secret ?? defaultSecret,
        });

        requestHeaders = { ...synthetic.headers, ...requestHeaders };
        requestBody = synthetic.rawBody;

        // Apply tampering if specified
        if (step.tamper) {
          if (step.tamper.headers) {
            Object.assign(requestHeaders, step.tamper.headers);
          }
          if (step.tamper.signature) {
            // Find signature header
            const sigHeader = Object.keys(requestHeaders).find(
              (h) =>
                h.includes('signature') ||
                h.includes('webhook') ||
                h.includes('signature-256'),
            );
            if (sigHeader) {
              requestHeaders[sigHeader] = step.tamper.signature;
            }
          }
          if (step.tamper.body) {
            requestBody =
              typeof step.tamper.body === 'string'
                ? step.tamper.body
                : JSON.stringify(step.tamper.body);
          }
        }
      } else if (step.action === 'replay') {
        let eventToReplay: WebhookEvent | null = null;
        if (step.eventId && store) {
          eventToReplay = await store.get(step.eventId);
        } else if (step.fixturePath) {
          const rawFixture = await fs.readFile(
            path.resolve(process.cwd(), step.fixturePath),
            'utf8',
          );
          const fixtureData = JSON.parse(rawFixture);
          eventToReplay = fixtureData.event ?? fixtureData;
        } else {
          eventToReplay = lastDispatchedEvent;
        }

        if (!eventToReplay) {
          throw new Error(`Replay step "${step.name}" has no available event source.`);
        }

        for (const [k, v] of Object.entries(eventToReplay.headers || {})) {
          if (k.toLowerCase() !== 'host' && k.toLowerCase() !== 'content-length') {
            requestHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
          }
        }
        requestBody = eventToReplay.rawBody;

        if (step.tamper?.signature) {
          const sigHeader = Object.keys(requestHeaders).find((h) =>
            h.includes('signature'),
          );
          if (sigHeader) requestHeaders[sigHeader] = step.tamper.signature;
        }
      }

      // Execute HTTP request
      const validated = await validateDestinationUrl(targetUrl, {
        allowLoopback,
        allowPrivate,
      });

      const isHttps = validated.url.protocol === 'https:';
      const transport = isHttps ? https : http;
      const cleanHost = validated.url.hostname.replace(/^\[|\]$/g, '');
      const lookup = createSsrfLookup({ allowLoopback, allowPrivate });

      const res = await new Promise<{ status: number; body: string }>(
        (resolve, reject) => {
          const reqOptions: http.RequestOptions = {
            method: 'POST',
            hostname: cleanHost,
            port: validated.url.port || (isHttps ? 443 : 80),
            path: `${validated.url.pathname}${validated.url.search}`,
            headers: {
              ...requestHeaders,
              'content-length': Buffer.byteLength(requestBody),
            },
            lookup,
            timeout: 5000,
          };

          const req = transport.request(reqOptions, (httpRes) => {
            let resBody = '';
            httpRes.on('data', (c) => (resBody += c.toString('utf8')));
            httpRes.on('end', () => {
              resolve({ status: httpRes.statusCode ?? 0, body: resBody });
            });
          });

          req.on('error', reject);
          req.on('timeout', () => req.destroy(new Error('Request timed out')));
          req.write(requestBody);
          req.end();
        },
      );

      const stepDuration = Date.now() - stepStartTime;

      if (step.action === 'trigger') {
        let parsedBody: unknown = null;
        try {
          parsedBody = JSON.parse(requestBody);
        } catch {
          parsedBody = requestBody;
        }
        lastDispatchedEvent = {
          id: `evt_suite_${Date.now()}`,
          timestamp: new Date().toISOString(),
          method: 'POST',
          path: validated.url.pathname,
          headers: requestHeaders,
          query: {},
          rawBody: requestBody,
          body: parsedBody,
          isJson: typeof parsedBody === 'object' && parsedBody !== null,
          jsonError: null,
          contentType: 'application/json',
          contentLength: Buffer.byteLength(requestBody),
          responseStatus: res.status,
          durationMs: stepDuration,
          signature: null,
          replays: [],
        };
      }

      // Evaluate Assertions
      if (step.expect) {
        if (step.expect.status !== undefined && res.status !== step.expect.status) {
          failures.push({
            assertion: 'status',
            expected: step.expect.status,
            actual: res.status,
            message: `Expected HTTP status ${step.expect.status}, got ${res.status}`,
          });
        }

        if (step.expect.bodyContains && !res.body.includes(step.expect.bodyContains)) {
          failures.push({
            assertion: 'bodyContains',
            expected: step.expect.bodyContains,
            actual: res.body.slice(0, 200),
            message: `Response body did not contain substring "${step.expect.bodyContains}"`,
          });
        }

        if (step.expect.maxDurationMs && stepDuration > step.expect.maxDurationMs) {
          failures.push({
            assertion: 'maxDurationMs',
            expected: `< ${step.expect.maxDurationMs}ms`,
            actual: `${stepDuration}ms`,
            message: `Step exceeded maximum duration (${stepDuration}ms > ${step.expect.maxDurationMs}ms)`,
          });
        }
      }

      stepResults.push({
        stepIndex: i + 1,
        name: step.name,
        action: step.action,
        passed: failures.length === 0,
        durationMs: stepDuration,
        status: res.status,
        responseBodySnippet: res.body.slice(0, 300),
        failures,
      });
    } catch (stepErr: unknown) {
      stepResults.push({
        stepIndex: i + 1,
        name: step.name,
        action: step.action,
        passed: false,
        durationMs: Date.now() - stepStartTime,
        failures: [],
        error: stepErr instanceof Error ? stepErr.message : String(stepErr),
      });
    }
  }

  const passedSteps = stepResults.filter((s) => s.passed).length;
  const failedSteps = stepResults.length - passedSteps;

  return {
    scenarioName: scenario.name,
    totalSteps: scenario.steps.length,
    passedSteps,
    failedSteps,
    allPassed: failedSteps === 0,
    durationMs: Date.now() - suiteStartTime,
    stepResults,
  };
}

/**
 * Lightweight YAML parser for simple test scenario files without external dependencies.
 */
function parseBasicYaml(yamlStr: string): TestScenario {
  const trimmed = yamlStr.trim();
  if (trimmed.startsWith('{')) {
    return JSON.parse(trimmed) as TestScenario;
  }

  const lines = yamlStr.split('\n');
  const steps: TestScenarioStep[] = [];
  let scenarioName = 'Webhook Test Scenario';
  let scenarioTarget: string | undefined;
  let currentStep: TestScenarioStep | null = null;

  for (const line of lines) {
    const clean = line.trim();
    if (!clean || clean.startsWith('#')) continue;

    if (clean.startsWith('name:')) {
      const val = clean
        .replace('name:', '')
        .trim()
        .replace(/^['"]|['"]$/g, '');
      if (!currentStep) {
        scenarioName = val;
      } else {
        currentStep.name = val;
      }
    } else if (clean.startsWith('target:')) {
      const val = clean
        .replace('target:', '')
        .trim()
        .replace(/^['"]|['"]$/g, '');
      if (!currentStep) {
        scenarioTarget = val;
      } else {
        currentStep.target = val;
      }
    } else if (clean.startsWith('- name:') || clean.startsWith('- action:')) {
      currentStep = { name: '', action: 'trigger', expect: {} };
      steps.push(currentStep);
      const colonIdx = clean.indexOf(':');
      if (colonIdx > 0) {
        const k = clean.slice(2, colonIdx).trim();
        const v = clean
          .slice(colonIdx + 1)
          .trim()
          .replace(/^['"]|['"]$/g, '');
        if (k === 'name') currentStep.name = v;
        if (k === 'action') currentStep.action = v as 'trigger' | 'replay' | 'delay';
      }
    } else if (currentStep && clean.includes(':')) {
      const colonIdx = clean.indexOf(':');
      const key = clean.slice(0, colonIdx).trim();
      const val = clean
        .slice(colonIdx + 1)
        .trim()
        .replace(/^['"]|['"]$/g, '');
      if (key === 'status') {
        currentStep.expect = currentStep.expect ?? {};
        currentStep.expect.status = parseInt(val, 10);
      } else if (key === 'bodyContains') {
        currentStep.expect = currentStep.expect ?? {};
        currentStep.expect.bodyContains = val;
      } else if (key === 'preset') {
        currentStep.preset = val;
      } else if (key === 'event') {
        currentStep.event = val;
      } else if (key === 'action') {
        currentStep.action = val as 'trigger' | 'replay' | 'delay';
      }
    }
  }

  return {
    name: scenarioName,
    target: scenarioTarget,
    steps,
  };
}
