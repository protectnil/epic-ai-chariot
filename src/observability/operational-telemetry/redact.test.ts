/**
 * Behavioral tests for redact.ts — pure functions, no I/O, run directly
 * (no Mongo/fixture needed).
 *
 * C4AMD::§8::3 (traceability.spec_nodes): "When enabled, operational
 * telemetry SHALL be minimized and redacted, permitting metadata such as
 * tenant-scoped canonical tool ID, success/failure, latency, and typed
 * failure stage." Ruling item 93 closes this to exactly six fields.
 * C4AMD::§8::5: "No secrets, credentials, raw authorization material,
 * sensitive arguments, tool results, or training examples SHALL be
 * collected by this v4.0 telemetry contract."
 *
 * Run (after tsc): node --test dist/observability/operational-telemetry/redact.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactEvent, toHourBucket, TelemetryRedactionError } from './redact.js';

const BASE: Record<string, unknown> = {
  tenantId: 'tenant-1',
  canonicalToolId: 'stripe.charge_create',
  outcome: 'success',
  latencyMs: 123,
  failureStage: null,
  hourBucket: '2026-09-04T14:00:00.000Z',
  productVersion: '4.0.0',
  platform: 'linux-arm64',
  catalogEpoch: 7,
};

// ── §8::3 — closed allowlist ────────────────────────────────────────────────

test('§8::3 (amended 2026-10-12): a well-formed event round-trips with exactly the nine allowed fields', () => {
  const out = redactEvent({ ...BASE });
  assert.deepStrictEqual(Object.keys(out).sort(), [
    'canonicalToolId',
    'catalogEpoch',
    'failureStage',
    'hourBucket',
    'latencyMs',
    'outcome',
    'platform',
    'productVersion',
    'tenantId',
  ]);
});

test('§8::3: unknown extra fields on the candidate never appear on the output', () => {
  const candidate: Record<string, unknown> = {
    ...BASE,
    extraField: 'should never appear',
    metadata: { nested: 'also never appear' },
  };
  const out = redactEvent(candidate);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(out, 'extraField'), false);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(out, 'metadata'), false);
  assert.deepStrictEqual(Object.keys(out).sort(), [
    'canonicalToolId',
    'catalogEpoch',
    'failureStage',
    'hourBucket',
    'latencyMs',
    'outcome',
    'platform',
    'productVersion',
    'tenantId',
  ]);
});

// ── §8::5 — prohibited categories never survive, even if present on input ──

test('§8::5: a candidate carrying secrets/args/results/training-examples never leaks any of them', () => {
  const malicious: Record<string, unknown> = {
    ...BASE,
    apiKey: 'sk_live_should_never_be_collected',
    credentials: { user: 'admin', password: 'hunter2' },
    authorizationHeader: 'Bearer some-raw-token',
    args: { ssn: '123-45-6789', creditCard: '4111111111111111' },
    toolResult: { content: 'raw tool output that must never be collected' },
    trainingExample: { prompt: 'x', completion: 'y' },
  };
  const out = redactEvent(malicious);
  const serialized = JSON.stringify(out);
  for (const forbidden of [
    'sk_live_should_never_be_collected',
    'hunter2',
    'Bearer some-raw-token',
    '123-45-6789',
    '4111111111111111',
    'raw tool output',
    'prompt',
  ]) {
    assert.ok(!serialized.includes(forbidden), `redacted event must never contain "${forbidden}"`);
  }
  for (const key of ['apiKey', 'credentials', 'authorizationHeader', 'args', 'toolResult', 'trainingExample']) {
    assert.strictEqual(Object.prototype.hasOwnProperty.call(out, key), false, `redacted event must never carry key "${key}"`);
  }
});

// ── outcome / failureStage invariant ────────────────────────────────────────

test('outcome must be "success" or "failure"; anything else is rejected', () => {
  assert.throws(() => redactEvent({ ...BASE, outcome: 'partial' }), TelemetryRedactionError);
});

test('failureStage must be null on a success outcome', () => {
  assert.throws(() => redactEvent({ ...BASE, outcome: 'success', failureStage: 'dispatch' }), TelemetryRedactionError);
});

test('failureStage is required and must be one of the four typed values on a failure outcome', () => {
  assert.throws(() => redactEvent({ ...BASE, outcome: 'failure', failureStage: null }), TelemetryRedactionError);
  assert.throws(
    () => redactEvent({ ...BASE, outcome: 'failure', failureStage: 'not_a_real_stage' }),
    TelemetryRedactionError,
  );
  for (const stage of ['route', 'args', 'dispatch', 'other']) {
    const out = redactEvent({ ...BASE, outcome: 'failure', failureStage: stage });
    assert.strictEqual(out.failureStage, stage);
  }
});

// ── required-field / type validation ────────────────────────────────────────

test('tenantId and canonicalToolId must be non-empty strings', () => {
  assert.throws(() => redactEvent({ ...BASE, tenantId: '' }), TelemetryRedactionError);
  assert.throws(() => redactEvent({ ...BASE, tenantId: 42 }), TelemetryRedactionError);
  assert.throws(() => redactEvent({ ...BASE, canonicalToolId: '' }), TelemetryRedactionError);
});

test('latencyMs must be a finite number >= 0', () => {
  assert.throws(() => redactEvent({ ...BASE, latencyMs: -1 }), TelemetryRedactionError);
  assert.throws(() => redactEvent({ ...BASE, latencyMs: Infinity }), TelemetryRedactionError);
  assert.throws(() => redactEvent({ ...BASE, latencyMs: 'fast' }), TelemetryRedactionError);
});

// ── hourBucket minimization ─────────────────────────────────────────────────

test('toHourBucket floors to the hour, dropping minutes/seconds/ms', () => {
  assert.strictEqual(toHourBucket(new Date('2026-09-04T14:37:52.918Z')), '2026-09-04T14:00:00.000Z');
  assert.strictEqual(toHourBucket(new Date('2026-09-04T00:00:00.000Z')), '2026-09-04T00:00:00.000Z');
});

// ── amended closed set: productVersion / platform / catalogEpoch ──────────────

test('productVersion must be a 1-64 character version string', () => {
  assert.throws(() => redactEvent({ ...BASE, productVersion: '' }), TelemetryRedactionError);
  assert.throws(() => redactEvent({ ...BASE, productVersion: 4 }), TelemetryRedactionError);
  assert.throws(() => redactEvent({ ...BASE, productVersion: '4.0.0 /etc/passwd' }), TelemetryRedactionError);
  assert.throws(() => redactEvent({ ...BASE, productVersion: 'x'.repeat(65) }), TelemetryRedactionError);
  assert.strictEqual(redactEvent({ ...BASE, productVersion: 'unknown' }).productVersion, 'unknown');
});

test('platform must be a lowercase <os>-<arch> key', () => {
  for (const ok of ['linux-x64', 'linux-arm64', 'darwin-arm64', 'win32-x64', 'android-arm64']) {
    assert.strictEqual(redactEvent({ ...BASE, platform: ok }).platform, ok);
  }
  for (const bad of ['', 'linux', 'Linux-x64', 'linux x64', 'a-b-c', 42, null]) {
    assert.throws(() => redactEvent({ ...BASE, platform: bad }), TelemetryRedactionError);
  }
});

test('catalogEpoch is a non-negative integer or null — absent is never coerced to zero', () => {
  assert.strictEqual(redactEvent({ ...BASE, catalogEpoch: null }).catalogEpoch, null);
  assert.strictEqual(redactEvent({ ...BASE, catalogEpoch: 0 }).catalogEpoch, 0);
  for (const bad of [-1, 1.5, '7', undefined, NaN]) {
    assert.throws(() => redactEvent({ ...BASE, catalogEpoch: bad }), TelemetryRedactionError);
  }
});

test('redactEvent rejects an hourBucket that is not a real UTC instant', () => {
  assert.throws(() => redactEvent({ ...BASE, hourBucket: '2026-99-99T99:00:00.000Z' }), TelemetryRedactionError);
  assert.throws(() => redactEvent({ ...BASE, hourBucket: '2026-02-30T10:00:00.000Z' }), TelemetryRedactionError);
  assert.strictEqual(redactEvent({ ...BASE, hourBucket: '2028-02-29T23:00:00.000Z' }).hourBucket, '2028-02-29T23:00:00.000Z');
});

test('redactEvent rejects an hourBucket that is not already hour-floored', () => {
  assert.throws(() => redactEvent({ ...BASE, hourBucket: '2026-09-04T14:37:00.000Z' }), TelemetryRedactionError);
});
