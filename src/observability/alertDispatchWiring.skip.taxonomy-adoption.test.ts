/**
 * CHARIOT::§16.2 (rulings item 91(2)/105/114(d), review gate finding (d),
 * thread 01a06d96-0132-71b2-92f4-a87dd7611393) — "a skipped channel is
 * never silent": emit a WARN log naming the missing variable AND count it
 * in ChariotMetrics as a dispatch failure for that channel.
 *
 * This file tests `createFederationAlertDispatcher()`'s skip() closure
 * directly (WARN log + metrics side effects) — the orchestration-level
 * queuing/skippedChannels behavior is covered separately in
 * `alertDispatchWiring.test.ts` (stubbed dispatcher). Captures
 * `process.stderr.write` (this repo's established pattern — see
 * `KillListWatcher.no-feed.test.ts`) since `createLogger`'s default
 * transport is stderr, not a return value.
 *
 * Run (after tsc): node --test dist/observability/alertDispatchWiring.skip.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFederationAlertDispatcher } from './alertDispatchWiring.js';
import { ChariotMetrics } from './metrics.js';
import type { ChariotState } from '../engine/server/ChariotState.js';
import type { ChariotEvent } from './emitter.js';

function captureStderr(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
    lines.push(String(chunk));
    // @ts-expect-error — forwarding a variadic overload through a captured stub
    return original(chunk, ...rest);
  }) as typeof process.stderr.write;
  return { lines, restore: () => { process.stderr.write = original; } };
}

function makeState(chariotMetrics: ChariotMetrics, configuredAdapterIds: string[] = []): ChariotState {
  return {
    getConfiguredAdapters: () => configuredAdapterIds.map((id) => ({ id }) as never),
    chariotMetrics,
  } as unknown as ChariotState;
}

function makeEvent(): ChariotEvent {
  return {
    type: 'adapter.connected',
    timestamp: new Date(),
    severity: 'warning',
    data: { tenantId: 'tenant-skip-test' },
    alertWorthy: true,
  };
}

test('§16.2 gate finding (d): email dispatch with CHARIOT_ALERT_EMAIL_FROM unset -> WARN log naming the variable, metrics counted, skip outcome returned', async () => {
  const original = process.env.CHARIOT_ALERT_EMAIL_FROM;
  delete process.env.CHARIOT_ALERT_EMAIL_FROM;
  const metrics = new ChariotMetrics();
  const capture = captureStderr();
  try {
    const dispatcher = createFederationAlertDispatcher(makeState(metrics, ['sendgrid']));
    const outcome = await dispatcher.dispatch('email', makeEvent(), { email: 'admin@x.example' });

    assert.deepEqual(outcome, { ok: false, skipped: true, reason: 'CHARIOT_ALERT_EMAIL_FROM is not set — no verified sender configured' });
    assert.ok(capture.lines.some((l) => l.includes('CHARIOT_ALERT_EMAIL_FROM')), `expected a WARN log naming the missing variable, got: ${capture.lines.join('')}`);
    assert.equal(metrics.getSummary().alertDispatch.skipped.email, 1);
  } finally {
    capture.restore();
    if (original !== undefined) process.env.CHARIOT_ALERT_EMAIL_FROM = original;
  }
});

test('§16.2 gate finding (d): pagerduty dispatch with CHARIOT_ALERT_PAGERDUTY_SERVICE_ID unset -> WARN log naming the variable, metrics counted, skip outcome returned', async () => {
  const original = process.env.CHARIOT_ALERT_PAGERDUTY_SERVICE_ID;
  delete process.env.CHARIOT_ALERT_PAGERDUTY_SERVICE_ID;
  const metrics = new ChariotMetrics();
  const capture = captureStderr();
  try {
    const dispatcher = createFederationAlertDispatcher(makeState(metrics, ['pagerduty']));
    const outcome = await dispatcher.dispatch('pagerduty', makeEvent(), { email: 'admin@x.example' });

    assert.deepEqual(outcome, { ok: false, skipped: true, reason: 'CHARIOT_ALERT_PAGERDUTY_SERVICE_ID is not set — no target service configured' });
    assert.ok(capture.lines.some((l) => l.includes('CHARIOT_ALERT_PAGERDUTY_SERVICE_ID')), `expected a WARN log naming the missing variable, got: ${capture.lines.join('')}`);
    assert.equal(metrics.getSummary().alertDispatch.skipped.pagerduty, 1);
  } finally {
    capture.restore();
    if (original !== undefined) process.env.CHARIOT_ALERT_PAGERDUTY_SERVICE_ID = original;
  }
});

test('§16.2 gate finding (d): email dispatch with NO sendgrid/amazon-ses adapter configured for the tenant is ALSO a reported skip (not just the env var case)', async () => {
  process.env.CHARIOT_ALERT_EMAIL_FROM = 'alerts@example.com';
  const metrics = new ChariotMetrics();
  const capture = captureStderr();
  try {
    const dispatcher = createFederationAlertDispatcher(makeState(metrics, [])); // no email adapter configured
    const outcome = await dispatcher.dispatch('email', makeEvent(), { email: 'admin@x.example' });

    assert.equal(outcome.ok, false);
    assert.equal(metrics.getSummary().alertDispatch.skipped.email, 1);
  } finally {
    capture.restore();
    delete process.env.CHARIOT_ALERT_EMAIL_FROM;
  }
});

test('§16.2 gate finding (d): with CHARIOT_ALERT_EMAIL_FROM SET and a configured adapter, the dispatcher does NOT take the skip path (no WARN, no metrics increment)', { timeout: 5000 }, async () => {
  process.env.CHARIOT_ALERT_EMAIL_FROM = 'alerts@example.com';
  const metrics = new ChariotMetrics();
  const capture = captureStderr();
  try {
    const dispatcher = createFederationAlertDispatcher(makeState(metrics, ['sendgrid']));
    // handleCall() itself will very likely reject/throw in this minimal
    // synthetic-state harness (no real adapter runtime wired) — that is
    // NOT what this test asserts. It asserts the SKIP branch specifically
    // was not taken: no skip-shaped WARN log, no metrics increment.
    await dispatcher.dispatch('email', makeEvent(), { email: 'admin@x.example' }).catch(() => {});

    assert.ok(!capture.lines.some((l) => l.includes('alert_dispatch.channel_skipped')), 'the skip WARN must not fire when CHARIOT_ALERT_EMAIL_FROM is set and an adapter is configured');
    assert.equal(metrics.getSummary().alertDispatch.skipped.email, 0);
  } finally {
    capture.restore();
    delete process.env.CHARIOT_ALERT_EMAIL_FROM;
  }
});
