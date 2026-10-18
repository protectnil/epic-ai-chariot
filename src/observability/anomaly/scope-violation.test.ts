/**
 * @epicai/chariot — Scope-violation anomaly rule adversarial eval
 *
 * Verified gap (Wiz practices 2/5): AnomalySignal carried no field for the
 * acting token's GRANTED scope, so nothing could ever fire when a
 * read-only-scoped actor issued a destructive tool call — a single-event
 * authorization-boundary failure that the pre-existing rules (rate-spike,
 * destructive-burst, cross-tenant-drift) cannot catch by construction: all
 * three require either a volume threshold or two distinct tenants, so a
 * single read-only-actor-runs-one-destructive-call event produces zero
 * findings from any of them.
 *
 * This proves:
 *   1. ScopeViolationRule fires on exactly the single violating event
 *      (grantedReadOnly=true AND destructive=true) — no threshold, no
 *      window, no cooldown suppression on repeat violations.
 *   2. It stays silent for the three non-violating quadrant combinations.
 *   3. Wired into the full default rule set (mirrors anomaly/index.ts
 *      registration order), a lone violating signal produces EXACTLY ONE
 *      finding total — the other three rules do not also fire on it.
 *   4. reportToolDispatch() (the dispatch-layer wiring entry point) carries
 *      a scope violation through to the shared AlertQueue.
 *
 * Run after `tsc`: node --test dist/observability/anomaly/scope-violation.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ToolCallRateSpikeRule,
  DestructiveToolBurstRule,
  CrossTenantDriftRule,
  ScopeViolationRule,
} from './rules.js';
import { AnomalyDetector } from './Detector.js';
import type { AnomalySignal } from './types.js';
import { reportToolDispatch, anomalyAlertQueue } from './wiring.js';

function baseSignal(overrides: Partial<AnomalySignal> = {}): AnomalySignal {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    tenantId: 'tenant-scope-violation-test',
    actorId: 'actor-readonly-1',
    adapterId: 'stripe',
    toolName: 'create_charge',
    destructive: true,
    grantedReadOnly: true,
    ...overrides,
  };
}

test('ScopeViolationRule fires on a single read-only + destructive signal', () => {
  const rule = new ScopeViolationRule();
  const finding = rule.observe(baseSignal());

  assert.ok(finding, 'expected a finding for read-only actor + destructive call');
  assert.equal(finding?.ruleId, 'scope-violation');
  assert.equal(finding?.severity, 'critical');
  assert.equal(finding?.trigger.grantedReadOnly, true);
  assert.equal(finding?.trigger.destructive, true);
});

test('ScopeViolationRule stays silent for the three non-violating quadrants', () => {
  const rule = new ScopeViolationRule();

  assert.equal(
    rule.observe(baseSignal({ grantedReadOnly: true, destructive: false })),
    null,
    'read-only actor + non-destructive call must not fire',
  );
  assert.equal(
    rule.observe(baseSignal({ grantedReadOnly: false, destructive: true })),
    null,
    'write-scoped actor + destructive call must not fire (expected/authorized)',
  );
  assert.equal(
    rule.observe(baseSignal({ grantedReadOnly: false, destructive: false })),
    null,
    'write-scoped actor + non-destructive call must not fire',
  );
});

test('ScopeViolationRule fires on EVERY repeat violation — not a volume threshold', () => {
  const rule = new ScopeViolationRule();
  const signal1 = baseSignal({ timestamp: new Date('2026-01-01T00:00:00.000Z') });
  const signal2 = baseSignal({ timestamp: new Date('2026-01-01T00:00:01.000Z') });

  const f1 = rule.observe(signal1);
  const f2 = rule.observe(signal2);

  assert.ok(f1, 'first violation must fire');
  assert.ok(f2, 'second violation (1s later) must ALSO fire — no cooldown suppression');
});

test('reset() is a no-op that does not affect subsequent firing (stateless rule)', () => {
  const rule = new ScopeViolationRule();
  rule.reset();
  const finding = rule.observe(baseSignal());
  assert.ok(finding, 'rule must still fire correctly after reset()');
});

test('Wired into the full default rule set, exactly ONE finding fires for a lone violating signal', () => {
  // Mirrors the registration order in anomaly/index.ts / wiring.ts exactly.
  const detector = new AnomalyDetector([
    new ToolCallRateSpikeRule(),
    new DestructiveToolBurstRule(),
    new CrossTenantDriftRule(),
    new ScopeViolationRule(),
  ]);

  const findings = detector.observe(baseSignal());

  assert.equal(findings.length, 1, 'exactly one finding must fire for a single violating event');
  assert.equal(findings[0]?.ruleId, 'scope-violation');
  assert.equal(detector.failedRules.length, 0, 'no rule should have thrown');
});

test('reportToolDispatch() carries a scope violation through to the shared AlertQueue', () => {
  const uniqueActor = `actor-wiring-test-${Date.now()}`;
  const before = anomalyAlertQueue.getPending().length;

  const findings = reportToolDispatch({
    tenantId: 'tenant-wiring-test',
    actorId: uniqueActor,
    toolName: 'delete_database',
    adapterId: 'postgres',
    destructive: true,
    grantedReadOnly: true,
    sourceIp: '203.0.113.42',
  });

  assert.equal(findings.length, 1, 'reportToolDispatch must surface the scope-violation finding');
  assert.equal(findings[0]?.ruleId, 'scope-violation');

  const after = anomalyAlertQueue.getPending();
  assert.ok(after.length > before, 'the finding must have reached the shared AlertQueue');

  const match = after.find(a => a.event.data.actorId === uniqueActor);
  assert.ok(match, 'the queued alert must carry the reporting actor for attribution');
  assert.equal(match?.event.data.grantedReadOnly, true);
  assert.equal(match?.event.data.sourceIp, '203.0.113.42');
  assert.equal(match?.event.severity, 'critical');
});
