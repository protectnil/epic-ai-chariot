/**
 * CHARIOT::§16.1 (CHARIOT-SPEC.md:1338-1348, rulings item 91, taxonomy
 * option (a)) — proves the code ADOPTS every spec-pinned event name as a
 * `ChariotEventType` member, that `discovery.*` was renamed to the spec's
 * dotted form (not just added alongside the old underscore form), and that
 * `chariotEmitter` dispatches each pinned type to subscribers correctly.
 *
 * "A pinned string is a valid ChariotEventType member" is fundamentally a
 * TYPE-CHECK, not a runtime property — TypeScript erases the union at
 * compile time. Each event array below is typed `ChariotEventType[]`; if a
 * pinned string here is NOT a member of the union, this file fails to
 * COMPILE (a `tsc` error), which is how a missing/misspelled member is
 * actually caught — per COMMON.md, builders do not compile, so this
 * surfaces at the lead's roll-call, not at `node --test` runtime. The
 * runtime assertions below prove the SEPARATE property that `emit()`
 * actually delivers events of each pinned type to subscribers (the type
 * union alone does not prove the emitter's switch/dispatch path handles
 * every value correctly — e.g. a case that only matched a narrower
 * template-literal type would still type-check the array below while
 * silently dropping some emitted values at runtime).
 *
 * Run (after tsc): node --test dist/observability/emitter.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ChariotEmitter, type ChariotEventType, type ChariotEvent } from './emitter.js';
import { ChariotMetrics } from './metrics.js';

function makeEvent(type: ChariotEventType, data: Record<string, unknown> = {}): ChariotEvent {
  return { type, timestamp: new Date(), severity: 'info', data, alertWorthy: false };
}

/** Emit every type in `pinned`, in order, and assert the subscriber saw
 * exactly that sequence of types back — proves dispatch, not just typing. */
function assertAllDispatch(pinned: readonly ChariotEventType[]): void {
  const emitter = new ChariotEmitter();
  const received: ChariotEventType[] = [];
  emitter.on((e) => received.push(e.type));
  for (const type of pinned) emitter.emit(makeEvent(type));
  assert.deepEqual(received, pinned);
}

// CHARIOT-SPEC.md:1345 — "License: `license.loaded`, `license.expired`,
// `license.grace_entered`, `license.degraded`, `license.renewed`,
// `license.renew_failed`."
test('§16.1 License group: all 6 pinned event types are valid ChariotEventType members and dispatch', () => {
  const pinned: ChariotEventType[] = [
    'license.loaded',
    'license.expired',
    'license.grace_entered',
    'license.degraded',
    'license.renewed',
    'license.renew_failed',
  ];
  assertAllDispatch(pinned);
});

// CHARIOT-SPEC.md:1346 — "IAM: `auth.success`, `auth.failure`,
// `auth.brute_force_lockout`, `mfa.enrolled`, `mfa.skipped_via_idp`,
// `scim.user_provisioned`, `scim.user_deprovisioned`, `scim.group_synced`."
test('§16.1 IAM group: all 8 pinned event types are valid ChariotEventType members and dispatch', () => {
  const pinned: ChariotEventType[] = [
    'auth.success',
    'auth.failure',
    'auth.brute_force_lockout',
    'mfa.enrolled',
    'mfa.skipped_via_idp',
    'scim.user_provisioned',
    'scim.user_deprovisioned',
    'scim.group_synced',
  ];
  assertAllDispatch(pinned);
});

// CHARIOT-SPEC.md:1347 — "Federation: `adapter.connected`,
// `adapter.disconnected`, `adapter.revoked`, [the adapter-retirement
// event], `tool.dispatched`, `tool.denied`." The retirement event is
// `adapter.retired` in this codebase — renamed from the spec's original
// wording per rulings item 121 (repo leak-denylist collision on
// internal catalog-lifecycle vocabulary); customer-facing semantics
// unchanged.
test('§16.1 Federation group: all 6 pinned event types are valid ChariotEventType members and dispatch', () => {
  const pinned: ChariotEventType[] = [
    'adapter.connected',
    'adapter.disconnected',
    'adapter.revoked',
    'adapter.retired',
    'tool.dispatched',
    'tool.denied',
  ];
  assertAllDispatch(pinned);
});

// CHARIOT-SPEC.md:1348 (misnumbered line-range continuation) — "Autonomy:
// `autonomy.escalated`, `autonomy.approved`, `autonomy.rejected`,
// `autonomy.timed_out`."
test('§16.1 Autonomy group: all 4 pinned event types are valid ChariotEventType members and dispatch', () => {
  const pinned: ChariotEventType[] = [
    'autonomy.escalated',
    'autonomy.approved',
    'autonomy.rejected',
    'autonomy.timed_out',
  ];
  assertAllDispatch(pinned);
});

// "Audit: `audit.gap_detected`, `audit.export_started`,
// `audit.export_completed`."
test('§16.1 Audit group: all 3 pinned event types are valid ChariotEventType members and dispatch', () => {
  const pinned: ChariotEventType[] = [
    'audit.gap_detected',
    'audit.export_started',
    'audit.export_completed',
  ];
  assertAllDispatch(pinned);
});

// "Catalog: `catalog.signature_verified`, `catalog.signature_failed`,
// `catalog.stale_warning`, `catalog.refresh_completed`."
test('§16.1 Catalog group: all 4 pinned event types are valid ChariotEventType members and dispatch', () => {
  const pinned: ChariotEventType[] = [
    'catalog.signature_verified',
    'catalog.signature_failed',
    'catalog.stale_warning',
    'catalog.refresh_completed',
  ];
  assertAllDispatch(pinned);
});

// "Discovery: `discovery.scan.started`, `discovery.scan.completed`,
// `discovery.service.approved`, `discovery.service.rejected`,
// `discovery.exclusion.override`."
test('§16.1 Discovery group: all 5 pinned event types (dotted form) are valid ChariotEventType members and dispatch', () => {
  const pinned: ChariotEventType[] = [
    'discovery.scan.started',
    'discovery.scan.completed',
    'discovery.service.approved',
    'discovery.service.rejected',
    'discovery.exclusion.override',
  ];
  assertAllDispatch(pinned);
});

// "Operational: `gateway.backend_unhealthy`, `gateway.circuit_opened`,
// `redis.unreachable`, `mongo.unreachable`."
test('§16.1 Operational group: all 4 pinned event types are valid ChariotEventType members and dispatch', () => {
  const pinned: ChariotEventType[] = [
    'gateway.backend_unhealthy',
    'gateway.circuit_opened',
    'redis.unreachable',
    'mongo.unreachable',
  ];
  assertAllDispatch(pinned);
});

// ── Discovery rename: proves this was a RENAME (old underscore forms
// removed), not an addition alongside the old ones. If the old forms were
// still present, TypeScript would happily accept
// `'discovery.scan_completed' satisfies ChariotEventType` — proving their
// ABSENCE requires a runtime/text check, since there is no negative type
// assertion this file can lean on the compiler for. ─────────────────────
test('§16.1 Discovery rename: the old underscore-form event names no longer appear in the compiled emitter/metrics output', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  // Reads the COMPILED output this test itself runs alongside (dist/,
  // since this file only ever runs as `node --test dist/....js` per
  // COMMON.md) — a source-only check could pass while a stale dist/
  // build still ships the old names.
  const compiledEmitter = readFileSync(fileURLToPath(new URL('./emitter.js', import.meta.url)), 'utf-8');
  const compiledMetrics = readFileSync(fileURLToPath(new URL('./metrics.js', import.meta.url)), 'utf-8');
  for (const oldName of ['discovery.scan_started', 'discovery.scan_completed', 'discovery.service_approved', 'discovery.service_rejected']) {
    assert.ok(!compiledEmitter.includes(oldName), `emitter.js must not contain the old underscore-form "${oldName}"`);
    assert.ok(!compiledMetrics.includes(oldName), `metrics.js must not contain the old underscore-form "${oldName}"`);
  }
});

// ── metrics.ts ingestion: discovery events it DOES handle update the
// expected counter under the new dotted names. ──────────────────────────
test('§16.1 Discovery rename: ChariotMetrics.ingest() recognizes the new dotted event names', () => {
  const metrics = new ChariotMetrics();
  metrics.ingest(makeEvent('discovery.scan.completed'));
  metrics.ingest(makeEvent('discovery.service.approved'));
  metrics.ingest(makeEvent('discovery.service.rejected'));
  const summary = metrics.getSummary();
  assert.equal(summary.discovery.scans, 1);
  assert.equal(summary.discovery.approved, 1);
  assert.equal(summary.discovery.rejected, 1);
});

// ── Retained events: every pre-existing event with NO spec-§16.1
// counterpart is still present and still dispatches — the rename/addition
// must not have silently dropped any of the 34 retained members. ────────
test('§16.1 retained events: a representative sample of pre-existing, no-spec-counterpart events still dispatch', () => {
  const retained: ChariotEventType[] = [
    'license.checked',
    'session.created',
    'rbac.access_granted',
    'vault.encrypt',
    'scim.group_updated',
    'adapter.call_success',
    'anomaly.finding',
    'audit.tail_truncation_detected',
    'system.startup',
  ];
  assertAllDispatch(retained);
});

// ── Unrecognized-by-metrics safety: a newly-adopted event type metrics.ts
// has no `case` for MUST NOT throw when ingested — the switch's implicit
// fallthrough (no default arm) must stay a safe no-op, not a crash, for
// every one of the 33 newly-added spec-pinned members whose metrics-side
// consumption is a later unit's scope. ───────────────────────────────────
test('§16.1: ChariotMetrics.ingest() does not throw on newly-adopted event types it has no case for', () => {
  const metrics = new ChariotMetrics();
  const newlyAdopted: ChariotEventType[] = [
    'license.loaded', 'auth.success', 'adapter.connected', 'autonomy.escalated',
    'audit.gap_detected', 'catalog.signature_verified', 'discovery.exclusion.override',
    'gateway.backend_unhealthy',
  ];
  for (const type of newlyAdopted) {
    assert.doesNotThrow(() => metrics.ingest(makeEvent(type)));
  }
});
