/**
 * CHARIOT::§16.3::1 (CHARIOT-SPEC.md:1370-1373, rulings item 91(3)) —
 * quoted governing bytes:
 *   "- Per-tenant counts (active sessions, pending approvals, audit records).
 *    - Per-adapter counts (connection state, dispatches, errors).
 *    - Per-tier autonomy decisions.
 *    - Token usage by adapter (from §8.12 TokenTracker)."
 *
 * Proves ChariotMetrics.getSummary() carries pendingApprovals, byTier, and
 * tokenUsageByAdapter (structural TokenTracker stub — see metrics.ts's
 * TokenUsageByAdapterSource doc comment for why no TokenTracker import).
 *
 * Run (after tsc): node --test dist/observability/metrics.autonomy-tokens.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ChariotMetrics } from './metrics.js';
import type { ChariotEvent } from './emitter.js';
import { clearRegisteredTokenUsageSource } from './tokenUsageRegistry.js';

function autonomyEvent(type: ChariotEvent['type'], tier?: string): ChariotEvent {
  return {
    type,
    timestamp: new Date(),
    severity: 'info',
    data: tier === undefined ? {} : { tier },
    alertWorthy: false,
  };
}

test('§16.3::1: byTier tallies each recognized tier across all four autonomy event types', () => {
  const m = new ChariotMetrics();
  m.ingest(autonomyEvent('autonomy.escalated', 'escalate'));
  m.ingest(autonomyEvent('autonomy.approved', 'approve'));
  m.ingest(autonomyEvent('autonomy.rejected', 'approve'));
  m.ingest(autonomyEvent('autonomy.timed_out', 'escalate'));
  m.ingest(autonomyEvent('autonomy.approved', 'auto'));

  const { autonomy } = m.getSummary();
  assert.deepEqual(autonomy.byTier, { auto: 1, escalate: 2, approve: 2 });
  assert.equal(autonomy.escalated, 1);
  assert.equal(autonomy.approved, 2);
  assert.equal(autonomy.rejected, 1);
  assert.equal(autonomy.timedOut, 1);
});

test('§16.3::1: an unrecognized or absent tier increments the top-level counter but NOT byTier (absent != a named bucket)', () => {
  const m = new ChariotMetrics();
  m.ingest(autonomyEvent('autonomy.escalated', 'nonsense-tier'));
  m.ingest(autonomyEvent('autonomy.escalated'));

  const { autonomy } = m.getSummary();
  assert.equal(autonomy.escalated, 2, 'the decision-count must still increment even with unknown/absent tier data');
  assert.deepEqual(autonomy.byTier, { auto: 0, escalate: 0, approve: 0 }, 'unknown/absent tier must not be coerced into any named bucket');
});

test('§16.3::1: pendingApprovals = escalated - (approved + rejected + timedOut), floored at 0', () => {
  const m = new ChariotMetrics();
  m.ingest(autonomyEvent('autonomy.escalated', 'approve'));
  m.ingest(autonomyEvent('autonomy.escalated', 'approve'));
  m.ingest(autonomyEvent('autonomy.escalated', 'approve'));
  m.ingest(autonomyEvent('autonomy.approved', 'approve'));
  assert.equal(m.getSummary().autonomy.pendingApprovals, 2);

  // A resolution with no matching prior escalation in THIS aggregator's
  // view must never drive the count negative.
  const m2 = new ChariotMetrics();
  m2.ingest(autonomyEvent('autonomy.rejected', 'approve'));
  assert.equal(m2.getSummary().autonomy.pendingApprovals, 0);
});

test('§16.3::1 / gate finding 114(i): tokenUsageByAdapter carries the honest absence marker until a source is injected, then reflects the injected source verbatim', () => {
  // Updated (W34-4c): silently returning {} when no source is wired was
  // itself the gate finding — a gateway process with no EpicAI instance
  // could not tell "genuinely zero token usage" apart from "no
  // orchestrator in this process at all." See tokenUsageRegistry.test.ts
  // for the process-wide-registry half of this contract.
  clearRegisteredTokenUsageSource(); // hygiene: no leakage from another test/file's registration
  const m = new ChariotMetrics();
  assert.deepEqual(m.getSummary().tokenUsageByAdapter, { available: false, reason: 'no orchestrator in this process' });

  m.setTokenUsageSource({
    getTokenUsageByAdapter: () => ({ slack: { tokens: 1200, costUsd: 0.03 } }),
  });
  assert.deepEqual(m.getSummary().tokenUsageByAdapter, { slack: { tokens: 1200, costUsd: 0.03 } });
});
