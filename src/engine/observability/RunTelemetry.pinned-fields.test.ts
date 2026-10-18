/**
 * CHARIOT::§8.12::4 — "RunTelemetry.ts — per-run summary (token in, token
 * out, latency, tool calls, audit records) written to the observability
 * sink." Defect this catches: RunTelemetrySnapshot previously had no
 * tokenIn/tokenOut/toolCalls/auditRecords fields at all (only a generic
 * eventCounts/logCounts/durationMs shape) — the pinned five-field summary
 * the clause names did not exist.
 *
 * Run (after tsc):
 *   node --test dist/engine/observability/RunTelemetry.pinned-fields.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RunTelemetryCollector } from './RunTelemetry.js';
import type { StreamEvent } from '../types/index.js';

function actionEvent(tool: string): StreamEvent {
  return { type: 'action', data: { tool, server: 's', durationMs: 1 }, timestamp: new Date() };
}

test('§8.12::4: snapshot() carries all five pinned fields, correctly computed', () => {
  const collector = new RunTelemetryCollector({ startedAt: new Date(1000) });

  collector.recordEvent(actionEvent('tool-a'));
  collector.recordEvent(actionEvent('tool-b'));
  collector.recordEvent(actionEvent('tool-c'));

  collector.recordTokens(100, 50);
  collector.recordTokens(20, 10); // additive — two generator calls in one run

  collector.recordAudit();
  collector.recordAudit();
  collector.recordAudit();

  collector.recordEvent({ type: 'done', data: { loopIterations: 1, actionsExecuted: 3, actionsPending: 0, timing: { totalMs: 500, retrievalMs: 0, orchestratorMs: 0, federationMs: 0, autonomyMs: 0, generatorMs: 0, memoryMs: 0 } }, timestamp: new Date(1500) });

  const snapshot = collector.snapshot();

  assert.equal(snapshot.tokenIn, 120, 'tokenIn accumulates across recordTokens() calls');
  assert.equal(snapshot.tokenOut, 60, 'tokenOut accumulates across recordTokens() calls');
  assert.equal(snapshot.toolCalls, 3, 'toolCalls == count of action StreamEvents (one per dispatch)');
  assert.equal(snapshot.auditRecords, 3, 'auditRecords accumulates across recordAudit() calls');
  assert.equal(snapshot.latencyMs, snapshot.durationMs, 'latencyMs mirrors durationMs (pinned field name from the clause)');
  assert.equal(snapshot.latencyMs, 500, 'latency computed from startedAt -> done-event timestamp, same as durationMs');
});

test('§8.12::4: a run with zero tokens/audit records reports zero, not undefined', () => {
  const collector = new RunTelemetryCollector();
  const snapshot = collector.snapshot();

  assert.equal(snapshot.tokenIn, 0);
  assert.equal(snapshot.tokenOut, 0);
  assert.equal(snapshot.toolCalls, 0);
  assert.equal(snapshot.auditRecords, 0);
  assert.equal(typeof snapshot.latencyMs, 'number');
});
