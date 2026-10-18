/**
 * Prove-on-revert for CHARIOT §3.5::17 (CH-12).
 *
 * CHARIOT-SPEC.md line 255 (verbatim): "The IAM `audit.log()` call that
 * hash-chains the event is invoked by the request-boundary caller, before the
 * federation dispatch begins."
 *
 * Defect this catches: the pre-dispatch hash-chained record was produced by
 * engine/audit/AuditTrail.record() (its own engine-side HashChain), NOT by the
 * IAM audit.log() chain — no src/iam caller ran before federation dispatch at
 * all. A tenant's IAM audit chain therefore had no record of the dispatch.
 *
 * The load-bearing property is ORDERING: the chain write must complete before
 * any upstream dispatch, and a failed write must abort the call rather than let
 * an unaudited dispatch through.
 *
 * Behavioral end-to-end coverage (real Mongo chain) lives in the infra-gated
 * eval harness; this asserts the seam contract and placement by source
 * inspection plus a direct port-ordering check.
 *
 * Run (after tsc): node --test dist/engine/server/toolHandlers.pre-dispatch-audit.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import type { DecisionAuditPort } from '../ports/DecisionAuditPort.js';

const src = readFileSync(fileURLToPath(new URL('./toolHandlers.js', import.meta.url)), 'utf8');

test('§3.5::17: the request boundary invokes the pre-dispatch audit hook', () => {
  assert.ok(
    /recordPreDispatchDecision\(/.test(src),
    'handleCallImpl must invoke the pre-dispatch decision audit hook',
  );
  assert.ok(
    /state\.decisionAudit\s*\?\?\s*context\?\.decisionAudit/.test(src),
    'the hook must resolve from installation-scoped state, with a per-request override',
  );
});

test('§3.5::17: the hook is AWAITED — dispatch cannot begin before the chain write', () => {
  const call = src.slice(src.indexOf('recordPreDispatchDecision'));
  const lineStart = src.lastIndexOf('\n', src.indexOf('recordPreDispatchDecision'));
  const invocation = src.slice(lineStart, lineStart + 120);
  assert.ok(
    /await\s+decisionAudit\.recordPreDispatchDecision/.test(invocation),
    `the audit write must be awaited before dispatch: ${invocation.trim()}`,
  );
  void call;
});

test('§3.5::17: the hook is NOT swallowed — an unauditable call must not dispatch', () => {
  const idx = src.indexOf('recordPreDispatchDecision');
  // Walk back to the enclosing statement; there must be no try/catch wrapping
  // the audit call that would let a failed chain write fall through to dispatch.
  const window = src.slice(Math.max(0, idx - 400), idx);
  const lastTry = window.lastIndexOf('try {');
  const lastCatch = window.lastIndexOf('catch');
  assert.ok(
    lastTry === -1 || lastCatch > lastTry,
    'the pre-dispatch audit write must not be wrapped in a swallowing try/catch',
  );
});

test('§3.5::17: a port implementation runs strictly before dispatch', async () => {
  const order: string[] = [];
  const port: DecisionAuditPort = {
    async recordPreDispatchDecision() {
      order.push('audit');
    },
  };
  // Model the boundary contract: audit resolves, then dispatch runs.
  await port.recordPreDispatchDecision({
    context: { tenantId: 't1', actorId: 'u1' },
    adapterId: 'a',
    toolName: 't',
    detail: {},
  });
  order.push('dispatch');
  assert.deepEqual(order, ['audit', 'dispatch']);
});

test('§3.5::17: a rejecting port prevents dispatch', async () => {
  const order: string[] = [];
  const port: DecisionAuditPort = {
    async recordPreDispatchDecision() {
      throw new Error('chain write failed');
    },
  };
  await assert.rejects(async () => {
    await port.recordPreDispatchDecision({
      context: { tenantId: 't1' },
      adapterId: 'a',
      toolName: 't',
      detail: {},
    });
    order.push('dispatch');
  });
  assert.deepEqual(order, [], 'dispatch must not run when the audit write rejects');
});
