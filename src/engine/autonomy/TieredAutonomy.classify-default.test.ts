/**
 * Regression eval: unmatched tools default to 'approve' / allowed:false
 * (CHARIOT::§3.5 CH-11, CHARIOT-SPEC.md:254, restated at :553).
 *
 * History: this test previously asserted the fallback tier was 'escalate'
 * citing §19 (retired framing — see CHARIOT-SPEC.md:553, "Correction to v1's
 * 'default deny' framing"). That assertion was itself wrong: in this
 * codebase 'escalate' yields `allowed: true` (TieredAutonomy.evaluate() —
 * the tool dispatches immediately, pending only after-the-fact review),
 * while 'approve' yields `allowed: false` (queued, blocked pending human
 * action). CH-11 requires the unmatched-tier default to be 'approve' so an
 * unclassified tool is NEVER dispatched without human action. commit
 * f3dd7e1 (2026-07-26) made classifyAction() default to 'escalate', which
 * regressed CH-11: unmatched tools got allowed:true and dispatched. This
 * test asserts the CH-11-compliant default and drives the actual dispatch
 * guard (`decision.allowed`, consumed at
 * src/engine/orchestrator/Orchestrator.ts:619 `if (!decision.allowed) { ...
 * continue; }`) — not just the classifier tier label — so a regression that
 * kept the tier label 'approve' but flipped `allowed` would still fail this
 * test.
 *
 * Run (after tsc):
 *   node --test dist/engine/autonomy/TieredAutonomy.classify-default.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { TieredAutonomy } from './TieredAutonomy.js';
import type { ActionContext } from '../types/index.js';

function unclassifiedContext(tool: string): ActionContext {
  return {
    tool,
    server: 'test-server',
    args: {},
    persona: 'tenant-a',
    timestamp: new Date(),
    priorActions: [],
  };
}

test('classifyAction defaults unmatched tools to approve/allowed:false per CH-11, not escalate', async () => {
  // Empty rule arrays -> every tool is "unclassified" and must fall through.
  const autonomy = new TieredAutonomy({ auto: [], escalate: [], approve: [] });

  const decision = await autonomy.evaluate(unclassifiedContext('some_unclassified_write_tool'));

  assert.equal(
    decision.tier,
    'approve',
    'CH-11: unmatched tool must classify as approve, not raw deny and not escalate',
  );

  // Drive the actual dispatch guard, not just the classifier label.
  // Orchestrator.ts:619 gates execution on `!decision.allowed` — a tool is
  // dispatched iff `allowed` is true. CH-11 requires the unmatched tool NOT
  // be dispatched without human action, so `allowed` must be false.
  assert.equal(
    decision.allowed,
    false,
    'CH-11: unmatched tool must not be dispatchable — allowed must be false so the ' +
      'Orchestrator dispatch guard (!decision.allowed) blocks execution',
  );

  autonomy.destroy();
});

test('classifyAction: escalate-tier match still dispatches (allowed:true) — matched tiers unchanged', async () => {
  const autonomy = new TieredAutonomy({ auto: [], escalate: ['some_escalate_tool'], approve: [] });

  const decision = await autonomy.evaluate(unclassifiedContext('some_escalate_tool'));

  assert.equal(decision.tier, 'escalate');
  assert.equal(
    decision.allowed,
    true,
    'escalate tier is unchanged by the CH-11 default fix: explicitly-configured escalate ' +
      'actions still dispatch immediately (allowed:true)',
  );

  autonomy.destroy();
});

test('classifyAction: auto-tier match still dispatches (allowed:true) — matched tiers unchanged', async () => {
  const autonomy = new TieredAutonomy({ auto: ['some_auto_tool'], escalate: [], approve: [] });

  const decision = await autonomy.evaluate(unclassifiedContext('some_auto_tool'));

  assert.equal(decision.tier, 'auto');
  assert.equal(
    decision.allowed,
    true,
    'auto tier is unchanged by the CH-11 default fix',
  );

  autonomy.destroy();
});

test('classifyAction: explicitly-configured approve-tier match is unchanged (allowed:false)', async () => {
  const autonomy = new TieredAutonomy({ auto: [], escalate: [], approve: ['some_approve_tool'] });

  const decision = await autonomy.evaluate(unclassifiedContext('some_approve_tool'));

  assert.equal(decision.tier, 'approve');
  assert.equal(decision.allowed, false);

  autonomy.destroy();
});
