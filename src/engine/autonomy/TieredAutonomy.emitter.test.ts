/**
 * CHARIOT::§8.12::1 — "ObservabilityEmitter.ts — the event bus inside the
 * engine. The orchestrator, federation, autonomy, and resilience layers
 * all emit through it." Defect this catches: grepping
 * `ObservabilityEmitter|EventEmitter` in src/engine/autonomy previously
 * returned 0 hits — the autonomy layer never emitted through it at all.
 *
 * Run (after tsc):
 *   node --test dist/engine/autonomy/TieredAutonomy.emitter.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { TieredAutonomy } from './TieredAutonomy.js';
import type { ActionContext } from '../types/index.js';

function ctx(tool: string, persona = 'tenant-a'): ActionContext {
  return { tool, server: 'srv', args: {}, persona, timestamp: new Date(), priorActions: [] };
}

test('§8.12::1: evaluate() emits through the wired emitter on the auto tier', async () => {
  const emitted: Array<{ message: string; data?: Record<string, unknown>; layer?: string }> = [];
  const autonomy = new TieredAutonomy(
    { auto: ['read_file'], escalate: [], approve: [] },
    undefined,
    { emitter: { info: (message, data, layer) => { emitted.push({ message, data, layer }); } } },
  );

  const decision = await autonomy.evaluate(ctx('read_file'));

  assert.equal(decision.tier, 'auto');
  assert.equal(emitted.length, 1, 'evaluate() must emit exactly once per decision');
  assert.equal(emitted[0].message, 'autonomy_decision');
  assert.equal(emitted[0].layer, 'autonomy');
  assert.equal(emitted[0].data?.tier, 'auto');
  assert.equal(emitted[0].data?.allowed, true);

  autonomy.destroy();
});

test('§8.12::1: evaluate() emits on the escalate and approve tiers too', async () => {
  const emitted: string[] = [];
  const autonomy = new TieredAutonomy(
    { auto: [], escalate: ['escalate_tool'], approve: ['approve_tool'] },
    undefined,
    { emitter: { info: (_m, data) => { emitted.push(String(data?.tier)); } } },
  );

  await autonomy.evaluate(ctx('escalate_tool'));
  await autonomy.evaluate(ctx('approve_tool'));

  assert.deepEqual(emitted, ['escalate', 'approve']);

  autonomy.destroy();
});

test('§8.12::1: without a wired emitter, evaluate() still works (no throw) — default-disabled', async () => {
  const autonomy = new TieredAutonomy({ auto: ['read_file'], escalate: [], approve: [] });
  const decision = await autonomy.evaluate(ctx('read_file'));
  assert.equal(decision.tier, 'auto');
  autonomy.destroy();
});
