/**
 * CHARIOT::§16.1 Autonomy (CHARIOT-SPEC.md:1348, rulings item 91/105) —
 * "Autonomy: `autonomy.escalated`, `autonomy.approved`, `autonomy.rejected`,
 * `autonomy.timed_out`."
 *
 * REAL BEHAVIORAL test (TieredAutonomy/ApprovalQueue are pure in-process
 * classes with no Mongo/Express/signed-fixture dependency — unlike the
 * license loader, there is no reason to fall back to source inspection
 * here). Subscribes to the real `chariotEmitter` singleton and exercises
 * `evaluate()`/`approve()`/`deny()`/expiry against a real (in-memory)
 * `TieredAutonomy` instance with a short TTL for the timeout case.
 *
 * Run (after tsc): node --test dist/engine/autonomy/TieredAutonomy.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TieredAutonomy } from './TieredAutonomy.js';
import { chariotEmitter, type ChariotEvent } from '../../observability/emitter.js';
import type { ActionContext } from '../types/index.js';

function captureEvents(): { events: ChariotEvent[]; stop: () => void } {
  const events: ChariotEvent[] = [];
  const cb = (e: ChariotEvent) => events.push(e);
  chariotEmitter.on(cb);
  return { events, stop: () => chariotEmitter.off(cb) };
}

function makeContext(tool: string, persona = 'tenant-autonomy-test'): ActionContext {
  return {
    tool,
    server: 'test-adapter',
    args: {},
    persona,
    timestamp: new Date(),
    priorActions: [],
  };
}

test('§16.1 Autonomy: an "escalate"-tier action emits autonomy.escalated with data.tier === "escalate"', async () => {
  const ta = new TieredAutonomy({ auto: [], escalate: ['risky_tool'], approve: [] });
  const { events, stop } = captureEvents();
  try {
    await ta.evaluate(makeContext('risky_tool'));
    const evt = events.find((e) => e.type === 'autonomy.escalated');
    assert.ok(evt, 'expected autonomy.escalated');
    assert.equal(evt!.data.tier, 'escalate');
  } finally {
    stop();
    ta.destroy();
  }
});

test('§16.1 Autonomy: an "approve"-tier action ALSO emits autonomy.escalated, with data.tier === "approve"', async () => {
  const ta = new TieredAutonomy({ auto: [], escalate: [], approve: ['dangerous_tool'] });
  const { events, stop } = captureEvents();
  try {
    await ta.evaluate(makeContext('dangerous_tool'));
    const evt = events.find((e) => e.type === 'autonomy.escalated');
    assert.ok(evt, 'both escalate and approve tiers enqueue for human review, and both emit autonomy.escalated');
    assert.equal(evt!.data.tier, 'approve');
  } finally {
    stop();
    ta.destroy();
  }
});

test('§16.1 Autonomy: an "auto"-tier action emits NONE of the 4 pinned Autonomy events', async () => {
  const ta = new TieredAutonomy({ auto: ['safe_tool'], escalate: [], approve: [] });
  const { events, stop } = captureEvents();
  try {
    await ta.evaluate(makeContext('safe_tool'));
    const autonomyEvents = events.filter((e) => e.type.startsWith('autonomy.'));
    assert.deepEqual(autonomyEvents, [], 'auto-tier is not a human-review decision — none of the 4 pinned events apply');
  } finally {
    stop();
    ta.destroy();
  }
});

test('§16.1 Autonomy: approve() emits autonomy.approved for a genuinely pending item', async () => {
  const ta = new TieredAutonomy({ auto: [], escalate: [], approve: ['dangerous_tool'] });
  try {
    const decision = await ta.evaluate(makeContext('dangerous_tool'));
    const { events, stop } = captureEvents();
    try {
      await ta.approve(decision.id, 'admin@example.com');
      const evt = events.find((e) => e.type === 'autonomy.approved');
      assert.ok(evt);
      assert.equal(evt!.data.approver, 'admin@example.com');
    } finally {
      stop();
    }
  } finally {
    ta.destroy();
  }
});

test('§16.1 Autonomy: a SECOND approve() call on an already-decided item does NOT re-emit autonomy.approved (idempotent-replay guard)', async () => {
  const ta = new TieredAutonomy({ auto: [], escalate: [], approve: ['dangerous_tool'] });
  try {
    const decision = await ta.evaluate(makeContext('dangerous_tool'));
    await ta.approve(decision.id, 'admin@example.com');

    const { events, stop } = captureEvents();
    try {
      await ta.approve(decision.id, 'admin@example.com');
      assert.equal(events.filter((e) => e.type === 'autonomy.approved').length, 0, 'a replayed approve() on an already-approved item must not double-emit');
    } finally {
      stop();
    }
  } finally {
    ta.destroy();
  }
});

test('§16.1 Autonomy: deny() emits autonomy.rejected with the reason', async () => {
  const ta = new TieredAutonomy({ auto: [], escalate: ['risky_tool'], approve: [] });
  try {
    const decision = await ta.evaluate(makeContext('risky_tool'));
    const { events, stop } = captureEvents();
    try {
      await ta.deny(decision.id, 'admin@example.com', 'looks suspicious');
      const evt = events.find((e) => e.type === 'autonomy.rejected');
      assert.ok(evt);
      assert.equal(evt!.data.reason, 'looks suspicious');
    } finally {
      stop();
    }
  } finally {
    ta.destroy();
  }
});

test('§16.1 Autonomy: an unresolved item emits autonomy.timed_out after its TTL elapses', { timeout: 30_000 }, async () => {
  // ApprovalQueue's expiration CHECK runs on a fixed 10s interval
  // regardless of ttlMs (ApprovalQueue.ts's startExpirationCheck: "Check
  // every 10 seconds for expired approvals") — a short ttlMs (50ms) makes
  // the item ELIGIBLE for expiry almost immediately, but the test still
  // has to wait for the next 10s tick to observe it. Poll for up to 25s
  // (2+ ticks) to avoid flaking near a tick boundary.
  const ta = new TieredAutonomy({ auto: [], escalate: ['risky_tool'], approve: [] }, { persistence: 'memory', ttlMs: 50 });
  const { events, stop } = captureEvents();
  try {
    await ta.evaluate(makeContext('risky_tool'));
    const deadline = Date.now() + 25_000;
    while (Date.now() < deadline && !events.some((e) => e.type === 'autonomy.timed_out')) {
      await new Promise((r) => setTimeout(r, 200));
    }
    const evt = events.find((e) => e.type === 'autonomy.timed_out');
    assert.ok(evt, 'expected autonomy.timed_out for an item whose TTL elapsed with no human decision');
  } finally {
    stop();
    ta.destroy();
  }
});
