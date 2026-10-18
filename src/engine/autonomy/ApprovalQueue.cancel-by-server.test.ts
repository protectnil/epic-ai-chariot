/**
 * CHARIOT::§7.6::4 — "WHEN an adapter is revoked at runtime the system
 * SHALL mark ApprovalQueue items pointing at the adapter as cancelled."
 *
 * Unit-level coverage of ApprovalQueue.cancelByServer(), the primitive
 * FederationManager.unloadAdapter({revoked:true}) calls. Derived from the
 * clause's own failure enumeration:
 *   - value/position: only items whose action.server MATCHES the revoked
 *     adapter are touched; items for other servers are untouched.
 *   - state boundary: only 'pending' items transition — an already
 *     approved/denied/expired item must NOT be silently flipped to
 *     'cancelled' by a later revocation (idempotence parity with
 *     approve()/deny()).
 *   - empty/first-run: cancelling with no matching items returns [].
 *
 * Run (after `tsc`):
 *   node --test dist/engine/autonomy/ApprovalQueue.cancel-by-server.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ApprovalQueue } from './ApprovalQueue.js';
import type { ActionContext } from '../types/index.js';

function ctx(server: string, tool = 'do-thing'): ActionContext {
  return {
    tool,
    server,
    args: {},
    persona: 'tenant-a',
    timestamp: new Date(),
    priorActions: [],
  };
}

test('cancelByServer marks only pending items for the named server as cancelled', () => {
  const queue = new ApprovalQueue({ persistence: 'memory', ttlMs: 3_600_000, onExpire: 'deny' });
  const a1 = queue.enqueue(ctx('revoked-adapter'), 'approve');
  const a2 = queue.enqueue(ctx('revoked-adapter'), 'escalate');
  const other = queue.enqueue(ctx('other-adapter'), 'approve');

  const cancelled = queue.cancelByServer('revoked-adapter', 'kill_list: contradiction_detected');

  assert.equal(cancelled.length, 2);
  assert.deepEqual(new Set(cancelled.map((c) => c.id)), new Set([a1.id, a2.id]));

  assert.equal(queue.get(a1.id)!.state, 'cancelled');
  assert.equal(queue.get(a1.id)!.denyReason, 'kill_list: contradiction_detected');
  assert.ok(queue.get(a1.id)!.decidedAt, 'cancelled item must carry a decidedAt timestamp');

  assert.equal(queue.get(a2.id)!.state, 'cancelled');
  assert.equal(queue.get(other.id)!.state, 'pending', 'a different server\'s pending item must be untouched');

  queue.destroy();
});

test('cancelByServer does not re-decide an item already approved/denied/expired', () => {
  const queue = new ApprovalQueue({ persistence: 'memory', ttlMs: 3_600_000, onExpire: 'deny' });
  const approved = queue.enqueue(ctx('revoked-adapter'), 'approve');
  queue.approve(approved.id, 'operator-1');
  const denied = queue.enqueue(ctx('revoked-adapter'), 'approve');
  queue.deny(denied.id, 'operator-1', 'not needed');

  const cancelled = queue.cancelByServer('revoked-adapter', 'kill_list: reason');

  assert.equal(cancelled.length, 0, 'no pending items exist for this server — nothing to cancel');
  assert.equal(queue.get(approved.id)!.state, 'approved', 'an already-approved item must stay approved');
  assert.equal(queue.get(denied.id)!.state, 'denied', 'an already-denied item must stay denied');

  queue.destroy();
});

test('cancelByServer against a server with no queue entries at all returns an empty array', () => {
  const queue = new ApprovalQueue({ persistence: 'memory', ttlMs: 3_600_000, onExpire: 'deny' });
  const cancelled = queue.cancelByServer('never-enqueued-adapter', 'reason');
  assert.deepEqual(cancelled, []);
  queue.destroy();
});
