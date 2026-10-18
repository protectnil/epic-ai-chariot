/**
 * CHARIOT::§7.6::4 — Redis-backed ApprovalQueue.cancelByServer(), the
 * production path an enterprise (Redis-persisted) deployment takes when
 * an adapter is revoked at runtime.
 *
 * CHARIOT-SPEC.md:635 (§7.6, quoted verbatim, on-disk):
 *   "3. ApprovalQueue items pointing at the adapter are marked as
 *   cancelled."
 *
 * `src/engine/autonomy/adapters/RedisQueue.ts:129-149` implements
 * `cancelByServer()` for the Redis-backed queue (in-memory `ApprovalQueue`
 * has its own, separately-tested,
 * ApprovalQueue.cancel-by-server.test.ts). `RedisQueue.connect()`
 * unconditionally `import('redis')`s and opens a real TCP connection — it
 * has no constructor seam to inject a fake client — so this test bypasses
 * `connect()` via reflection and wires `(queue as any).redis` directly to
 * an in-process, Map-backed fake before `connected = true`, then exercises
 * the REAL enqueue()/pending()/cancelByServer()/get() methods against it.
 * The fake wraps `src/iam/inProcessRedisShim.ts`'s `createInProcessRedisShim()`
 * (the codebase's existing in-process Redis stand-in) plus a `persist()`
 * no-op — the shim's public interface does not declare `persist` (it has
 * no TTL-tracking to persist against), and `RedisQueue.cancelByServer()`
 * calls `redis.persist()` after every cancel to strip the pending
 * approval's TTL. Since the shim shares the sMembers/sAdd/sRem/set/get
 * subset RedisQueue actually calls, `persist()` being a no-op does not
 * affect any assertion below — none of them re-check TTL, only
 * `state`/`denyReason`/set-membership after cancellation.
 *
 * Run (after `tsc`):
 *   node --test dist/engine/autonomy/adapters/RedisQueue.cancel-by-server.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RedisQueue } from './RedisQueue.js';
import { createInProcessRedisShim } from '../../../iam/inProcessRedisShim.js';
import type { ActionContext } from '../../types/index.js';

function fakeContext(server: string): ActionContext {
  return {
    tool: 'noop',
    server,
    args: {},
    persona: 'test',
    timestamp: new Date(),
    priorActions: [],
  };
}

/** Bypass RedisQueue.connect()'s real `import('redis')` + TCP connect —
 *  see file docstring. */
function wireFakeRedis(queue: RedisQueue): void {
  const shim = createInProcessRedisShim();
  const fakeRedis = {
    ...shim,
    persist: async (_key: string) => 1,
  };
  (queue as unknown as { redis: unknown }).redis = fakeRedis;
  (queue as unknown as { connected: boolean }).connected = true;
}

test('CHARIOT::§7.6::4 — RedisQueue.cancelByServer marks matching pending approvals cancelled, persists the write, and drops them from the pending set', async () => {
  const queue = new RedisQueue({ host: 'unused', port: 0, ttlMs: 60_000 });
  wireFakeRedis(queue);

  const matching = await queue.enqueue(fakeContext('revocable-server'), 'approve');
  const other = await queue.enqueue(fakeContext('other-server'), 'approve');

  const cancelled = await queue.cancelByServer('revocable-server', 'kill_list: revoked');

  assert.equal(cancelled.length, 1);
  assert.equal(cancelled[0].id, matching.id);
  assert.equal(cancelled[0].state, 'cancelled');
  assert.equal(cancelled[0].denyReason, 'kill_list: revoked');
  assert.ok(cancelled[0].decidedAt, 'decidedAt must be set on cancellation');

  // Persistence: the mutation was actually WRITTEN to the store (not only
  // returned in-memory) — read back via a fresh get() call.
  const readBack = await queue.get(matching.id);
  assert.ok(readBack, 'cancelled approval must still be readable by id');
  assert.equal(readBack!.state, 'cancelled');
  assert.equal(readBack!.denyReason, 'kill_list: revoked');

  // Pending-set removal: pending() must no longer surface the cancelled
  // approval, and the unrelated server's approval must be untouched.
  const stillPending = await queue.pending();
  assert.deepEqual(stillPending.map((p) => p.id), [other.id]);
});

test('CHARIOT::§7.6::4 — RedisQueue.cancelByServer is idempotent: a second call finds nothing left to cancel', async () => {
  const queue = new RedisQueue({ host: 'unused', port: 0, ttlMs: 60_000 });
  wireFakeRedis(queue);

  const approval = await queue.enqueue(fakeContext('revocable-server-2'), 'escalate');

  const first = await queue.cancelByServer('revocable-server-2', 'first revocation');
  assert.equal(first.length, 1);
  assert.equal(first[0].id, approval.id);

  // cancelByServer only touches state === 'pending' approvals (RedisQueue.ts
  // :137: `if (approval.state !== 'pending' || approval.action.server !==
  // server) continue;`) — an already-cancelled approval must not be
  // re-cancelled, re-counted, or have its denyReason overwritten.
  const second = await queue.cancelByServer('revocable-server-2', 'second revocation');
  assert.equal(second.length, 0, 'an already-cancelled approval must not be cancelled again');

  const readBack = await queue.get(approval.id);
  assert.equal(readBack!.denyReason, 'first revocation', 'the second call must not overwrite the first cancellation');
});

test('CHARIOT::§7.6::4 — RedisQueue.cancelByServer for a server with no pending approvals is a no-op', async () => {
  const queue = new RedisQueue({ host: 'unused', port: 0, ttlMs: 60_000 });
  wireFakeRedis(queue);

  const cancelled = await queue.cancelByServer('never-had-any-approvals', 'irrelevant');
  assert.deepEqual(cancelled, []);
});

test('CHARIOT::§7.6::4 — RedisQueue.cancelByServer only cancels approvals for the matching server (alias/position failure class)', async () => {
  const queue = new RedisQueue({ host: 'unused', port: 0, ttlMs: 60_000 });
  wireFakeRedis(queue);

  const a = await queue.enqueue(fakeContext('server-a'), 'approve');
  const b1 = await queue.enqueue(fakeContext('server-b'), 'approve');
  const b2 = await queue.enqueue(fakeContext('server-b'), 'escalate');

  const cancelled = await queue.cancelByServer('server-b', 'revoked');

  assert.deepEqual(cancelled.map((c) => c.id).sort(), [b1.id, b2.id].sort());
  const stillPending = await queue.pending();
  assert.deepEqual(stillPending.map((p) => p.id), [a.id]);
});
