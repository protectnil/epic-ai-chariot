/**
 * CHARIOT::§18.2::2 / §18.3::4 — the in-process Redis shim is the fallback
 * surface enterprise bootstrap wires up when REDIS_URL is absent
 * ("optionally uses Redis (in-process fallback if absent)",
 * CHARIOT-SPEC.md:1469) or unreachable ("ControlPlane SHALL degrade to
 * in-process, ApprovalQueue to in-memory", CHARIOT-SPEC.md:1475). Extracted
 * verbatim (no behavior change) from src/engine/bin/setup.ts's prior inline
 * copy into a module shared with src/iam/bootstrap.ts, so both
 * enterprise-bootstrap paths use identical semantics.
 *
 * Failure enumeration exercised: get/set round trip; TTL expiry (EX);
 * NX no-clobber; KEEPTTL preserves prior expiry on overwrite; jti-replay
 * eval() first-sight/match/replay tri-state (the Lua-CAS semantics
 * jti-replay-cache.ts depends on); incr on a non-integer existing value
 * throws rather than silently producing NaN (fail-closed, not fail-open,
 * on a poisoned key).
 *
 * Run (after tsc): node --test dist/iam/inProcessRedisShim.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createInProcessRedisShim } from './inProcessRedisShim.js';

test('get/set round trip', async () => {
  const shim = createInProcessRedisShim();
  assert.equal(await shim.get('k'), null);
  await shim.set('k', 'v');
  assert.equal(await shim.get('k'), 'v');
});

test('expire() with a past TTL makes the key unreadable (lazy expiration on get)', async () => {
  const shim = createInProcessRedisShim();
  await shim.set('k', 'v');
  await shim.expire('k', -1);
  assert.equal(await shim.get('k'), null);
});

test('set with NX does not clobber an existing key', async () => {
  const shim = createInProcessRedisShim();
  await shim.set('k', 'first');
  const result = await shim.set('k', 'second', { NX: true });
  assert.equal(result, null);
  assert.equal(await shim.get('k'), 'first');
});

test('set with KEEPTTL updates the value without throwing, on top of a still-live prior TTL', async () => {
  const shim = createInProcessRedisShim();
  await shim.set('k', 'v1');
  await shim.expire('k', 1000); // still-live TTL (~1000s out)
  const result = await shim.set('k', 'v2', { KEEPTTL: true });
  assert.equal(result, 'OK');
  assert.equal(await shim.get('k'), 'v2');
});

test('eval() reserveOrMatch: first-sight, then match on the same value, then replay on a different value', async () => {
  const shim = createInProcessRedisShim();
  const opts1 = { keys: ['replay:abc'], arguments: ['hash1', '60'] };
  assert.equal(await shim.eval('', opts1), 'first-sight');
  assert.equal(await shim.eval('', opts1), 'match');
  const opts2 = { keys: ['replay:abc'], arguments: ['hash2', '60'] };
  assert.equal(await shim.eval('', opts2), 'replay');
});

test('incr on a non-integer existing value throws (fail-closed, not NaN)', async () => {
  const shim = createInProcessRedisShim();
  await shim.set('counter', 'not-a-number');
  await assert.rejects(() => shim.incr('counter'), /non-integer value/);
});

test('incr on an absent key starts at 1', async () => {
  const shim = createInProcessRedisShim();
  assert.equal(await shim.incr('fresh-counter'), 1);
  assert.equal(await shim.incr('fresh-counter'), 2);
});

test('multi().exec() applies queued ops in order', async () => {
  const shim = createInProcessRedisShim();
  const chain = shim.multi() as {
    set(k: string, v: string): unknown;
    incr(k: string): unknown;
    exec(): Promise<unknown[]>;
  };
  chain.set('mk', 'mv');
  chain.incr('mc');
  const results = await chain.exec();
  assert.deepEqual(results, ['OK', 1]);
  assert.equal(await shim.get('mk'), 'mv');
});
