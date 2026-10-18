/**
 * CHARIOT §8.7::5 — CHARIOT-SPEC.md:781: "`RateLimiter.ts` — per-server
 * token bucket. Used by federation to back-pressure adapter calls when an
 * upstream returns 429." Also CHARIOT-SPEC.md:728: "An LLM that generates
 * a high-volume tool-call loop is back-pressured by the token bucket."
 *
 * penalize(server) is the primitive federation calls on a 429. The
 * contract it must satisfy, derived from the drain+refill machinery
 * (RateLimiter.ts refill()/allow()/waitForAllowance()):
 *
 *   1. DRAIN: after penalize(A), allow(A) is false immediately (the bucket
 *      is empty, not merely reduced).
 *   2. WAIT: after penalize(A), waitForAllowance(A, smallMax) throws
 *      rather than resolving instantly — the caller actually paces.
 *   3. ISOLATION: penalize(A) must not touch server B's bucket — B keeps
 *      its full allowance.
 *   4. RECOVERY: after enough injected refill time, A's bucket recovers
 *      to capacity exactly as an ordinary drain-then-refill would (same
 *      refill() path, not a separate reset).
 *
 * Run (after tsc): node --test dist/engine/resilience/RateLimiter.penalize.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RateLimiter } from './RateLimiter.js';

const A = 'server-a';
const B = 'server-b';
/** 10 tokens per 1000 ms => 0.01 tokens/ms. */
const CONFIG = { maxRequests: 10, windowMs: 1000 };

function limiterAt(start: number): { rl: RateLimiter; at: (t: number) => void } {
  let clock = start;
  const rl = new RateLimiter(CONFIG, { now: () => clock });
  return { rl, at: (t: number) => { clock = t; } };
}

test('§8.7::5: penalize() drains the bucket to zero — allow() is false immediately', () => {
  const { rl } = limiterAt(1000);

  assert.equal(rl.remaining(A).remaining, 10, 'starts at full capacity');
  rl.penalize(A);
  assert.equal(rl.remaining(A).remaining, 0, 'penalize drains to zero');
  assert.equal(rl.allow(A), false, 'a penalized server is denied immediately');
});

test('§8.7::5: penalize() makes waitForAllowance() actually wait, not resolve instantly', async () => {
  const { rl, at } = limiterAt(1000);

  rl.penalize(A);
  // A full refill for 1 token at 0.01 tokens/ms takes 100ms. A maxWaitMs
  // smaller than that must throw rather than silently granting the call.
  await assert.rejects(
    () => rl.waitForAllowance(A, 10),
    /Rate limit exceeded/,
    'penalized server does not grant allowance within an insufficient wait window',
  );
  // Sanity: the clock injection above is unused by waitForAllowance's
  // internal setTimeout, so this only proves the throw path, not timing.
  void at;
});

test('§8.7::5: penalize() is per-server — an unrelated server is unaffected', () => {
  const { rl } = limiterAt(1000);

  rl.penalize(A);
  assert.equal(rl.remaining(A).remaining, 0, 'A is drained');
  assert.equal(rl.remaining(B).remaining, 10, 'B keeps its full bucket');
  assert.equal(rl.allow(B), true, "B dispatch is not back-pressured by A's penalty");
});

test('§8.7::5: a penalized server recovers via ordinary refill once enough time passes', () => {
  const { rl, at } = limiterAt(1000);

  rl.penalize(A);
  assert.equal(rl.allow(A), false, 'immediately after penalize, denied');

  // Full capacity (10 tokens) refills after 1000ms at 0.01 tokens/ms.
  at(2000);
  assert.equal(rl.remaining(A).remaining, 10, 'fully refilled 1000ms later');
  assert.equal(rl.allow(A), true, 'and dispatch is allowed again');
});

test('§8.7::5: penalize() respects the injected clock seam (not a hardcoded reset)', () => {
  const { rl, at } = limiterAt(1000);

  rl.penalize(A);
  // Only 500ms elapse => only half of one token's worth of the window has
  // passed relative to a 10-token/1000ms bucket: 500 * 0.01 = 5 tokens.
  at(1500);
  assert.equal(rl.remaining(A).remaining, 5, 'partial refill reflects the injected clock, not Date.now()');
});

test('§8.7::5: prove-on-revert — without penalize(), a 429 would not back-pressure the next call', () => {
  const { rl } = limiterAt(1000);

  // No penalize() call here: this is the pre-fix behavior. The bucket is
  // untouched by the (simulated) 429, so the very next call still succeeds.
  assert.equal(rl.allow(A), true, 'baseline: an un-penalized server is always allowed while tokens remain');

  // Now apply the fix and show the contrast on the SAME bucket state.
  rl.penalize(A);
  assert.equal(rl.allow(A), false, 'post-fix: penalize() closes exactly the gap the baseline above left open');
});
