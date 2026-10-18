/**
 * CHARIOT §8.7 — token-bucket refill under a non-monotonic clock.
 *
 * refill() advances the bucket by (now - lastRefillAt) * refillRate. Wall-clock
 * time is NOT monotonic: NTP correction, a VM snapshot restore, or a manual
 * clock set can move `now` backwards. The failure enumeration for that input:
 *
 *   1. NEGATIVE ELAPSED drains the bucket — tokens go DOWN on a refill, so a
 *      backward jump silently converts spare capacity into throttling.
 *   2. ANCHOR REWIND — lastRefillAt is set to the earlier timestamp, so the
 *      next legitimate call double-counts the interval and over-refills.
 *
 * Both must be closed: elapsed is clamped at zero and the anchor only moves
 * forward. Regression is a no-op refill, never a penalty and never a credit.
 *
 * Run (after tsc): node --test dist/engine/resilience/RateLimiter.clock-regression.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RateLimiter } from './RateLimiter.js';

const SERVER = 'srv';
/** 10 tokens per 1000 ms => 0.01 tokens/ms. */
const CONFIG = { maxRequests: 10, windowMs: 1000 };

/** A limiter whose clock is driven by the test rather than by Date.now(). */
function limiterAt(start: number): { rl: RateLimiter; at: (t: number) => void } {
  let clock = start;
  const rl = new RateLimiter(CONFIG, { now: () => clock });
  return { rl, at: (t: number) => { clock = t; } };
}

test('§8.7: a backward clock jump does not drain the bucket', () => {
  const { rl, at } = limiterAt(1000);

  // Spend 4 tokens at t=1000, leaving 6.
  for (let i = 0; i < 4; i += 1) assert.equal(rl.allow(SERVER), true);
  assert.equal(rl.remaining(SERVER).remaining, 6);

  // Clock jumps back 500 ms. A negative elapsed would subtract 5 tokens.
  at(500);
  assert.equal(rl.remaining(SERVER).remaining, 6, 'regression must not reduce tokens');
});

test('§8.7: a backward clock jump does not rewind the refill anchor', () => {
  const { rl, at } = limiterAt(1000);

  for (let i = 0; i < 10; i += 1) assert.equal(rl.allow(SERVER), true);
  assert.equal(rl.remaining(SERVER).remaining, 0, 'bucket is empty at t=1000');

  // Observe the bucket at an earlier instant, then return to real time.
  at(400);
  rl.remaining(SERVER);

  // If the anchor had rewound to 400, the interval 400->1100 would credit
  // 7 tokens instead of the 1 token actually earned between 1000 and 1100.
  at(1100);
  assert.equal(rl.remaining(SERVER).remaining, 1, 'only the true 100 ms is credited');
});

test('§8.7: forward refill still works normally after a regression', () => {
  const { rl, at } = limiterAt(1000);

  for (let i = 0; i < 10; i += 1) rl.allow(SERVER);
  at(200);
  rl.remaining(SERVER); // regression, absorbed as a no-op

  // 1000 ms after the drain the bucket is back to capacity, not beyond it.
  at(2000);
  assert.equal(rl.remaining(SERVER).remaining, 10, 'refills to capacity');
  at(9000);
  assert.equal(rl.remaining(SERVER).remaining, 10, 'and is capped at capacity');
});

test('§8.7: regression cannot let a denied call through', () => {
  const { rl, at } = limiterAt(1000);

  for (let i = 0; i < 10; i += 1) assert.equal(rl.allow(SERVER), true);
  assert.equal(rl.allow(SERVER), false, 'eleventh call is denied');

  // Replaying at an earlier timestamp must not manufacture capacity.
  at(100);
  assert.equal(rl.allow(SERVER), false, 'regression does not grant a token');
});

test('§8.7: the default construction still reads the real clock', () => {
  // The seam must be opt-in: omitting it leaves the production path unchanged.
  const rl = new RateLimiter(CONFIG);
  assert.equal(rl.allow(SERVER), true);
  assert.equal(rl.remaining(SERVER).remaining, 9);
});
