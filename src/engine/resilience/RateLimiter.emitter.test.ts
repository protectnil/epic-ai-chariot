/**
 * CHARIOT::§8.12::1 — "the orchestrator, federation, autonomy, and
 * resilience layers all emit through it." Defect this catches: grepping
 * `ObservabilityEmitter|EventEmitter` in src/engine/resilience previously
 * returned 0 hits — the resilience layer never emitted through it at all.
 *
 * Run (after tsc):
 *   node --test dist/engine/resilience/RateLimiter.emitter.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RateLimiter } from './RateLimiter.js';

const CONFIG = { maxRequests: 1, windowMs: 1000 };

test('§8.12::1: allow() emits rate_limit_exceeded through the wired emitter when the bucket is empty', () => {
  const emitted: Array<{ message: string; data?: Record<string, unknown>; layer?: string }> = [];
  const rl = new RateLimiter(CONFIG, { emitter: { info: (message, data, layer) => { emitted.push({ message, data, layer }); } } });

  assert.equal(rl.allow('server-a'), true, 'first call consumes the single token');
  assert.equal(emitted.length, 0, 'no emission on the allowed call');

  assert.equal(rl.allow('server-a'), false, 'second call is denied — bucket empty');
  assert.equal(emitted.length, 1, 'exactly one emission on the denied call');
  assert.equal(emitted[0].message, 'rate_limit_exceeded');
  assert.equal(emitted[0].layer, 'resilience');
  assert.equal(emitted[0].data?.server, 'server-a');
});

test('§8.12::1: penalize() emits rate_limiter_penalized through the wired emitter', () => {
  const emitted: Array<{ message: string; data?: Record<string, unknown>; layer?: string }> = [];
  const rl = new RateLimiter(CONFIG, { emitter: { info: (message, data, layer) => { emitted.push({ message, data, layer }); } } });

  rl.penalize('server-b');

  assert.equal(emitted.length, 1);
  assert.equal(emitted[0].message, 'rate_limiter_penalized');
  assert.equal(emitted[0].layer, 'resilience');
  assert.equal(emitted[0].data?.server, 'server-b');
  assert.equal(rl.remaining('server-b').remaining, 0, 'penalize still drains the bucket — emission is additive, not a behavior change');
});

test('§8.12::1: without a wired emitter, allow()/penalize() still work (no throw) — default-disabled', () => {
  const rl = new RateLimiter(CONFIG);
  assert.equal(rl.allow('s'), true);
  assert.equal(rl.allow('s'), false);
  rl.penalize('s');
});
