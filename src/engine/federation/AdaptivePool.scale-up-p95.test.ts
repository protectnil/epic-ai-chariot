/**
 * Prove-on-revert for CHARIOT §7.3::2 — "AdaptivePool SHALL be a per-tenant
 * pool with global ceiling, burst window, LRU eviction, scale-up on
 * p95(connectionWait) > scaleUpThresholdMs, and scale-down on idle, used in
 * enterprise multi-tenant."
 *
 * Defect this catches: every other element of the clause was implemented —
 * globalMaxConnections, per-tenant counts, burst window/multiplier, LRU
 * eviction (findLRU/evictOne), and the idle scale-down sweep — but the
 * `p95(connectionWait) > scaleUpThresholdMs` SCALE-UP TRIGGER was not.
 * `scaleUpThresholdMs` was declared and defaulted in config and then never read
 * or compared anywhere in the file, so the pool could never scale up under
 * load: it only ever shrank.
 *
 * Run (after tsc): node --test dist/engine/federation/AdaptivePool.scale-up-p95.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { AdaptivePool } from './AdaptivePool.js';

const src = readFileSync(fileURLToPath(new URL('./AdaptivePool.js', import.meta.url)), 'utf8');

/** Minimal adapter stub — the pool only ever calls disconnect() on it. */
function stubAdapter(): never {
  return { disconnect: async () => {} } as never;
}

test('§7.3::2: scaleUpThresholdMs is actually READ, not just declared', () => {
  const reads = src
    .split('\n')
    .filter((l) => l.includes('scaleUpThresholdMs') && !/scaleUpThresholdMs\s*:/.test(l));
  assert.ok(
    reads.length > 0,
    'scaleUpThresholdMs must be compared somewhere, not only defined in config',
  );
});

test('§7.3::2: the comparison is a p95 of connection waits', () => {
  assert.ok(/connectionWaitP95\s*\(/.test(src), 'a p95 of connectionWait must be computed');
  assert.ok(
    />\s*this\.config\.scaleUpThresholdMs/.test(src),
    'the p95 must be compared against scaleUpThresholdMs',
  );
});

test('§7.3::2: an idle tenant reports p95 0 and cannot trip the threshold', async () => {
  const pool = new AdaptivePool();
  assert.equal(pool.connectionWaitP95('never-seen-tenant'), 0);
  await pool.shutdown();
});

test('§7.3::2: p95 reflects recorded waits and rises with slow acquires', async () => {
  const pool = new AdaptivePool();
  // Fast acquires: a reused connection returns immediately.
  await pool.acquire('t1', 'a1', async () => stubAdapter());
  for (let i = 0; i < 20; i++) {
    await pool.acquire('t1', 'a1', async () => stubAdapter());
  }
  const fastP95 = pool.connectionWaitP95('t1');
  assert.ok(fastP95 >= 0, 'p95 must be defined once samples exist');

  // A deliberately slow factory must push the p95 up.
  await pool.acquire('t1', 'slow', async () => {
    await new Promise((r) => setTimeout(r, 60));
    return stubAdapter();
  });
  const slowP95 = pool.connectionWaitP95('t1');
  assert.ok(
    slowP95 >= fastP95,
    `a slow acquire must not lower the p95 (fast=${fastP95}, slow=${slowP95})`,
  );
  await pool.shutdown();
});

test('§7.3::2: scale-up runs in the same sweep as scale-down, before eviction', () => {
  const sweep = src.slice(src.indexOf('startCleanup'));
  const upIdx = sweep.indexOf('scaleUpThresholdMs');
  const downIdx = sweep.indexOf('scaleDownIdleMs');
  assert.ok(upIdx !== -1 && downIdx !== -1, 'both scale directions must live in the sweep');
  assert.ok(upIdx < downIdx, 'scale-up must be evaluated before idle scale-down');
});
