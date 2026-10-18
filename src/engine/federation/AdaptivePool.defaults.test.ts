/**
 * Regression eval: AdaptivePool compiled-in defaults match §7.3::3.
 *
 * The defect this exists to catch: DEFAULT_POOL_CONFIG shipped
 * burstMultiplier=2.5 (spec: 2.0), burstWindowMs=30_000 (spec: 60000),
 * scaleUpThresholdMs=200 (spec: 250), scaleDownIdleMs=120_000
 * (spec: 300000) — four of seven asserted defaults were wrong. This test
 * pins the full compiled-in default set and would FAIL against the pre-fix
 * values.
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/AdaptivePool.defaults.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_POOL_CONFIG } from './AdaptivePool.js';

test('DEFAULT_POOL_CONFIG matches the §7.3::3 compiled-in defaults', () => {
  assert.deepEqual(DEFAULT_POOL_CONFIG, {
    globalMaxConnections: 500,
    perTenantBaseConnections: 20,
    perTenantMaxConnections: 50,
    burstMultiplier: 2.0,
    burstWindowMs: 60000,
    evictionPolicy: 'lru',
    scaleUpThresholdMs: 250,
    scaleDownIdleMs: 300000,
  });
});
