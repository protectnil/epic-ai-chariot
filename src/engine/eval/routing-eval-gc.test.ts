/**
 * Epic AI® Chariot — G-C-grade route-correct assertion unit tests (CHARIOT-SPEC §4.5)
 *
 * Derived from the clause's own failure enumeration:
 *   "route-correct means the exact canonical tool_id ... is the gold tool —
 *   not the router's top-1 offer and not merely the correct adapter/server
 *   ... The current routing-eval.ts deduplicates by server and passes on
 *   expected-server-present, so it is insufficient for G-C."
 *
 * The load-bearing case is #3: a shortlist that contains the WRONG tool from
 * the RIGHT server must PASS the old (§4.5-flagged) check while FAILING the
 * new G-C check — proving the new function actually closes the gap the
 * clause names, not merely duplicating the old behavior under a new name.
 *
 * Run: node --test dist/engine/eval/routing-eval-gc.test.js
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertRouteCorrectGC, assertRouteCorrectServerDedup } from './routing-eval-gc.js';

test('assertRouteCorrectGC hits on the exact tool_id and reports its ordered rank', () => {
  const r = assertRouteCorrectGC(
    ['stripe:list_customers', 'stripe:create_refund', 'other:x'],
    'stripe:create_refund',
  );
  assert.equal(r.hit, true);
  assert.equal(r.rank, 2);
});

test('assertRouteCorrectGC misses when the gold tool_id is absent entirely', () => {
  const r = assertRouteCorrectGC(['stripe:list_customers', 'other:x'], 'stripe:create_refund');
  assert.equal(r.hit, false);
  assert.equal(r.rank, null);
});

test('§4.5 THE failure class: right server / wrong tool PASSES the old server-dedup check but FAILS G-C', () => {
  // Gold tool is stripe:create_refund. The shortlist offers a DIFFERENT
  // stripe tool (list_customers) — never the gold one.
  const selected = ['stripe:list_customers', 'other:x'];
  const expectedServer = 'stripe';
  const expectedToolId = 'stripe:create_refund';

  // OLD check — verbatim extraction of routing-eval.ts's current runTier1/
  // runTier2 logic: server-level, deduplicated.
  const selectedServers = selected.map((id) => id.split(':')[0]);
  const oldPasses = assertRouteCorrectServerDedup(selectedServers, expectedServer);
  assert.equal(oldPasses, true, 'sanity: the old check treats ANY stripe:* tool as a hit');

  // NEW G-C check — exact tool_id, no dedup — must FAIL on this exact case.
  const gc = assertRouteCorrectGC(selected, expectedToolId);
  assert.equal(gc.hit, false, 'G-C must FAIL: the shortlist offers a stripe tool, but not the gold one');
  assert.equal(gc.rank, null);
});

test('control: right server AND right tool passes BOTH the old check and G-C', () => {
  const selected = ['stripe:create_refund', 'other:x'];
  const selectedServers = selected.map((id) => id.split(':')[0]);
  assert.equal(assertRouteCorrectServerDedup(selectedServers, 'stripe'), true);
  const gc = assertRouteCorrectGC(selected, 'stripe:create_refund');
  assert.equal(gc.hit, true);
  assert.equal(gc.rank, 1);
});

test('boundary: empty shortlist never hits, in either check', () => {
  assert.equal(assertRouteCorrectServerDedup([], 'stripe'), false);
  const gc = assertRouteCorrectGC([], 'stripe:create_refund');
  assert.equal(gc.hit, false);
  assert.equal(gc.rank, null);
});

test('boundary: duplicate tool ids in the shortlist rank at the FIRST occurrence, not deduplicated away', () => {
  const r = assertRouteCorrectGC(['a:x', 'a:x', 'stripe:create_refund', 'stripe:create_refund'], 'stripe:create_refund');
  assert.equal(r.hit, true);
  assert.equal(r.rank, 3);
});

test('boundary: expectedToolId with a colon in the method segment does not confuse exact match (no partial/prefix match)', () => {
  // Guards against a naive `.startsWith`/`.includes` implementation that
  // would treat `stripe:create_refund` as matching `stripe:create_refund_v2`.
  const r = assertRouteCorrectGC(['stripe:create_refund_v2'], 'stripe:create_refund');
  assert.equal(r.hit, false, 'exact string equality only — no prefix/substring match');
});
