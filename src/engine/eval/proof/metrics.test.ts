/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: metrics + scoring unit tests
 *
 * Pins exact values for every pure scoring primitive against fixed fixtures.
 * The metric code must be provably correct before any number it produces can
 * back a claim (§1.4 "provable"). Run: node --test dist/engine/eval/proof/metrics.test.js
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  topK,
  recallAtK,
  precisionAtK,
  ndcgAtK,
  hitsAtK,
  firstRelevantRank,
  reciprocalRank,
  percentile,
  summarizeLatencies,
  sha256Hex,
  hashCandidateSet,
  hitRateWilsonLcb95,
  round,
} from './metrics.js';
import { evaluateQuery, aggregate } from './scoring.js';
import type { GoldQuery, PerQueryResult } from './types.js';

const close = (a: number, b: number, eps = 1e-9): boolean => Math.abs(a - b) < eps;

test('topK slices, clamps, and rejects non-positive k', () => {
  assert.deepEqual(topK(['a', 'b', 'c'], 2), ['a', 'b']);
  assert.deepEqual(topK(['a', 'b'], 5), ['a', 'b']);
  assert.deepEqual(topK(['a', 'b'], 0), []);
  assert.deepEqual(topK(['a', 'b'], -1), []);
  assert.deepEqual(topK(['a', 'b'], Number.NaN), []);
});

test('recallAtK = |relevant ∩ top-k| / |relevant|', () => {
  assert.equal(recallAtK(['a', 'b', 'c', 'd'], ['b', 'd'], 4), 1);
  assert.equal(recallAtK(['a', 'b', 'c', 'd'], ['b', 'x'], 4), 0.5);
  assert.equal(recallAtK(['a', 'b', 'c', 'd'], ['x'], 4), 0);
  // out of the top-k window
  assert.equal(recallAtK(['a', 'b', 'c', 'd'], ['c'], 2), 0);
  // no relevant labels → 0, not a spurious 1.0
  assert.equal(recallAtK(['a'], [], 4), 0);
  // duplicate returned ids are not double-counted
  assert.equal(recallAtK(['b', 'b', 'd'], ['b', 'd'], 3), 1);
});

test('precisionAtK denominator is k (fixed budget, not actual returned count)', () => {
  assert.equal(precisionAtK(['a', 'b', 'c', 'd'], ['b', 'd'], 4), 0.5);
  assert.equal(precisionAtK(['a', 'b', 'c', 'd'], ['b', 'd'], 2), 0.5); // top2=[a,b], hit b
  assert.equal(precisionAtK(['a', 'b'], ['b'], 8), 0.125); // 1/8 — <k returns do not inflate precision
  assert.equal(precisionAtK([], ['b'], 8), 0);
});

test('hitsAtK returns ordered, deduped intersection', () => {
  assert.deepEqual(hitsAtK(['a', 'b', 'c', 'd'], ['d', 'b'], 4), ['b', 'd']);
  assert.deepEqual(hitsAtK(['b', 'b', 'd'], ['b', 'd'], 3), ['b', 'd']);
  assert.deepEqual(hitsAtK(['a'], ['x'], 4), []);
});

test('firstRelevantRank is 1-based within top-k, else null', () => {
  assert.equal(firstRelevantRank(['a', 'b', 'c'], ['b'], 3), 2);
  assert.equal(firstRelevantRank(['a', 'b', 'c'], ['a'], 3), 1);
  assert.equal(firstRelevantRank(['a', 'b', 'c'], ['x'], 3), null);
  assert.equal(firstRelevantRank(['a', 'b', 'c'], ['c'], 2), null); // out of window
});

test('reciprocalRank = 1/rank, 0 when none', () => {
  assert.equal(reciprocalRank(['a', 'b'], ['b'], 2), 0.5);
  assert.equal(reciprocalRank(['a', 'b'], ['a'], 2), 1);
  assert.equal(reciprocalRank(['a', 'b'], ['x'], 2), 0);
});

test('percentile uses nearest-rank (no interpolation)', () => {
  const v = [1, 2, 3, 4, 5];
  assert.equal(percentile(v, 0), 1);
  assert.equal(percentile(v, 50), 3);
  assert.equal(percentile(v, 95), 5);
  assert.equal(percentile(v, 99), 5);
  assert.equal(percentile(v, 100), 5);
  assert.equal(percentile([5, 3, 1, 4, 2], 50), 3); // sorts internally
  assert.equal(percentile([42], 50), 42);
  assert.ok(Number.isNaN(percentile([], 50)));
  assert.throws(() => percentile(v, 101), RangeError);
  assert.throws(() => percentile(v, -1), RangeError);
});

test('summarizeLatencies reports real order statistics + mean', () => {
  const s = summarizeLatencies([1, 2, 3, 4, 5]);
  assert.equal(s.count, 5);
  assert.equal(s.min, 1);
  assert.equal(s.p50, 3);
  assert.equal(s.p95, 5);
  assert.equal(s.p99, 5);
  assert.equal(s.max, 5);
  assert.equal(s.mean, 3);
});

test('hashCandidateSet is order-sensitive, stable, and matches sha256 of the joined list', () => {
  assert.equal(hashCandidateSet(['a', 'b']), sha256Hex('a\nb'));
  assert.equal(hashCandidateSet(['a', 'b']), hashCandidateSet(['a', 'b'])); // stable
  assert.notEqual(hashCandidateSet(['a', 'b']), hashCandidateSet(['b', 'a'])); // order matters
});

// ─── ndcgAtK ─────────────────────────────────────────────────────────────────
// Known-answer vectors derived directly from the standard IR NDCG definition
// (see metrics.ts docstring): DCG@k = Σ rel(i)/log2(i+1), IDCG@k = ideal
// ordering's DCG@k, NDCG@k = DCG@k/IDCG@k (0 when IDCG@k = 0).

test('ndcgAtK: perfect ordering (all relevant first) scores 1.0', () => {
  // relevant = {b,d}; returned puts both relevant items in positions 1,2.
  assert.ok(close(ndcgAtK(['b', 'd', 'a', 'c'], ['b', 'd'], 4), 1));
});

test('ndcgAtK: single relevant item at rank 1 scores 1.0 (trivially ideal)', () => {
  assert.equal(ndcgAtK(['a', 'b', 'c'], ['a'], 3), 1);
});

test('ndcgAtK: single relevant item at rank 2 — DCG=1/log2(3), IDCG=1/log2(2)', () => {
  const expected = (1 / Math.log2(3)) / (1 / Math.log2(2));
  assert.ok(close(ndcgAtK(['x', 'a', 'y'], ['a'], 3), expected));
});

test('ndcgAtK: worst ordering (relevant items last) scores below 1.0 but above 0', () => {
  // relevant = {b,d}; returned puts them LAST within the k=4 window.
  const dcg = 1 / Math.log2(4) + 1 / Math.log2(5); // ranks 3,4 (1-based)
  const idcg = 1 / Math.log2(2) + 1 / Math.log2(3); // ideal: ranks 1,2
  assert.ok(close(ndcgAtK(['a', 'c', 'b', 'd'], ['b', 'd'], 4), dcg / idcg));
  assert.ok(ndcgAtK(['a', 'c', 'b', 'd'], ['b', 'd'], 4) < 1);
});

test('ndcgAtK: no relevant labels → 0, not a spurious 1.0 (mirrors recallAtK)', () => {
  assert.equal(ndcgAtK(['a', 'b'], [], 4), 0);
});

test('ndcgAtK: no relevant item within top-k → 0', () => {
  assert.equal(ndcgAtK(['a', 'b', 'c'], ['x'], 3), 0);
  // relevant present in the full list but OUTSIDE the k window
  assert.equal(ndcgAtK(['a', 'b', 'c', 'd'], ['d'], 2), 0);
});

test('ndcgAtK: boundary k <= 0 → 0 (topK yields empty, IDCG computed over min(0,|relevant|)=0)', () => {
  assert.equal(ndcgAtK(['a', 'b'], ['a'], 0), 0);
  assert.equal(ndcgAtK(['a', 'b'], ['a'], -1), 0);
});

test('ndcgAtK: empty returned list → 0', () => {
  assert.equal(ndcgAtK([], ['a'], 4), 0);
});

test('ndcgAtK: duplicate ids in returned list are not double-counted (matches hitsAtK convention)', () => {
  // relevant = {b}; 'b' appears twice — must not inflate DCG by crediting it twice.
  const dcg = 1 / Math.log2(2); // credited once, at its first (best) occurrence, rank 1
  const idcg = 1 / Math.log2(2); // single relevant label → ideal DCG is the same
  assert.ok(close(ndcgAtK(['b', 'b', 'a'], ['b'], 3), dcg / idcg));
  assert.equal(ndcgAtK(['b', 'b', 'a'], ['b'], 3), 1);
});

test('ndcgAtK: ties in the relevant set — more relevant labels than k caps IDCG at k', () => {
  // relevant = {a,b,c,d} (4 labels) but k=2: IDCG uses min(k,|relevant|)=2 ideal slots.
  const idcg = 1 / Math.log2(2) + 1 / Math.log2(3);
  const dcg = 1 / Math.log2(2) + 1 / Math.log2(3); // both k=2 slots are relevant (a,b)
  assert.ok(close(ndcgAtK(['a', 'b', 'x', 'y'], ['a', 'b', 'c', 'd'], 2), dcg / idcg));
  assert.equal(ndcgAtK(['a', 'b', 'x', 'y'], ['a', 'b', 'c', 'd'], 2), 1);
});

// ─── hitRateWilsonLcb95 ──────────────────────────────────────────────────────
// Thin re-export over the already-tested GateMetrics.wilsonLowerBound (not a
// second implementation) — pin that the re-export forwards correctly.

test('hitRateWilsonLcb95: 0 successes of n → 0', () => {
  assert.equal(hitRateWilsonLcb95(0, 10), 0);
});

test('hitRateWilsonLcb95: all successes is strictly below the point estimate (1.0) for finite n', () => {
  const lcb = hitRateWilsonLcb95(10, 10);
  assert.ok(lcb < 1 && lcb > 0.6, `expected a bounded LCB in (0.6,1), got ${lcb}`);
});

test('hitRateWilsonLcb95: LCB is monotonically non-decreasing in n at a fixed proportion', () => {
  const small = hitRateWilsonLcb95(9, 10);
  const large = hitRateWilsonLcb95(900, 1000);
  assert.ok(large > small, `expected larger-n LCB (${large}) > smaller-n LCB (${small}) at the same 90% rate`);
});

test('hitRateWilsonLcb95: rejects invalid inputs (delegates to GateMetrics.wilsonLowerBound)', () => {
  assert.throws(() => hitRateWilsonLcb95(-1, 10), RangeError);
  assert.throws(() => hitRateWilsonLcb95(11, 10), RangeError);
  assert.throws(() => hitRateWilsonLcb95(1, 0), RangeError);
});

test('round to 4 decimals; passes through non-finite', () => {
  assert.equal(round(0.123456), 0.1235);
  assert.ok(close(round(1 / 3), 0.3333));
  assert.equal(round(0.5), 0.5);
  assert.ok(Number.isNaN(round(Number.NaN)));
  assert.equal(round(1.23456, 2), 1.23);
});

// ─── scoring composition ─────────────────────────────────────────────────────

const goldFixture = (over: Partial<GoldQuery> = {}): GoldQuery => ({
  id: 'T1',
  query: 'do the thing',
  relevantToolIds: ['svc:b', 'svc:d'],
  domain: 'x',
  style: 'natural-intent',
  labelBasis: 'fixture',
  ...over,
});

test('evaluateQuery composes per-query result and propagates flags', () => {
  const r = evaluateQuery(goldFixture(), ['svc:a', 'svc:b', 'svc:c'], 8);
  assert.equal(r.id, 'T1');
  assert.equal(r.recallAtK, 0.5); // {b} of {b,d}
  assert.ok(close(r.precisionAtK, 1 / 8)); // 1 hit / k=8 (denominator is k, not actual returned count)
  assert.ok(close(r.ndcgAtK, ndcgAtK(['svc:a', 'svc:b', 'svc:c'], ['svc:b', 'svc:d'], 8)));
  assert.equal(r.firstRelevantRank, 2);
  assert.equal(r.reciprocalRank, 0.5);
  assert.deepEqual(r.hitToolIds, ['svc:b']);
  assert.deepEqual(r.returnedToolIds, ['svc:a', 'svc:b', 'svc:c']);
  assert.equal(r.candidateSetSha256, hashCandidateSet(['svc:a', 'svc:b', 'svc:c']));
  assert.equal(r.bugRef, undefined);
  assert.equal(r.pendingP4, undefined);

  const flagged = evaluateQuery(goldFixture({ bugRef: 'biomedical-misroute-repro', pendingP4: true }), ['svc:b'], 8);
  assert.equal(flagged.bugRef, 'biomedical-misroute-repro');
  assert.equal(flagged.pendingP4, true);
});

const pqr = (over: Partial<PerQueryResult>): PerQueryResult => ({
  id: 'r',
  query: 'q',
  domain: 'x',
  style: 'natural-intent',
  relevantToolIds: ['a'],
  returnedToolIds: [],
  hitToolIds: [],
  recallAtK: 0,
  precisionAtK: 0,
  ndcgAtK: 0,
  firstRelevantRank: null,
  reciprocalRank: 0,
  candidateSetSha256: 'x',
  ...over,
});

test('aggregate computes macro/micro recall, hit@1, floor verdict', () => {
  const hit = pqr({ id: 'h', relevantToolIds: ['a'], hitToolIds: ['a'], recallAtK: 1, firstRelevantRank: 1, reciprocalRank: 1, precisionAtK: 1 });
  const miss = pqr({ id: 'm', relevantToolIds: ['a'], hitToolIds: [], recallAtK: 0, firstRelevantRank: null });
  const agg = aggregate([hit, miss], 8, 0.95);
  assert.equal(agg.queryCount, 2);
  assert.equal(agg.macroRecallAtK, 0.5);
  assert.equal(agg.microRecallAtK, 0.5); // (1+0)/(1+1)
  assert.equal(agg.hitAt1, 0.5);
  assert.equal(agg.anyHitAtK, 0.5);
  assert.equal(agg.meetsFloor, false);
  assert.equal(agg.excludingPendingP4, undefined); // nothing pending
  // hit-rate Wilson LCB(1,2) must be strictly below the point estimate 0.5
  assert.ok(agg.hitRateWilsonLcb95 < 0.5 && agg.hitRateWilsonLcb95 >= 0);
});

test('aggregate attaches excludingPendingP4 when a pending-P4 miss is present', () => {
  const hit = pqr({ id: 'h', relevantToolIds: ['a'], hitToolIds: ['a'], recallAtK: 1, firstRelevantRank: 1, reciprocalRank: 1 });
  const pendingMiss = pqr({ id: 'p', relevantToolIds: ['a'], hitToolIds: [], recallAtK: 0, firstRelevantRank: null, pendingP4: true });
  const agg = aggregate([hit, pendingMiss], 8, 0.95);
  assert.equal(agg.macroRecallAtK, 0.5);
  assert.ok(agg.excludingPendingP4);
  assert.equal(agg.excludingPendingP4!.macroRecallAtK, 1); // only the hit remains
  assert.equal(agg.excludingPendingP4!.meetsFloor, true);
  assert.equal(agg.excludingPendingP4!.queryCount, 1);
});

test('aggregate handles empty input without NaN', () => {
  const agg = aggregate([], 8, 0.95);
  assert.equal(agg.queryCount, 0);
  assert.equal(agg.macroRecallAtK, 0);
  assert.equal(agg.microRecallAtK, 0);
  assert.equal(agg.meetsFloor, false);
  assert.ok(Number.isNaN(agg.hitRateWilsonLcb95)); // 0/0 proportion is undefined, never fabricated as 0 or 1
});
