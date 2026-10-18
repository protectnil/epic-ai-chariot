/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: pure scoring composition
 *
 * Composes the pure primitives in `metrics.ts` into the per-query and aggregate
 * result shapes the artifact reports. Every function here is pure (no I/O, no
 * clock, no randomness): the retriever has already been called and its ORDERED
 * candidate ids handed in, so the scoring is exactly reproducible and unit-
 * testable against fixed fixtures — the numbers must be provably correct before
 * any of them can back a claim (§1.4 "provable").
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import {
  recallAtK,
  precisionAtK,
  ndcgAtK,
  hitsAtK,
  firstRelevantRank,
  reciprocalRank,
  hashCandidateSet,
  hitRateWilsonLcb95,
  topK,
} from './metrics.js';
import type {
  GoldQuery,
  PerQueryResult,
  AggregateMetrics,
} from './types.js';

/**
 * Score one gold query against a retriever's ORDERED candidate ids.
 * `returnedIds` is the candidate shortlist as returned (already best-first and
 * capped at k by the retriever); it is treated as the exact set the LLM is
 * offered. The candidate-set hash is computed over that ordered list — order is
 * significant (a reorder is a determinism failure, §8.6).
 */
export function evaluateQuery(
  q: GoldQuery,
  returnedIds: readonly string[],
  k: number,
): PerQueryResult {
  const returnedTopK = topK(returnedIds, k);
  return {
    id: q.id,
    query: q.query,
    domain: q.domain,
    style: q.style,
    relevantToolIds: [...q.relevantToolIds],
    returnedToolIds: returnedTopK,
    hitToolIds: hitsAtK(returnedIds, q.relevantToolIds, k),
    recallAtK: recallAtK(returnedIds, q.relevantToolIds, k),
    precisionAtK: precisionAtK(returnedIds, q.relevantToolIds, k),
    ndcgAtK: ndcgAtK(returnedIds, q.relevantToolIds, k),
    firstRelevantRank: firstRelevantRank(returnedIds, q.relevantToolIds, k),
    reciprocalRank: reciprocalRank(returnedIds, q.relevantToolIds, k),
    candidateSetSha256: hashCandidateSet(returnedTopK),
    ...(q.bugRef ? { bugRef: q.bugRef } : {}),
    ...(q.pendingP4 ? { pendingP4: q.pendingP4 } : {}),
  };
}

function mean(values: readonly number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((s, v) => s + v, 0) / values.length;
}

function fraction(results: readonly PerQueryResult[], pred: (r: PerQueryResult) => boolean): number {
  if (results.length === 0) return 0;
  let n = 0;
  for (const r of results) if (pred(r)) n += 1;
  return n / results.length;
}

/**
 * Aggregate per-query results into the headline metrics (§4.5). `macroRecallAtK`
 * (mean of per-query recall) is the headline measured against `recallFloor`.
 * `microRecallAtK` pools hits over all relevant labels. When `withPendingP4Split`
 * is true and any query is flagged pending-P4, an `excludingPendingP4` block is
 * attached with the same metrics restricted to non-pending queries (the
 * baseline's achievable view, since pending-P4 queries are expected BM25 misses).
 */
export function aggregate(
  results: readonly PerQueryResult[],
  k: number,
  recallFloor: number,
  withPendingP4Split = true,
): AggregateMetrics {
  let pooledHits = 0;
  let pooledRelevant = 0;
  for (const r of results) {
    pooledHits += r.hitToolIds.length;
    pooledRelevant += r.relevantToolIds.length;
  }
  const macroRecallAtK = mean(results.map((r) => r.recallAtK));
  const anyHitCount = results.filter((r) => r.firstRelevantRank !== null).length;
  const base: AggregateMetrics = {
    k,
    queryCount: results.length,
    macroRecallAtK,
    microRecallAtK: pooledRelevant === 0 ? 0 : pooledHits / pooledRelevant,
    macroPrecisionAtK: mean(results.map((r) => r.precisionAtK)),
    meanNdcgAtK: mean(results.map((r) => r.ndcgAtK)),
    meanReciprocalRank: mean(results.map((r) => r.reciprocalRank)),
    hitAt1: fraction(results, (r) => r.firstRelevantRank === 1),
    anyHitAtK: fraction(results, (r) => r.firstRelevantRank !== null),
    hitRateWilsonLcb95: results.length === 0 ? Number.NaN : hitRateWilsonLcb95(anyHitCount, results.length),
    recallFloor,
    meetsFloor: macroRecallAtK >= recallFloor,
  };

  if (withPendingP4Split) {
    const nonPending = results.filter((r) => !r.pendingP4);
    if (nonPending.length !== results.length) {
      base.excludingPendingP4 = aggregate(nonPending, k, recallFloor, false);
    }
  }
  return base;
}
