/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: pure metrics
 *
 * Deterministic, dependency-free scoring primitives. Every function here is
 * pure (no I/O, no clock, no randomness) so the unit suite can pin exact
 * values against known fixtures — the metric code itself must be provably
 * correct before any number it produces can back a claim (§1.4 "provable").
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createHash } from 'node:crypto';
import { wilsonLowerBound } from '../GateMetrics.js';

/**
 * One-sided 95% Wilson lower confidence bound of a binomial proportion
 * (successes/n), re-exported from the already-tested `GateMetrics.wilsonLowerBound`
 * (default z=1.6448536269514722, the one-sided 95% z-score) rather than
 * reimplementing the formula a second time. Used by `aggregate()` to report
 * a Wilson-bounded hit-rate alongside the point estimate (§4.5's release-gate
 * pattern applied to the proof artifact's hit-rate/recall figures — never the
 * point estimate alone).
 */
export function hitRateWilsonLcb95(successes: number, n: number): number {
  return wilsonLowerBound(successes, n);
}

/** Top-k slice of an ordered candidate list. k <= 0 yields the empty set. */
export function topK<T>(ordered: readonly T[], k: number): T[] {
  if (!Number.isFinite(k) || k <= 0) return [];
  return ordered.slice(0, k);
}

/**
 * Recall@k = |relevant ∩ top-k| / |relevant|.
 * The §4.5 headline metric. Returns 0 when there are no relevant labels
 * (an unlabeled query contributes nothing rather than a spurious 1.0).
 */
export function recallAtK(
  returnedIds: readonly string[],
  relevantIds: readonly string[],
  k: number,
): number {
  const relevant = new Set(relevantIds);
  if (relevant.size === 0) return 0;
  const considered = topK(returnedIds, k);
  let hit = 0;
  const seen = new Set<string>();
  for (const id of considered) {
    if (relevant.has(id) && !seen.has(id)) {
      hit += 1;
      seen.add(id);
    }
  }
  return hit / relevant.size;
}

/**
 * Precision@k = |relevant ∩ top-k| / k.
 * Denominator is k (the fixed candidate budget exposed to the LLM), so a
 * retriever is not rewarded for returning fewer candidates than requested.
 * Returns 0 when k ≤ 0 or nothing was returned.
 */
export function precisionAtK(
  returnedIds: readonly string[],
  relevantIds: readonly string[],
  k: number,
): number {
  const relevant = new Set(relevantIds);
  const considered = topK(returnedIds, k);
  if (considered.length === 0) return 0;
  let hit = 0;
  const seen = new Set<string>();
  for (const id of considered) {
    if (relevant.has(id) && !seen.has(id)) {
      hit += 1;
      seen.add(id);
    }
  }
  return hit / k;
}

/** Ordered intersection of top-k with the relevant set (dedup, top-k order). */
export function hitsAtK(
  returnedIds: readonly string[],
  relevantIds: readonly string[],
  k: number,
): string[] {
  const relevant = new Set(relevantIds);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const id of topK(returnedIds, k)) {
    if (relevant.has(id) && !seen.has(id)) {
      out.push(id);
      seen.add(id);
    }
  }
  return out;
}

/**
 * NDCG@k (binary relevance, log2 discount, standard IR definition):
 *   DCG@k  = Σ_{i=1..k} rel(i) / log2(i+1)   (1-based position i; rel(i) ∈ {0,1})
 *   IDCG@k = Σ_{i=1..min(k,|relevant|)} 1 / log2(i+1)   (ideal ordering: all
 *            relevant items first)
 *   NDCG@k = DCG@k / IDCG@k, defined as 0 when IDCG@k = 0 (no relevant labels
 *            — mirrors recallAtK's convention of contributing 0, not a
 *            spurious 1.0).
 * Duplicate ids in `returnedIds` are NOT double-counted (relevance is credited
 * only once per distinct id, matching recallAtK/precisionAtK/hitsAtK above).
 */
export function ndcgAtK(
  returnedIds: readonly string[],
  relevantIds: readonly string[],
  k: number,
): number {
  const relevant = new Set(relevantIds);
  const considered = topK(returnedIds, k);
  const seen = new Set<string>();
  let dcg = 0;
  for (let i = 0; i < considered.length; i += 1) {
    const id = considered[i];
    if (relevant.has(id) && !seen.has(id)) {
      seen.add(id);
      dcg += 1 / Math.log2(i + 2); // i is 0-based here; position = i+1, so log2((i+1)+1)
    }
  }
  const idealHits = Math.min(k > 0 ? k : 0, relevant.size);
  let idcg = 0;
  for (let i = 0; i < idealHits; i += 1) {
    idcg += 1 / Math.log2(i + 2);
  }
  return idcg === 0 ? 0 : dcg / idcg;
}

/**
 * 1-based rank of the first relevant id within top-k, or null if none.
 * (Used for MRR and Hit@1 diagnostics — never the headline claim.)
 */
export function firstRelevantRank(
  returnedIds: readonly string[],
  relevantIds: readonly string[],
  k: number,
): number | null {
  const relevant = new Set(relevantIds);
  const considered = topK(returnedIds, k);
  for (let i = 0; i < considered.length; i += 1) {
    if (relevant.has(considered[i])) return i + 1;
  }
  return null;
}

/** Reciprocal rank = 1 / firstRelevantRank, or 0 when no relevant in top-k. */
export function reciprocalRank(
  returnedIds: readonly string[],
  relevantIds: readonly string[],
  k: number,
): number {
  const rank = firstRelevantRank(returnedIds, relevantIds, k);
  return rank === null ? 0 : 1 / rank;
}

/**
 * Percentile via the nearest-rank method (no interpolation): for p in [0,100],
 * rank = ceil(p/100 * n), value = sorted-ascending[rank-1]. p=0 → min.
 * Reports a REAL order statistic, never a mean. Empty input → NaN.
 */
export function percentile(values: readonly number[], p: number): number {
  if (values.length === 0) return Number.NaN;
  if (!Number.isFinite(p) || p < 0 || p > 100) {
    throw new RangeError(`percentile p must be in [0,100], got ${p}`);
  }
  const sorted = [...values].sort((a, b) => a - b);
  if (p <= 0) return sorted[0];
  const rank = Math.ceil((p / 100) * sorted.length);
  const idx = Math.min(sorted.length - 1, Math.max(0, rank - 1));
  return sorted[idx];
}

export interface LatencySummary {
  count: number;
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}

/** Full latency summary (min/p50/p95/p99/max/mean) over raw samples. */
export function summarizeLatencies(samples: readonly number[]): LatencySummary {
  const count = samples.length;
  const mean = count === 0 ? Number.NaN : samples.reduce((s, v) => s + v, 0) / count;
  return {
    count,
    min: percentile(samples, 0),
    p50: percentile(samples, 50),
    p95: percentile(samples, 95),
    p99: percentile(samples, 99),
    max: percentile(samples, 100),
    mean,
  };
}

/** sha256 hex of a UTF-8 string. */
export function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

/**
 * Determinism witness for a candidate set: sha256 of the ORDERED, newline-
 * joined tool-id list. Order is significant — a reordering is a determinism
 * failure under the §8.6 100%-selection-repeatability invariant, so this
 * intentionally does NOT sort before hashing.
 */
export function hashCandidateSet(orderedIds: readonly string[]): string {
  return sha256Hex(orderedIds.join('\n'));
}

/** Round to `digits` decimals for stable artifact serialization. */
export function round(value: number, digits = 4): number {
  if (!Number.isFinite(value)) return value;
  const f = 10 ** digits;
  return Math.round(value * f) / f;
}
