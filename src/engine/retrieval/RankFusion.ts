/**
 * @epicai/chariot — Rank Fusion
 * Reciprocal Rank Fusion (RRF), weighted fusion, and custom fusion strategies
 * for the §8.6 hybrid retrieval stack.
 *
 * Salvaged from `git show 240c415^:src/engine/retrieval/RankFusion.ts` (the
 * BM25-only excision removed the file but the fusion math is unchanged and was
 * never the reason for the excision). RRF is rank-based — no score
 * normalization — and therefore deterministic across legs (§8.6 step 6). The
 * lexicographic tie-break makes the final order independent of leg-resolution
 * order so golden-trace byte-equal comparison holds (§8.6 selection
 * determinism / CH-23).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { ScoredResult, FusionSource, RetrievalResult, RetrievalLeg } from './types.js';

/** Default RRF constant. Standard value from the original RRF paper. */
export const DEFAULT_K = 60;

export class RankFusion {
  /**
   * Reciprocal Rank Fusion — merges multiple ranked lists into one.
   * score(d) = sum over all result sets of 1 / (k + rank(d))
   *
   * Documents appearing in multiple result sets receive higher fused scores.
   * Uses Map-based O(n) deduplication.
   *
   * @param resultSets - Arrays of results from different retrieval legs
   * @param k - RRF constant (default 60)
   */
  static rrf(resultSets: { type: RetrievalLeg; results: ScoredResult[] }[], k?: number): RetrievalResult[];
  static rrf(resultSets: Record<string, readonly { toolId: string; score: number }[]>, maxTools?: number, k?: number): Array<{ toolId: string; score: number; ranks: Record<string, number> }>;
  static rrf(
    resultSets: { type: RetrievalLeg; results: ScoredResult[] }[] | Record<string, readonly { toolId: string; score: number }[]>,
    k: number = DEFAULT_K,
    legacyK?: number,
  ): RetrievalResult[] | Array<{ toolId: string; score: number; ranks: Record<string, number> }> {
    if (!Array.isArray(resultSets)) {
      const legacy = Object.entries(resultSets).map(([type, rows]) => ({
        type: type as RetrievalLeg,
        results: rows.map((row) => ({ id: row.toolId, score: row.score })),
      }));
      const fused = this.rrf(legacy, legacyK ?? k) as RetrievalResult[];
      return fused.slice(0, k).map((row) => ({
        toolId: row.id,
        score: row.fusionScore,
        ranks: Object.fromEntries(row.fusionSources.map((source) => [source.type, source.rank + 1])),
      }));
    }
    const fusedScores = new Map<string, number>();
    const fusedSources = new Map<string, FusionSource[]>();
    const documents = new Map<string, ScoredResult>();

    for (const { type, results } of resultSets) {
      for (let rank = 0; rank < results.length; rank++) {
        const result = results[rank];
        const rrfScore = 1 / (k + rank + 1);

        const currentScore = fusedScores.get(result.id) ?? 0;
        fusedScores.set(result.id, currentScore + rrfScore);

        const sources = fusedSources.get(result.id) ?? [];
        sources.push({ type, rank, originalScore: result.score });
        fusedSources.set(result.id, sources);

        // Keep the first document data encountered (leg order is caller-fixed:
        // dense, then sparse, then bm25 — so dense content/metadata wins).
        if (!documents.has(result.id)) {
          documents.set(result.id, result);
        }
      }
    }

    return this.buildResults(fusedScores, fusedSources, documents);
  }

  /**
   * Weighted fusion — each result set has a weight multiplier. Retained from
   * the salvage for completeness/§8.6 ("weighted sum, custom"); RRF is the
   * shipped default because it needs no score normalization.
   *
   * @internal No production caller exists (only `rrf` is wired, via
   * HybridRetriever). Not part of the supported public surface until a
   * caller lands; do not build on it without a spec reference.
   */
  static weighted(
    ...weightedSets: { type: RetrievalLeg; results: ScoredResult[]; weight: number }[]
  ): RetrievalResult[] {
    const fusedScores = new Map<string, number>();
    const fusedSources = new Map<string, FusionSource[]>();
    const documents = new Map<string, ScoredResult>();

    for (const { type, results, weight } of weightedSets) {
      for (let rank = 0; rank < results.length; rank++) {
        const result = results[rank];
        const weightedScore = weight * result.score;

        const currentScore = fusedScores.get(result.id) ?? 0;
        fusedScores.set(result.id, currentScore + weightedScore);

        const sources = fusedSources.get(result.id) ?? [];
        sources.push({ type, rank, originalScore: result.score });
        fusedSources.set(result.id, sources);

        if (!documents.has(result.id)) {
          documents.set(result.id, result);
        }
      }
    }

    return this.buildResults(fusedScores, fusedSources, documents);
  }

  /**
   * Custom fusion — consumer provides their own fusion function.
   *
   * @internal No production caller exists (only `rrf` is wired, via
   * HybridRetriever). Not part of the supported public surface until a
   * caller lands; do not build on it without a spec reference.
   */
  static custom(
    resultSets: Map<string, ScoredResult[]>,
    fusionFn: (results: Map<string, ScoredResult[]>) => RetrievalResult[],
  ): RetrievalResult[] {
    return fusionFn(resultSets);
  }

  private static buildResults(
    fusedScores: Map<string, number>,
    fusedSources: Map<string, FusionSource[]>,
    documents: Map<string, ScoredResult>,
  ): RetrievalResult[] {
    const results: RetrievalResult[] = [];

    for (const [id, fusionScore] of fusedScores) {
      const doc = documents.get(id);
      if (!doc) continue;

      const built: RetrievalResult = {
        id,
        fusionScore,
        fusionSources: fusedSources.get(id) ?? [],
      };
      if (doc.content !== undefined) built.content = doc.content;
      if (doc.metadata !== undefined) built.metadata = doc.metadata;
      results.push(built);
    }

    // Sort by fused score descending. Ties are broken by lexicographic
    // ascending id so the ranking is fully deterministic regardless of Map
    // insertion order (which depends on leg-resolution order and is NOT stable
    // across runs). Without a tie-breaker two tools with equal RRF scores can
    // swap positions between calls, making golden-trace byte-equal comparison
    // impossible (§8.6 selection determinism / CH-23).
    results.sort((a, b) => {
      const scoreDiff = b.fusionScore - a.fusionScore;
      if (scoreDiff !== 0) return scoreDiff;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });

    return results;
  }
}
