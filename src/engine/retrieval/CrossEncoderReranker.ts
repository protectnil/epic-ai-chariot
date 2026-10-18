/**
 * @epicai/chariot — Cross-Encoder Reranker
 *
 * §8.6 step 7 / §4.1: after RRF fuses the dense + sparse + BM25 legs, the fused
 * shortlist is reranked by the pretrained `cross-encoder/ms-marco-MiniLM-L6-v2`
 * (the LLM-free re-ranking router of BIEN §7, LOCKED), run for CPU-capable
 * inference-time ordering — see `SHIPPED_RERANKER_MODEL` in
 * `src/engine/server/ChariotState.ts`. This is LLM-free: it scores (query,
 * document) pairs with a pluggable `RerankScorer`, never an agent reasoning
 * model. (CORRECTED 2026-08-09, MASTER chat authorization: this file
 * previously said "a fine-tuned cross-encoder" / "native fine-tuned
 * cross-encoder ONNX" — that was defective; CHARIOT-SPEC.md §4.1 states the
 * fine-tuned model is BIEN's DENSE encoder, not the reranker, which is
 * pretrained.)
 *
 * DETERMINISM (§8.6 / CH-23): rerank runs **brute-force over the entire fixed
 * shortlist** — every candidate is rescored, none pruned by an approximate
 * stage — and the final order is sorted by rerank score descending with a
 * lexicographic id tie-break, so the candidate set is byte-identical across
 * runs, replicas, and restarts for a fixed scorer.
 *
 * The native pretrained cross-encoder ONNX lands with BIEN M10 / P2; until
 * then any deterministic `RerankScorer` satisfies the interface and the stage
 * is a no-op when no scorer is wired (the fused order passes through
 * unchanged).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { RetrievalResult, RerankScorer } from './types.js';

export class CrossEncoderReranker {
  constructor(private readonly scorer: RerankScorer) {}

  /**
   * Rerank a fused shortlist. The document text for each candidate is taken
   * from `result.content`; candidates without content fall back to their id so
   * the scorer always receives a stable, non-empty string (a missing-content
   * candidate must not be silently dropped). The returned list is the same set,
   * reordered by rerank score (desc) with a lexicographic id tie-break.
   *
   * Brute-force: O(shortlist) scorer calls — intended for the bounded post-RRF
   * shortlist, not the full 29,633-tool index (§8.6 "exact brute-force
   * rescoring over the fixed shortlist").
   */
  rerank(query: string, shortlist: RetrievalResult[]): RetrievalResult[] {
    if (shortlist.length === 0) return shortlist;

    const docs = shortlist.map((r) => r.content ?? r.id);
    const scores = this.scorer.score(query, docs);
    if (scores.length !== shortlist.length) {
      throw new Error(
        `RerankScorer returned ${scores.length} scores for ${shortlist.length} documents`,
      );
    }

    // Sanitize scorer output: a NaN/±Infinity score would poison the sort
    // comparator (NaN diff → implementation-defined order, breaking §8.6
    // determinism) and defeat the CH-49 abstention comparison downstream.
    // Non-finite scores are coerced to -Infinity's finite stand-in via
    // NEGATIVE_INFINITY-safe ordering: rank last, deterministically, and let
    // the confidence/abstention layer treat them as zero-evidence.
    const rescored: RetrievalResult[] = shortlist.map((r, i) => ({
      ...r,
      rerankScore: Number.isFinite(scores[i]) ? scores[i] : Number.NEGATIVE_INFINITY,
    }));

    rescored.sort((a, b) => {
      // Explicit comparisons (not subtraction) so ±Infinity ties cannot
      // produce a NaN comparator result — order stays deterministic.
      const as = a.rerankScore ?? 0;
      const bs = b.rerankScore ?? 0;
      if (bs > as) return 1;
      if (bs < as) return -1;
      // Deterministic tie-break: lexicographic ascending by id.
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });

    return rescored;
  }
}
