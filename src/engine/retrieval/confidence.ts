/**
 * @epicai/chariot — Retrieval confidence + out-of-catalog abstention
 *
 * CH-37 (calibration) and CH-49 (abstention floor), per §4.5:
 *
 *  - `retrievalConfidence` MUST track route-correctness so a probable mis-route
 *    is flagged rather than silently surfaced. The dogfood failure was a
 *    confidence stuck around 0.70-0.74 even on a wrong top-1 candidate. The
 *    calibration here is therefore a smooth, monotonic function of BOTH the
 *    absolute relevance of the top candidate AND its separation margin from the
 *    runner-up — a strong-but-ambiguous top-1 (a close runner-up) yields LOW
 *    confidence, which is exactly the mis-route signal.
 *
 *  - CH-49: the router MUST abstain (`no_match`) when the best candidate is
 *    below an absolute relevance floor — "a haircut" must not confidently route
 *    to `mercedes-benz-image`. Calibration alone is insufficient (spec), so
 *    abstention is its own hard absolute-floor gate, NOT a confidence threshold.
 *
 * The abstention/confidence signal is the strongest ABSOLUTE relevance score
 * available for a candidate — the cross-encoder rerank score when the rerank
 * stage ran, else the best raw per-leg score behind the fused entry. RRF scores
 * are deliberately NOT used as the abstention signal: dense ANN returns k
 * neighbours for ANY query (including impossible intents), so a positive RRF
 * score cannot distinguish a real match from the nearest-of-nothing.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { RetrievalResult } from './types.js';

export interface ConfidenceConfig {
  /**
   * Absolute relevance floor for CH-49 abstention. Applied via `relevanceSignal`
   * (cross-encoder rerank score when the rerank stage ran, else the BM25
   * originalScore, else 0 — NOT the fused/dense score). On the current
   * BM25-only path any single-token lexical hit (including stop words) produces
   * a BM25 score well above this value, so abstention fires only on
   * ZERO-lexical-overlap queries (no BM25 token match at all). The 0.0001
   * default is therefore an exact-zero gate, not a meaningful semantic floor.
   * The meaningful logit floor for the cross-encoder path must be calibrated
   * empirically when the BIEN reranker ships; this value must be updated at
   * that point.
   */
  relevanceFloor: number;
  /** Reference scale that saturates the absolute-strength term toward 1. */
  relevanceScale: number;
  /** Blend weight on the separation margin vs absolute strength, in [0,1]. */
  marginWeight: number;
}

export const DEFAULT_CONFIDENCE_CONFIG: ConfidenceConfig = {
  relevanceFloor: 0.0001,
  relevanceScale: 4.0,
  marginWeight: 0.5,
};

function clamp01(x: number): number {
  if (Number.isNaN(x)) return 0;
  if (x < 0) return 0;
  if (x > 1) return 1;
  return x;
}

/**
 * Strength signal for the CONFIDENCE value (not abstention): the cross-encoder
 * rerank score if present, else the best raw per-leg score, else the fused
 * score. Dense similarity is allowed here because confidence is relative.
 */
export function absoluteSignal(r: RetrievalResult): number {
  if (r.rerankScore !== undefined) return r.rerankScore;
  let best = Number.NEGATIVE_INFINITY;
  for (const s of r.fusionSources) {
    if (s.originalScore > best) best = s.originalScore;
  }
  if (best === Number.NEGATIVE_INFINITY) return r.fusionScore;
  return best;
}

/**
 * CALIBRATED RELEVANCE signal for the CH-49 abstention floor. This deliberately
 * does NOT trust raw dense/sparse similarity: an ANN index returns its nearest
 * neighbours for ANY query (including impossible intents), so a positive dense
 * score is not evidence of relevance. The abstention signal is therefore the
 * cross-encoder rerank score when the rerank stage ran (the shipped stack always
 * reranks), else the lexical BM25 grounding (zero lexical overlap → 0 → abstain).
 * A dense/sparse-only candidate with no rerank and no lexical overlap scores 0
 * and abstains — surfacing a confident top-1 from raw ANN similarity alone is
 * exactly the "confident absurd top-1" the spec forbids.
 */
export function relevanceSignal(r: RetrievalResult): number {
  // Fail-closed sanitization: a NaN/±Infinity score is NOT evidence of
  // relevance. Coerce non-finite signals to 0 so a misbehaving scorer (or a
  // corrupt BM25 input) trips the CH-49 abstention floor instead of silently
  // defeating it (NaN < floor is false — a fail-open comparison).
  if (r.rerankScore !== undefined) {
    return Number.isFinite(r.rerankScore) ? r.rerankScore : 0;
  }
  for (const s of r.fusionSources) {
    if (s.type === 'bm25') {
      return Number.isFinite(s.originalScore) ? s.originalScore : 0;
    }
  }
  return 0;
}

export interface ConfidenceVerdict {
  /** Calibrated [0,1] confidence in the top-1 (CH-37). */
  confidence: number;
  /** True when the best candidate is below the relevance floor (CH-49). */
  abstain: boolean;
}

/**
 * Compute the calibrated confidence and the CH-49 abstention verdict for a
 * ranked, fused (optionally reranked) list. Deterministic and pure.
 */
export function scoreConfidence(
  ranked: RetrievalResult[],
  config: ConfidenceConfig = DEFAULT_CONFIDENCE_CONFIG,
): ConfidenceVerdict {
  if (ranked.length === 0) {
    return { confidence: 0, abstain: true };
  }

  const top = absoluteSignal(ranked[0]);
  // CH-49: hard absolute-floor abstention on the CALIBRATED relevance signal
  // (rerank score, else lexical BM25 grounding — never raw dense similarity).
  // Calibration (the confidence value) is explicitly not a substitute.
  // FAIL-CLOSED form: abstain unless the signal PROVABLY clears the floor —
  // `!(x >= floor)` abstains on NaN (NaN >= floor is false), whereas
  // `x < floor` would fail open on NaN. relevanceSignal additionally
  // sanitizes non-finite inputs to 0 as defense-in-depth.
  const abstain = !(relevanceSignal(ranked[0]) >= config.relevanceFloor);

  // Absolute-strength term: saturating, monotonic, never pinned to a constant.
  const absNorm = top <= 0 ? 0 : clamp01(top / (top + config.relevanceScale));

  // Separation margin from the runner-up: a close #2 means the top-1 is
  // ambiguous → lower confidence (the calibration the spec demands).
  let marginNorm = 1;
  if (ranked.length > 1) {
    const second = absoluteSignal(ranked[1]);
    const denom = Math.abs(top) + 1e-9;
    marginNorm = clamp01((top - second) / denom);
  }

  const w = clamp01(config.marginWeight);
  const confidence = clamp01((1 - w) * absNorm + w * marginNorm);

  return { confidence, abstain };
}
