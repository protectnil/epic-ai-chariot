/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: confidence calibration
 *
 * 3.1.2 exposed retrieval over-confidence — a 0.95 score on a garbage query,
 * wrong routes at 0.91. This module turns confidence-vs-correctness into an
 * explicit reliability curve (binned) plus an Expected Calibration Error, so it
 * is visible whether the score can be trusted. Pure + dependency-free → unit-
 * testable against fixed fixtures.
 *
 * Confidence is expected normalized to [0,1]; the caller normalizes a retriever's
 * raw score before binning. Samples with non-finite confidence are ignored
 * (a score-less retriever yields zero samples → caller records `unavailable`).
 * Finite confidence OUTSIDE [0,1] is a contract violation and throws — silently
 * dropping such samples would empty every bin and report ECE 0 ("perfectly
 * calibrated") for a retriever whose calibration was never measured.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { CalibrationBin } from './types.js';

export interface CalibrationSample {
  /** Retrieval confidence in [0,1]. */
  confidence: number;
  /** Did the query route correctly (the outcome confidence should predict)? */
  routeCorrect: boolean;
}

/**
 * Partition samples into `binCount` equal-width confidence bins over [0,1] and,
 * per bin, report count, mean confidence, actual route-correct rate, and the gap
 * (|meanConfidence − routeCorrectRate|) — a large gap is miscalibration. The top
 * bin is inclusive of 1.0; empty bins report zeros.
 */
export function reliabilityBins(
  samples: readonly CalibrationSample[],
  binCount = 10,
): CalibrationBin[] {
  if (!Number.isInteger(binCount) || binCount <= 0) {
    throw new RangeError(`binCount must be a positive integer, got ${binCount}`);
  }
  const valid = samples.filter((s) => Number.isFinite(s.confidence));
  // FAIL CLOSED: a finite confidence outside [0,1] violates the documented
  // contract and would silently match no bin — deflating every bin count and
  // driving ECE toward 0 (false "perfectly calibrated"). Throw instead of
  // silently dropping the sample; the caller must normalize before binning.
  const outOfRange = valid.filter((s) => s.confidence < 0 || s.confidence > 1);
  if (outOfRange.length > 0) {
    throw new RangeError(
      `reliabilityBins: ${outOfRange.length} sample(s) have confidence outside [0,1] ` +
        `(e.g. ${outOfRange[0].confidence}); normalize retriever scores before binning`,
    );
  }
  const bins: CalibrationBin[] = [];
  for (let i = 0; i < binCount; i += 1) {
    const lower = i / binCount;
    const upper = (i + 1) / binCount;
    const isTop = i === binCount - 1;
    const inBin = valid.filter((s) =>
      isTop ? s.confidence >= lower && s.confidence <= upper : s.confidence >= lower && s.confidence < upper,
    );
    const count = inBin.length;
    const meanConfidence = count === 0 ? 0 : inBin.reduce((a, s) => a + s.confidence, 0) / count;
    const correct = inBin.filter((s) => s.routeCorrect).length;
    const routeCorrectRate = count === 0 ? 0 : correct / count;
    bins.push({
      lower,
      upper,
      count,
      meanConfidence,
      routeCorrectRate,
      gap: count === 0 ? 0 : Math.abs(meanConfidence - routeCorrectRate),
    });
  }
  return bins;
}

/**
 * Expected Calibration Error: count-weighted mean of the per-bin gaps. 0 = the
 * confidence perfectly tracks correctness; large = the score cannot be trusted.
 * Returns 0 for an empty sample.
 */
export function expectedCalibrationError(bins: readonly CalibrationBin[]): number {
  const total = bins.reduce((a, b) => a + b.count, 0);
  if (total === 0) return 0;
  return bins.reduce((a, b) => a + (b.count / total) * b.gap, 0);
}
