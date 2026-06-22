/**
 * @epicai/chariot — Central artifact size-cap policy.
 *
 * Every signed artifact loaded through verifyAndReadArtifact has a
 * per-artifact byte ceiling. Each ceiling must be at or below the
 * process-wide absolute ceiling; the assertion below enforces the
 * invariant at module-import time so a contributor that raises a
 * per-artifact cap past the absolute is caught at startup, not in
 * production via opaque "oversize" errors.
 *
 * To add a new signed artifact:
 *   1. Add its cap to the ARTIFACT_LIMITS table.
 *   2. Pass that cap as the `maxBytes` argument to verifyAndReadArtifact.
 *   3. If the new cap exceeds ABSOLUTE_MAX_ARTIFACT_BYTES, raise the
 *      absolute first — never silently above.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/**
 * Process-wide absolute ceiling. Every per-artifact cap must be at or
 * below this value. Acts as the anti-DoS upper bound regardless of any
 * future caller's `maxBytes` argument.
 */
export const ABSOLUTE_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;

/**
 * Per-artifact byte ceilings. Read by each loader's verifyAndReadArtifact
 * call site. Add new artifacts here, not as local constants.
 */
export const ARTIFACT_LIMITS = {
  /** chariot-adapter-bundle.json / chariot-adapter-catalog.json /
   *  chariot-mcp-registry.json. Historically called MAX_CATALOG_BYTES. */
  catalog: 64 * 1024 * 1024,
  /** vector-index.json — dense+sparse routing artifact. Currently ~85 MB
   *  at v3.0.7; 256 MB leaves headroom for future catalog growth. */
  vectorIndex: 256 * 1024 * 1024,
} as const;

/**
 * Compile-and-runtime invariant: every per-artifact cap must be at or
 * below the absolute ceiling. Runs at module import; throws at startup
 * if violated so the failure is unambiguous, not a downstream "oversize"
 * surprise.
 */
for (const [name, cap] of Object.entries(ARTIFACT_LIMITS)) {
  if (!Number.isFinite(cap) || cap < 0 || cap > ABSOLUTE_MAX_ARTIFACT_BYTES) {
    throw new Error(
      `artifact-limits invariant violated: ARTIFACT_LIMITS.${name}=${cap} ` +
      `is not a finite non-negative integer at or below ` +
      `ABSOLUTE_MAX_ARTIFACT_BYTES=${ABSOLUTE_MAX_ARTIFACT_BYTES}`,
    );
  }
}

/**
 * Normalize a caller's `maxBytes` argument:
 *   - NaN, Infinity, negative, or non-number → ABSOLUTE_MAX_ARTIFACT_BYTES
 *   - Finite non-negative → min(value, ABSOLUTE_MAX_ARTIFACT_BYTES)
 *
 * Closes the Math.min(NaN, x) === NaN bypass where an invalid caller
 * value would silently disable the oversize check.
 */
export function clampToAbsoluteMax(maxBytes: number): number {
  if (typeof maxBytes !== 'number' || !Number.isFinite(maxBytes) || maxBytes < 0) {
    return ABSOLUTE_MAX_ARTIFACT_BYTES;
  }
  return Math.min(maxBytes, ABSOLUTE_MAX_ARTIFACT_BYTES);
}
