/**
 * Operational-telemetry redaction allowlist (C4AMD §8::3, §8::5).
 *
 * Governing clause bytes (traceability.spec_nodes, C4AMD::§8::3):
 *   "When enabled, operational telemetry SHALL be minimized and redacted,
 *   permitting metadata such as tenant-scoped canonical tool ID,
 *   success/failure, latency, and typed failure stage."
 * Ruling item 93 (2026-09-04) CLOSED this "such as" list to exactly six
 * fields: `{tenantId, canonicalToolId, outcome, latencyMs, failureStage,
 * hourBucket}`. AMENDED 2026-10-12 (MASTER chat authorization "Approve all
 * three, wire the telemetry commands.", C4AMD §8 closed field set): the set
 * is now exactly NINE — the six above plus `productVersion`, `platform`,
 * `catalogEpoch`. This module is the enforcement point for that closure.
 *
 * Governing clause bytes (C4AMD::§8::5):
 *   "No secrets, credentials, raw authorization material, sensitive
 *   arguments, tool results, or training examples SHALL be collected by
 *   this v4.0 telemetry contract."
 *
 * DESIGN — allowlist by CONSTRUCTION, not by stripping. `redactEvent`
 * never spreads its input (`{...candidate}`); it builds the output object
 * one named field at a time, reading only the nine allowed keys off the
 * input and validating each one's type. A caller that (by bug or by
 * malice) hands in `{ ...allowedFields, apiKey: '...', toolArgs: {...},
 * toolResult: {...} }` gets back an object containing ONLY the nine
 * allowed fields — the extra keys are never read, so they structurally
 * cannot reach the return value, the DB write, or the export bundle. See
 * `redact.test.ts` for the proof (§8::5).
 *
 * `failureStage` values are the CHARIOT §4.5 / BIEN §2(d) G-C dispatch
 * taxonomy — route (Tier-2 tool_id selection) / args (schema-valid
 * arguments) / dispatch (successful dispatch) — plus `other` for
 * pre-dispatch gate failures (RBAC denial, rate limit, context-budget
 * exceeded, content-policy block) that are real failures but do not fit
 * that three-stage triad. `null` on success (mirrors `CallResult.errorClass`
 * in toolHandlers.ts, which is likewise "absent on success").
 */

export type TelemetryOutcome = 'success' | 'failure';

export type TelemetryFailureStage = 'route' | 'args' | 'dispatch' | 'other';

/** The exact nine-field closed schema (ruling item 93, amended 2026-10-12). Field order here is the canonical order used by every serializer in this module family. */
export interface OperationalTelemetryEvent {
  tenantId: string;
  canonicalToolId: string;
  outcome: TelemetryOutcome;
  latencyMs: number;
  /** Present (one of the four typed values) iff `outcome === 'failure'`; `null` on success. */
  failureStage: TelemetryFailureStage | null;
  hourBucket: string;
  /** Installed `@epicai/chariot` package version (`unknown` if it could not be read). */
  productVersion: string;
  /** Host `<os>-<arch>` key, e.g. `linux-arm64`. */
  platform: string;
  /** Epoch of the loaded signed catalog bundle; `null` when no signed catalog is loaded (ABSENT is not zero). */
  catalogEpoch: number | null;
}

export class TelemetryRedactionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TelemetryRedactionError';
  }
}

const OUTCOME_VALUES: readonly TelemetryOutcome[] = ['success', 'failure'];
const FAILURE_STAGE_VALUES: readonly TelemetryFailureStage[] = ['route', 'args', 'dispatch', 'other'];

/**
 * Type guards for the two closed unions — used instead of an `as` cast so
 * the compiler, not just the runtime check, proves the narrowed value is
 * actually a member of the union before it is assigned into
 * `OperationalTelemetryEvent`. (`Array.prototype.includes` has no
 * type-predicate overload, so `arr.includes(x as T)` checks the runtime
 * value but does NOT narrow `x`'s static type — the two functions below
 * do.)
 */
function isTelemetryOutcome(value: unknown): value is TelemetryOutcome {
  return typeof value === 'string' && (OUTCOME_VALUES as readonly string[]).includes(value);
}

function isTelemetryFailureStage(value: unknown): value is TelemetryFailureStage {
  return typeof value === 'string' && (FAILURE_STAGE_VALUES as readonly string[]).includes(value);
}

/** ISO-8601, UTC, floored to the hour — e.g. `2026-09-04T14:00:00.000Z`. Hour granularity is itself part of "minimized" (§8::3): no exact per-event timestamp that could correlate to a specific request/session. */
export function toHourBucket(date: Date): string {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    throw new TelemetryRedactionError('toHourBucket: date must be a valid Date');
  }
  return date.toISOString().slice(0, 13) + ':00:00.000Z';
}

/**
 * Build a redacted, schema-closed telemetry event from a candidate object.
 * Reads ONLY the six allowed keys by name; every other key on `candidate`
 * — however sensitive — is never touched. Throws `TelemetryRedactionError`
 * (fail closed) on a missing/mistyped required field or an invalid
 * outcome/failureStage combination, rather than silently emitting a
 * malformed or under-specified event.
 */
export function redactEvent(candidate: Record<string, unknown>): OperationalTelemetryEvent {
  if (candidate === null || typeof candidate !== 'object') {
    throw new TelemetryRedactionError('redactEvent: candidate must be an object');
  }

  const tenantId = candidate['tenantId'];
  if (typeof tenantId !== 'string' || tenantId.length === 0) {
    throw new TelemetryRedactionError('redactEvent: tenantId must be a non-empty string');
  }

  const canonicalToolId = candidate['canonicalToolId'];
  if (typeof canonicalToolId !== 'string' || canonicalToolId.length === 0) {
    throw new TelemetryRedactionError('redactEvent: canonicalToolId must be a non-empty string');
  }

  const outcome = candidate['outcome'];
  if (!isTelemetryOutcome(outcome)) {
    throw new TelemetryRedactionError(`redactEvent: outcome must be one of ${JSON.stringify(OUTCOME_VALUES)}`);
  }

  const latencyMs = candidate['latencyMs'];
  if (typeof latencyMs !== 'number' || !Number.isFinite(latencyMs) || latencyMs < 0) {
    throw new TelemetryRedactionError('redactEvent: latencyMs must be a finite number >= 0');
  }

  const failureStageRaw = candidate['failureStage'];
  let failureStage: TelemetryFailureStage | null;
  if (outcome === 'success') {
    // §4.5/G-C symmetry with CallResult.errorClass: a failure stage on a
    // success is not "extra harmless metadata" — it is an inconsistent
    // event that would misreport where a (nonexistent) failure occurred.
    if (failureStageRaw !== null && failureStageRaw !== undefined) {
      throw new TelemetryRedactionError('redactEvent: failureStage must be null/absent when outcome is "success"');
    }
    failureStage = null;
  } else {
    if (!isTelemetryFailureStage(failureStageRaw)) {
      throw new TelemetryRedactionError(
        `redactEvent: failureStage must be one of ${JSON.stringify(FAILURE_STAGE_VALUES)} when outcome is "failure"`,
      );
    }
    failureStage = failureStageRaw;
  }

  const hourBucket = candidate['hourBucket'];
  if (
    typeof hourBucket !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:00:00\.000Z$/.test(hourBucket) ||
    Number.isNaN(new Date(hourBucket).getTime()) ||
    new Date(hourBucket).toISOString() !== hourBucket
  ) {
    // The round-trip equality rejects impossible instants such as
    // 2026-99-99T99:00:00.000Z that a shape-only regex would accept.
    throw new TelemetryRedactionError('redactEvent: hourBucket must be an hour-floored ISO-8601 UTC string');
  }

  const productVersion = candidate['productVersion'];
  if (typeof productVersion !== 'string' || !/^[0-9A-Za-z.+_-]{1,64}$/.test(productVersion)) {
    throw new TelemetryRedactionError('redactEvent: productVersion must be a 1-64 character version string');
  }

  const platform = candidate['platform'];
  if (typeof platform !== 'string' || !/^[a-z0-9]+-[a-z0-9_]+$/.test(platform) || platform.length > 32) {
    throw new TelemetryRedactionError('redactEvent: platform must be a lowercase <os>-<arch> key');
  }

  const catalogEpoch = candidate['catalogEpoch'];
  if (catalogEpoch !== null && !(typeof catalogEpoch === 'number' && Number.isInteger(catalogEpoch) && catalogEpoch >= 0)) {
    throw new TelemetryRedactionError('redactEvent: catalogEpoch must be a non-negative integer or null');
  }

  // Explicit field-by-field construction — see module doc. Never
  // `{ ...candidate }`.
  return { tenantId, canonicalToolId, outcome, latencyMs, failureStage, hourBucket, productVersion, platform, catalogEpoch };
}
