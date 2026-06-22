/**
 * IAM — Per-Subject In-Process Mutex
 *
 * Defensive layer for IETF ID-JAG draft §4.4.3 re-submission idempotency
 * (draft-ietf-oauth-identity-assertion-authz-grant). Two concurrent
 * `upsertUserForSubject` calls with the same (tenantId, subjectKey) would
 * otherwise race through `findOneAndUpdate` and either tie up the catch
 * path on E11000 or — under burst from a misconfigured client — spin the
 * retry loop N times per request.
 *
 * This mutex serializes per-key access within a single Node process.
 * Multi-replica deployments need a Redis-backed sibling; the in-process
 * lock is the inner defense layer.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { subjectKeyAsExternalId } from './subject-key.js';
import type { SubjectKey } from './id-jag-validator.js';

const inFlight = new Map<string, Promise<unknown>>();

function lockKey(tenantId: string, subjectKey: SubjectKey): string {
  return `${tenantId}::${subjectKeyAsExternalId(subjectKey)}`;
}

/**
 * Serialize per-(tenantId, subjectKey) execution of `fn`. The second and
 * subsequent callers chain behind the first via the in-flight promise so
 * they see the result of the prior op before running their own. The map
 * entry is cleared once the chain settles to bound memory.
 */
export async function withSubjectLock<T>(
  tenantId: string,
  subjectKey: SubjectKey,
  fn: () => Promise<T>,
): Promise<T> {
  const key = lockKey(tenantId, subjectKey);
  const prior = inFlight.get(key);

  const next = (prior ? prior.catch(() => undefined) : Promise.resolve()).then(fn);

  // Track this attempt as the new tail so subsequent callers chain
  // behind it. Settled .finally() trims the map only when no later
  // caller has supplanted us — prevents wiping a still-live chain.
  inFlight.set(key, next);
  next.finally(() => {
    if (inFlight.get(key) === next) {
      inFlight.delete(key);
    }
  }).catch(() => undefined);

  return next;
}

/**
 * Test-only: report current in-flight count. Used by the mutex eval
 * to assert serialization holds.
 */
export function inFlightSize(): number {
  return inFlight.size;
}
