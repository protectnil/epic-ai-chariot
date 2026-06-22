/**
 * IAM — Per-Tenant Audit-Write Mutex
 *
 * The hash-chained audit log (iam_audit_events) requires strict
 * sequencing per tenant: event N's hash includes event N-1's hash, so
 * two concurrent writers cannot both compute valid chains in parallel.
 *
 * The previous implementation relied on an optimistic CAS loop bounded
 * at MAX_RETRIES=10. Under same-tenant burst (e.g. 50 concurrent ID-JAG
 * token issuances), the loop exhausted and the audit write threw,
 * surfacing as HTTP 500 to the caller.
 *
 * This mutex serializes audit-write attempts per tenant within a single
 * Node process. The CAS loop still runs inside the lock so that in
 * multi-replica deployments the loop remains the cross-process fallback;
 * the in-process lock removes single-process contention without changing
 * the chain semantics.
 *
 * Multi-replica deployments still need a Redis-backed sibling lock for
 * the same reason subject-mutex.ts does.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

const inFlight = new Map<string, Promise<unknown>>();

/**
 * Serialize per-tenant audit-write execution of `fn`. The second and
 * subsequent callers chain behind the first via the in-flight promise.
 * The map entry is cleared once the chain settles to bound memory.
 */
export async function withAuditLock<T>(
  tenantId: string,
  fn: () => Promise<T>,
): Promise<T> {
  const prior = inFlight.get(tenantId);
  const next = (prior ? prior.catch(() => undefined) : Promise.resolve()).then(fn);
  inFlight.set(tenantId, next);
  next.finally(() => {
    if (inFlight.get(tenantId) === next) {
      inFlight.delete(tenantId);
    }
  }).catch(() => undefined);
  return next;
}

/**
 * Test-only: report current in-flight count for invariant assertions
 * in the audit-mutex eval.
 */
export function auditInFlightSize(): number {
  return inFlight.size;
}
