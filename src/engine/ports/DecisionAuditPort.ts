/**
 * §3.5::17 (CH-12) — pre-dispatch decision audit seam.
 *
 * CHARIOT-SPEC.md line 255: "The IAM `audit.log()` call that hash-chains the
 * event is invoked by the request-boundary caller, before the federation
 * dispatch begins."
 *
 * The OSS engine must not import the enterprise IAM layer (`src/iam`), so the
 * engine declares this port and IAM supplies the implementation. When no
 * implementation is wired (OSS / single-user installs with no IAM in front)
 * the hook is simply absent and dispatch proceeds unaudited — the same posture
 * as every other enterprise-only control on this path.
 *
 * @module engine/ports/DecisionAuditPort
 */

/**
 * The identity the request boundary actually holds. Mirrors the subset of
 * `CallContext` that exists at dispatch time — deliberately no `actorEmail`,
 * `ip` or `userAgent`, because none of them are available at this layer.
 */
export interface DecisionAuditContext {
  /** Per-request tenant. Absent on local stdio installs. */
  tenantId?: string;
  /** Enterprise session `userId`. Absent when the call is anonymous/local. */
  actorId?: string;
  /**
   * Operations the session is entitled to, as resolved by RBAC: a map of
   * adapterId → allowed operation names (the shape carried by
   * `EnterpriseSessionPayload.allowedOperations`).
   */
  allowedOperations?: Record<string, string[]>;
  /** True only on the single-process local stdio path (RBAC is a no-op). */
  localMode?: boolean;
}

export interface DecisionAuditPort {
  /**
   * Record the hash-chained pre-dispatch decision. Invoked AFTER the RBAC and
   * catalog-validation gates have passed and BEFORE any upstream dispatch, so
   * the record describes a call that genuinely proceeded to dispatch — a
   * request rejected by a gate is not an attempted dispatch.
   *
   * Implementations MUST be fail-closed with respect to the audit chain: if the
   * record cannot be written, the rejection propagates and dispatch does not
   * happen.
   */
  recordPreDispatchDecision(input: {
    context: DecisionAuditContext;
    adapterId: string;
    toolName: string;
    detail: Record<string, unknown>;
  }): Promise<void>;
}
