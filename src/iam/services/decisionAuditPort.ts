/**
 * §3.5::17 (CH-12) — IAM implementation of the engine's pre-dispatch decision
 * audit port.
 *
 * CHARIOT-SPEC.md line 255: "The IAM `audit.log()` call that hash-chains the
 * event is invoked by the request-boundary caller, before the federation
 * dispatch begins."
 *
 * The engine owns the port interface (src/engine/ports/DecisionAuditPort.ts) so
 * the OSS engine never imports this enterprise layer; the dependency points
 * inward, IAM → engine, never the reverse.
 *
 * @module iam/services/decisionAuditPort
 */

import type { DecisionAuditPort } from '../../engine/ports/DecisionAuditPort.js';
import { log } from './audit.js';

/**
 * Build the port. Every invocation writes a hash-chained `adapter_query` event
 * BEFORE dispatch; a write failure propagates, so an unauditable call never
 * reaches the upstream adapter.
 */
export function createDecisionAuditPort(): DecisionAuditPort {
  return {
    async recordPreDispatchDecision(input) {
      const { tenantId, actorId, localMode } = input.context;

      // Local stdio installs have no tenant and no IAM identity — there is no
      // tenant-scoped chain to write into. That path is trusted by construction
      // (the operator owns the process) and is explicitly RBAC-exempt, so it is
      // not audited rather than being written under a fabricated tenant.
      if (!tenantId) {
        if (localMode === true) return;
        throw new Error(
          '[iam/decisionAuditPort] pre-dispatch audit requires a tenantId on a non-local call',
        );
      }

      await log(tenantId, 'adapter_query', {
        // No email exists at the dispatch boundary; audit.log records '' rather
        // than inventing one. actorId is the enterprise session userId.
        actorId: actorId ?? '',
        targetType: 'adapter',
        targetId: `${input.adapterId}:${input.toolName}`,
        detail: input.detail,
      });
    },
  };
}
