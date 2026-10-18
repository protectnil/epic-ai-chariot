/**
 * IAM — Principal-kind partition enforcement (gap #3, Wiz 2).
 *
 * The human/agent/service principal partition was fully MODELED
 * (TenantContext.principalType, PolicyRule.principal.principalTypes,
 * native rbac.rs principal_scope + checkAccessForPrincipal /
 * resolveUserAdaptersForPrincipal) but ENFORCED ON NO PATH: none of the
 * principal-aware surfaces had a single call site. This module is the
 * live enforcement seam: `adapterFilterMiddleware` (src/iam/middleware.ts)
 * calls `filterAdapterIdsForPrincipal` for every authenticated request
 * whose session is a NON-HUMAN principal (`principalType: 'agent' |
 * 'service'`, stamped at issuance — see EnterpriseSessionPayload doc),
 * stripping every adapter the session can only justify via a mapping an
 * operator explicitly scoped away from that principal kind (e.g.
 * `principalScope: ['human']`).
 *
 * Safe-default contract (NO regression on existing traffic):
 *   - Sessions with `principalType` absent, 'human', or unrecognized
 *     never reach this module — the middleware treats them as human and
 *     leaves the pre-partition behavior byte-identical (no extra DB read,
 *     no native call).
 *   - Mappings without a `principalScope` (every document authored
 *     before the field existed) grant to ALL principal kinds, so even an
 *     agent/service session loses access ONLY to grants explicitly
 *     marked for a different kind. This is NOT a deny-all default.
 *
 * Decision engine (CHARIOT::§2.1::2): "The Rust binary carries ... the
 * RBAC enforcement primitives" (CHARIOT-SPEC.md §2.1). The
 * principal-partition RBAC decision is therefore computed EXCLUSIVELY
 * by the native `resolveUserAdaptersForPrincipal` export
 * (native/src/rbac.rs, same engine that backs `checkAccess`). When the
 * native binding is not loaded, or is loaded but predates that export,
 * the decision is REFUSED — `filterAdapterIdsForPrincipal` throws
 * `NativeRbacUnavailableError` naming the missing binary/export — rather
 * than being approximated in TypeScript. There is no TS mirror of the
 * Rust algorithm in this module; RBAC is never delegated to TypeScript.
 */

import { createLogger } from '../../engine/logger.js';
import { loadNativeBinding } from '../../license/binding.js';
import { list as listMappings } from './mapping.js';
import type { GroupAdapterMappingDocument, PrincipalType } from '../types.js';

const log = createLogger('iam.principal-partition');

/** The subset of a mapping document the partition filter consumes. */
export type PrincipalScopedMapping = Pick<
  GroupAdapterMappingDocument,
  'tenantId' | 'groupId' | 'adapterIds' | 'principalScope'
>;

/** Injection point for tests / non-Mongo deployments. */
export type LoadMappingsFn = (tenantId: string) => Promise<PrincipalScopedMapping[]>;

/**
 * Signature of the native `resolveUserAdaptersForPrincipal` export
 * (native/src/rbac.rs, via `src/license/binding.ts`).
 */
export type NativeResolveAdaptersFn = (
  tenantId: string,
  principalType: PrincipalType,
  userGroups: string[],
  mappingsJson: string,
) => string[];

/**
 * Outcome of trying to obtain the native RBAC decision function: either the
 * function itself, or a `reason` the decision surface is unavailable. Never
 * throws — the caller (`filterAdapterIdsForPrincipal`) turns an unavailable
 * result into `NativeRbacUnavailableError`.
 */
export type NativeRbacResolution = { fn: NativeResolveAdaptersFn } | { reason: string };

/** Injectable resolver type — production default is `resolveNativeFromBinding`. */
export type NativeRbacResolver = () => NativeRbacResolution;

/**
 * Thrown by `filterAdapterIdsForPrincipal` when a principal-partition RBAC
 * decision cannot be delegated to the native Rust binary — CHARIOT::§2.1::2.
 * The message names the specific missing capability (no binary at all, vs.
 * a binary that predates the `resolveUserAdaptersForPrincipal` export) so
 * operators can act on it. Callers MUST treat this as a fail-closed
 * refusal, never fall back to computing the decision themselves.
 */
export class NativeRbacUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NativeRbacUnavailableError';
  }
}

/**
 * Resolve the native decision function from the loaded platform binding.
 * Never throws — returns a `reason` when no usable native decision
 * surface is available, distinguishing "no binding at all" from "binding
 * loaded but missing the export". This is the production `NativeRbacResolver`;
 * tests inject their own to exercise both branches deterministically
 * without depending on whether a platform binary happens to be present or
 * absent on the host running the test.
 */
export function resolveNativeFromBinding(): NativeRbacResolution {
  const binding = loadNativeBinding();
  if (!binding) {
    return {
      reason:
        'the native Chariot binary is not loaded (no platform binding found for this install)',
    };
  }
  if (typeof binding.resolveUserAdaptersForPrincipal !== 'function') {
    return {
      reason:
        'the loaded native Chariot binary predates the resolveUserAdaptersForPrincipal export',
    };
  }
  const nativeFn = binding.resolveUserAdaptersForPrincipal;
  return {
    fn: (tenantId, principalType, userGroups, mappingsJson) =>
      nativeFn(tenantId, principalType, userGroups, mappingsJson),
  };
}

/**
 * Compute the adapter ids a NON-HUMAN principal may keep out of the
 * adapter list its session was issued with.
 *
 * The session's `adapterIds` were resolved at token-issue time by the
 * principal-kind-AGNOSTIC `resolveAdapterIds()` (mapping.ts), so an
 * agent/service session can carry grants that exist only via human-only
 * mappings. This function re-resolves the user's grants principal-aware
 * against the CURRENT mapping documents and returns the intersection
 * with the session list — it can only ever NARROW the session's access,
 * never widen it (a mapping added after issuance does not leak in).
 *
 * MUST NOT be called for human principals — the middleware guards that;
 * this function also short-circuits defensively so a future caller
 * cannot accidentally add a DB read to the default path.
 *
 * Fail-closed (CHARIOT::§2.1::2): both a mapping-store read failure and
 * an unavailable native RBAC decision surface propagate to the caller
 * (middleware converts either to a 5xx) rather than returning the
 * unfiltered session list or computing the decision in TypeScript.
 */
export async function filterAdapterIdsForPrincipal(
  tenantId: string,
  principalType: PrincipalType,
  userGroups: string[],
  sessionAdapterIds: string[],
  loadMappings: LoadMappingsFn = listMappings,
  resolveNative: NativeRbacResolver = resolveNativeFromBinding,
): Promise<string[]> {
  if (principalType === 'human') return sessionAdapterIds;
  if (sessionAdapterIds.length === 0) return sessionAdapterIds;

  const mappings = await loadMappings(tenantId);

  // CHARIOT::§2.1::2 — RBAC enforcement primitives live in the Rust
  // binary; TypeScript never computes the decision itself. Production
  // default resolves the loaded native binding; neither a binding nor a
  // test-injected resolver being able to produce a decision function →
  // refuse (fail closed), never approximate the decision in TS.
  const resolved = resolveNative();
  if (!('fn' in resolved)) {
    throw new NativeRbacUnavailableError(
      `Principal-scoped adapter authorization could not be resolved: ${resolved.reason}. ` +
      'RBAC decisions are never computed in TypeScript (CHARIOT::§2.1::2); this request is refused.',
    );
  }
  const nativeFn = resolved.fn;

  // Shape matches rbac.rs GroupAdapterMapping (camelCase serde).
  const mappingsJson = JSON.stringify(
    mappings.map((m) => ({
      tenantId: m.tenantId,
      groupId: m.groupId,
      adapterIds: m.adapterIds,
      ...(Array.isArray(m.principalScope) && m.principalScope.length > 0
        ? { principalScope: m.principalScope }
        : {}),
    })),
  );
  const allowed = new Set(nativeFn(tenantId, principalType, userGroups, mappingsJson));

  const filtered = sessionAdapterIds.filter((id) => allowed.has(id));
  if (filtered.length !== sessionAdapterIds.length) {
    log.info('principal partition stripped session adapters', {
      tenantId,
      principalType,
      sessionCount: sessionAdapterIds.length,
      keptCount: filtered.length,
    });
  }
  return filtered;
}
