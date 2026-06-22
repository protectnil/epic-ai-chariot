/**
 * @epicai/chariot — Routing inclusion gate (shared)
 *
 * Single implementation of `getConfiguredAdapterIds` shared by
 * src/engine/server/ChariotState.ts and src/engine/bin/setup.ts. Both
 * surfaces previously cloned a near-identical function body; the clone
 * was the structural debt review flagged across iterations 1-5.
 * Every credential-routing change now lands here once.
 *
 * Semantics:
 *   - hasCredential   → REST envKey declared AND present in merged
 *                       {creds, process.env} view.
 *   - hasMcpKeys      → ≥1 MCP envKey declared AND all declared keys
 *                       present in merged view. Non-vacuous: zero-cred
 *                       adapters return false so they require explicit
 *                       opt-in via isSelected / isInState.
 *   - credentials-pending skip → status==='credentials-pending' AND
 *                       credentialStatus.state === 'partially-credentialed'.
 *                       Adapters with no required credentials never
 *                       trigger the skip; fully-credentialed never do.
 *   - inclusion → hasCredential || hasMcpKeys || isSelected || isInState.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { credentialStatus, type AdapterCredentialShape } from '../types/canonical-credentialed-brands.js';

export interface AdapterStateLike {
  adapters: Record<string, { status?: string } | undefined>;
}

export interface ConfigLike {
  selectedAdapters?: string[];
}

/**
 * Compute the set of adapter ids that should be active for routing
 * given the loaded catalog, credentials, config, and persisted state.
 * Used by ChariotState.loadChariotState() (live MCP server routing) and
 * setup.ts (cmdQuery + startMcpServer wiring).
 */
export function getConfiguredAdapterIds(
  allAdapters: readonly AdapterCredentialShape[],
  creds: Record<string, string>,
  config: ConfigLike | null,
  state: AdapterStateLike,
): Set<string> {
  const ids = new Set<string>();
  for (const adapter of allAdapters) {
    // ONE credentialStatus call per adapter. It already resolved
    // effectiveEnvKeys internally, so we do NOT call it again here;
    // and we read the discriminator booleans straight off the result rather
    // than reconstructing them from state + missing[], which removes the
    // &&-before-|| precedence hazard the prior reconstruction carried.
    const cred = credentialStatus(adapter, creds);
    const hasCredential = cred.restSatisfied; // restSatisfied implies restDeclared
    const hasMcpKeys = cred.mcpSatisfied;     // mcpSatisfied implies mcpDeclared
    const isSelected = config?.selectedAdapters?.includes(adapter.id) ?? false;
    const stateEntry = state.adapters[adapter.id];
    const isInState = !!stateEntry;
    // Fail-closed sentinel: skip credentials-pending adapters that
    // actually have a missing required credential. Adapters with no
    // required credentials never trigger this skip — they're either
    // public (route via isInState if added) or stale-status entries
    // that an operator must reconcile through `chariot remove`.
    if (stateEntry && stateEntry.status === 'credentials-pending'
        && cred.state === 'partially-credentialed') {
      continue;
    }
    if (hasCredential || hasMcpKeys || isSelected || isInState) {
      ids.add(adapter.id);
    }
  }
  return ids;
}
