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
 *   - isCurated       → adapter.id is in CHARIOT_CURATED_IDS
 *                       (src/catalog/curated.ts). CHARIOT-SPEC.md:442:
 *                       "Curated adapters (`CURATED_IDS`) are always
 *                       treated as `configured` for health-reporting
 *                       purposes; they require no credentials and are
 *                       dispatchable by construction." — that "dispatchable
 *                       by construction" clause governs ROUTING, not only
 *                       `chariot health`'s display. Curated adapters admit
 *                       unconditionally, with no isSelected/isInState
 *                       opt-in required.
 *   - hasCredential   → legacy REST envKey declared AND present in merged
 *                       {creds, process.env} view, OR the adapter's
 *                       REST_CREDENTIAL_MAP entry (required fields +
 *                       an alternatives[] group, if declared) is fully
 *                       satisfied in that same merged view.
 *   - hasMcpKeys      → ≥1 MCP envKey declared AND all declared keys
 *                       present in merged view. Non-vacuous: zero-cred
 *                       adapters return false so they require explicit
 *                       opt-in via isSelected / isInState.
 *   - credentials-pending skip → status==='credentials-pending' AND
 *                       credentialStatus.state === 'partially-credentialed'.
 *                       Adapters with no required credentials never
 *                       trigger the skip; fully-credentialed never do.
 *                       Does NOT apply to curated adapters — they admit
 *                       unconditionally regardless of any stale state
 *                       entry (a curated adapter never legitimately
 *                       carries 'credentials-pending' status, but a stale/
 *                       corrupted state file must not be able to exclude
 *                       one either).
 *   - inclusion → isCurated || hasCredential || hasMcpKeys || isSelected || isInState.
 *
 * History (2026-09-30, dogfood mechanism-test-2/3): this gate had NO
 * curated bypass at all — `chariot health`'s enumeration
 * (setup.ts enumerateAdapterIds) always unions CURATED_IDS regardless of
 * state, so `chariot health` correctly showed wikipedia/pubmed/dns as
 * healthy/curated, but THIS function (the actual routing set consumed by
 * `chariot query` AND the live `chariot serve` MCP server — see
 * ChariotState.loadChariotState) required isSelected/isInState for EVERY
 * adapter including curated ones. A fresh install (or any account whose
 * config.selectedAdapters/state.adapters never got curated ids populated
 * — e.g. an --ignore-scripts pack, or any deployment where the wizard
 * that would normally pre-populate them never ran) could not route a
 * plain "wikipedia summary for Detroit" query to the wikipedia adapter at
 * all — chariot_query returned "No adapters matched" while chariot health
 * reported wikipedia green in the same breath. Direct spec violation of
 * CHARIOT-SPEC.md:442's "dispatchable by construction."
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { credentialStatus, type AdapterCredentialShape } from '../types/canonical-credentialed-brands.js';
import { CHARIOT_CURATED_IDS } from '../../catalog/curated.js';

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
    // CHARIOT-SPEC.md:442 — curated adapters are "dispatchable by
    // construction": admit unconditionally, before any credential/state
    // check, and never subject to the credentials-pending skip below (a
    // stale/corrupted state entry must not be able to exclude one).
    if (CHARIOT_CURATED_IDS.includes(adapter.id)) {
      ids.add(adapter.id);
      continue;
    }
    // ONE credentialStatus call per adapter. It already resolved
    // effectiveEnvKeys internally, so we do NOT call it again here;
    // and we read the discriminator booleans straight off the result rather
    // than reconstructing them from state + missing[], which removes the
    // &&-before-|| precedence hazard the prior reconstruction carried.
    const cred = credentialStatus(adapter, creds);
    // restSatisfied implies restDeclared (legacy single rest.envKey);
    // restFieldsSatisfied implies restFieldsDeclared (REST_CREDENTIAL_MAP
    // required+alternatives) — both are non-vacuous by construction (see
    // canonical-credentialed-brands.ts credentialStatus).
    const hasCredential = cred.restSatisfied || cred.restFieldsSatisfied;
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
