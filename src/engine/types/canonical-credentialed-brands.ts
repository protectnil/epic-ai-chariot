/**
 * @epicai/chariot — Canonical Credentialed Brands + credential-presence helpers
 *
 * Defense-in-depth registry for credentialed adapters whose published catalog
 * row drops the `mcp.envKeys` field (publisher gap upstream of Chariot — see
 * src/bin/chariot.ts comment in cmdAdd). Without this fallback an adapter
 * that genuinely needs credentials would silently report "healthy" in
 * `chariot health` and "included in routing" in ChariotState.
 *
 * One source of truth, four callers:
 *   - src/bin/chariot.ts cmdAdd        — derive declaredEnvKeys
 *   - src/bin/chariot.ts cmdHealth     — credential-presence gate
 *   - src/engine/server/ChariotState.ts getConfiguredAdapterIds — routing
 *     inclusion + credentials-pending skip
 *   - src/engine/bin/setup.ts          — engine-side mirror of both
 *
 * Splitting this across modules would re-introduce the split-brain
 * round-1 surfaced (cmdHealth required ALL keys; ChariotState still
 * accepted ANY one). Keep ALL credential-presence checks routed through
 * the helpers below.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/**
 * Required env-keys per canonical credentialed brand id. The published
 * bundle does NOT carry credential metadata for many entries today — every
 * credentialed brand listed here MUST be checked against this fallback or
 * else `chariot add github` (with no GITHUB_TOKEN) silently lands at
 * status=configured and `chariot health` shows green.
 *
 * Maintenance contract: each entry is the FULL set of env-vars the adapter
 * needs to function. A multi-key adapter (jira/auth0/okta/zendesk/workday)
 * MUST list every required key here — partial presence is not "configured".
 */
export const CANONICAL_CREDENTIALED_BRANDS: Record<string, readonly string[]> = {
  slack: ['SLACK_BOT_TOKEN'],
  stripe: ['STRIPE_API_KEY'],
  notion: ['NOTION_API_KEY'],
  linear: ['LINEAR_API_KEY'],
  jira: ['JIRA_API_TOKEN', 'JIRA_EMAIL', 'JIRA_HOST'],
  'atlassian-jira': ['JIRA_API_TOKEN', 'JIRA_EMAIL', 'JIRA_HOST'],
  asana: ['ASANA_TOKEN'],
  monday: ['MONDAY_API_KEY'],
  salesforce: ['SALESFORCE_TOKEN'],
  hubspot: ['HUBSPOT_API_KEY'],
  gmail: ['GMAIL_CREDENTIALS'],
  sendgrid: ['SENDGRID_API_KEY'],
  github: ['GITHUB_TOKEN'],
  gitlab: ['GITLAB_TOKEN'],
  okta: ['OKTA_API_TOKEN', 'OKTA_DOMAIN'],
  auth0: ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET'],
  pagerduty: ['PAGERDUTY_API_KEY'],
  datadog: ['DATADOG_API_KEY', 'DATADOG_APP_KEY'],
  sentry: ['SENTRY_AUTH_TOKEN'],
  shopify: ['SHOPIFY_ADMIN_API_TOKEN', 'SHOPIFY_STORE_DOMAIN'],
  zendesk: ['ZENDESK_API_TOKEN', 'ZENDESK_SUBDOMAIN', 'ZENDESK_EMAIL'],
  intercom: ['INTERCOM_ACCESS_TOKEN'],
  twilio: ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN'],
  tavily: ['TAVILY_API_KEY'],
  mixpanel: ['MIXPANEL_PROJECT_TOKEN'],
  workday: ['WORKDAY_CLIENT_ID', 'WORKDAY_CLIENT_SECRET'],
};

/** Minimal adapter shape the helpers need. Compatible with both
 *  RegistryEntry and AdapterEntry in src/engine/types/index.ts. The
 *  optional `rest.envKey` lets `credentialStatus` recognise REST adapters
 *  that need a single token even when they declare no MCP envKeys. */
export interface AdapterCredentialShape {
  id: string;
  mcp?: {
    envKeys?: readonly string[];
  };
  rest?: {
    envKey?: string;
  };
}

/**
 * Resolve the required env-keys for an adapter. Prefer the catalog's
 * declared `mcp.envKeys` (non-empty); fall back to CANONICAL_CREDENTIALED_
 * BRANDS when the catalog row strips them.
 */
export function effectiveEnvKeys(adapter: AdapterCredentialShape): readonly string[] {
  if (adapter.mcp?.envKeys && adapter.mcp.envKeys.length > 0) {
    return adapter.mcp.envKeys;
  }
  return CANONICAL_CREDENTIALED_BRANDS[adapter.id] ?? [];
}

/**
 * Discriminated credential-state result. Replaces the prior split of
 * vacuous-true `hasAllRequiredCredentials` vs vacuous-false
 * `hasConfiguredMcpCredentials` — callers project the boolean they
 * need from `state` instead of remembering which of two near-identical
 * helpers carried the correct vacuity contract.
 *
 *   - 'no-creds-required'      adapter declares neither REST envKey nor
 *                              MCP envKeys (after CANONICAL fallback);
 *                              missing=[].
 *   - 'fully-credentialed'     adapter declares ≥1 required key AND
 *                              every required key resolves in the merged
 *                              {file-creds, process.env} view; missing=[].
 *   - 'partially-credentialed' adapter declares ≥1 required key AND
 *                              ≥1 required key is absent; missing[]
 *                              lists the missing keys in declaration
 *                              order (REST first if declared, then MCP).
 */
/**
 * Discriminator fields carried on every CredentialState. Callers
 * read these directly instead of reconstructing them from `state` + `missing[]`
 * — the prior reconstruction in configuredAdapterIds.ts used a
 * `&&`-before-`||` precedence chain that parsed correctly only by accident.
 * `mcpKeys` is the already-resolved effectiveEnvKeys result, exposed so callers
 * do not call effectiveEnvKeys a second time per adapter.
 */
export interface CredentialDiscriminators {
  /** A non-empty REST `rest.envKey` was declared on the adapter. */
  restDeclared: boolean;
  /** REST key declared AND resolved in the merged {creds, process.env} view. */
  restSatisfied: boolean;
  /** ≥1 MCP env-key is required after the CANONICAL_CREDENTIALED_BRANDS fallback. */
  mcpDeclared: boolean;
  /** mcpDeclared AND every declared MCP key resolves in the merged view. */
  mcpSatisfied: boolean;
  /** The resolved required MCP env-keys (effectiveEnvKeys), exposed once. */
  mcpKeys: readonly string[];
}

export type CredentialState =
  | ({ state: 'no-creds-required' } & CredentialDiscriminators)
  | ({ state: 'fully-credentialed' } & CredentialDiscriminators)
  | ({ state: 'partially-credentialed'; missing: string[] } & CredentialDiscriminators);

/**
 * Single source of truth for adapter credential-presence semantics
 * across BOTH dispatch surfaces (REST envKey + MCP envKeys with
 * CANONICAL_CREDENTIALED_BRANDS fallback). The merged
 * {file-creds, process.env} view is consulted for every required key.
 *
 * Use:
 *   - cmdHealth → state==='partially-credentialed' is the diagnostic;
 *     missing[0] is the operator-facing key to set.
 *   - Routing inclusion → state==='fully-credentialed' admits the
 *     adapter; 'no-creds-required' requires opt-in via isSelected/
 *     isInState (preserves pre-consolidation routing semantics where
 *     public adapters needed explicit add).
 *   - credentials-pending skip → state==='partially-credentialed' is
 *     the only state that should be gated when stateEntry status flags
 *     pending. The other two states either route or require opt-in.
 *
 * History: pre-iteration-5 the module exposed hasAllRequiredCredentials
 * (vacuous-true), hasConfiguredMcpCredentials (vacuous-false),
 * hasRestCredential, firstMissingCredential, and
 * isMissingAnyRequiredCredential — five overlapping predicates whose
 * vacuity contracts had to be memorised at every call site. The
 * round-1 split-brain and iteration-3 vacuous-true regression both
 * stemmed from picking the wrong predicate for the surface. The
 * discriminated result makes vacuity type-distinguishable.
 */
export function credentialStatus(
  adapter: AdapterCredentialShape,
  creds: Record<string, string>,
): CredentialState {
  const missing: string[] = [];
  const restKey = adapter.rest?.envKey;
  const restDeclared = typeof restKey === 'string' && restKey.length > 0;
  let restSatisfied = false;
  if (restDeclared) {
    restSatisfied = !!(creds[restKey] || process.env[restKey]);
    if (!restSatisfied) missing.push(restKey);
  }
  const mcpKeys = effectiveEnvKeys(adapter);
  const mcpDeclared = mcpKeys.length > 0;
  let mcpSatisfied = mcpDeclared;
  for (const k of mcpKeys) {
    if (creds[k] || process.env[k]) continue;
    mcpSatisfied = false;
    // Dedup: a REST+MCP adapter that names the same env-var on both surfaces
    // (e.g. both declare the same token) must list it once, not twice.
    if (!missing.includes(k)) missing.push(k);
  }
  const discriminators: CredentialDiscriminators = {
    restDeclared, restSatisfied, mcpDeclared, mcpSatisfied, mcpKeys,
  };
  if (!restDeclared && !mcpDeclared) return { state: 'no-creds-required', ...discriminators };
  if (missing.length === 0) return { state: 'fully-credentialed', ...discriminators };
  return { state: 'partially-credentialed', missing, ...discriminators };
}

/**
 * cmdHealth-shaped result for one adapter — combines credentialStatus
 * with the curated-adapter bypass. Returns {healthy, missingKey} where
 * healthy=true means cmdHealth should print a green line, and
 * missingKey (when healthy=false) is the operator-facing key name to
 * set. Shared by src/bin/chariot.ts cmdHealth and src/engine/bin/setup.ts
 * cmdHealth so the two surfaces cannot diverge on credential
 * resolution.
 */
export interface AdapterHealthCheck {
  healthy: boolean;
  missingKey: string;
  /**
   * Why this adapter is healthy/unhealthy — distinguishes a credential-FREE
   * pass from a verified-credential pass. Previously both returned
   * {healthy:true, missingKey:''}, so a custom adapter that lacks `mcp.envKeys`
   * and is not in CANONICAL_CREDENTIALED_BRANDS silently showed green even
   * though it may need credentials to function:
   *   - 'curated'   bypassed via the curated-adapter allowlist (trusted).
   *   - 'none'      no credentials required (no REST key, no MCP keys after
   *                 CANONICAL fallback) — green, but unverified; see the
   *                 coverage audit for possible mis-categorization.
   *   - 'satisfied' ≥1 required key declared AND all resolved — verified green.
   *   - 'missing'   ≥1 required key absent — red; `missingKey` names the first.
   */
  credentialBasis: 'curated' | 'none' | 'satisfied' | 'missing';
}
export function cmdHealthCheckAdapter(
  adapter: AdapterCredentialShape,
  creds: Record<string, string>,
  isCurated: boolean,
): AdapterHealthCheck {
  if (isCurated) return { healthy: true, missingKey: '', credentialBasis: 'curated' };
  const status = credentialStatus(adapter, creds);
  if (status.state === 'partially-credentialed') {
    return { healthy: false, missingKey: status.missing[0], credentialBasis: 'missing' };
  }
  const credentialBasis = status.state === 'fully-credentialed' ? 'satisfied' : 'none';
  return { healthy: true, missingKey: '', credentialBasis };
}

/**
 * CANONICAL coverage audit. Flags non-curated adapters that land in
 * `no-creds-required` — i.e. they declare neither a REST envKey nor any MCP
 * env-keys after the CANONICAL_CREDENTIALED_BRANDS fallback — and are NOT
 * listed in CANONICAL_CREDENTIALED_BRANDS. These show green in `chariot health`
 * via credentialBasis:'none' but may genuinely need credentials at runtime; the
 * likely cause is a missing CANONICAL_CREDENTIALED_BRANDS entry or a publisher
 * gap. Pure/read-only — callers (e.g. cmdHealth) decide how to surface the list.
 */
export interface CanonicalCoverageGap {
  id: string;
}
export function auditCanonicalCoverage(
  adapters: readonly AdapterCredentialShape[],
  isCurated: (id: string) => boolean,
): CanonicalCoverageGap[] {
  const gaps: CanonicalCoverageGap[] = [];
  for (const adapter of adapters) {
    if (isCurated(adapter.id)) continue;
    const restDeclared = typeof adapter.rest?.envKey === 'string' && adapter.rest.envKey.length > 0;
    const mcpDeclared = effectiveEnvKeys(adapter).length > 0;
    if (!restDeclared && !mcpDeclared && !(adapter.id in CANONICAL_CREDENTIALED_BRANDS)) {
      gaps.push({ id: adapter.id });
    }
  }
  return gaps;
}
