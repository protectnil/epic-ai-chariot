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

import { REST_CREDENTIAL_MAP, type RestCredentialField, type RestCredentialEntry } from './rest-credential-map.generated.js';

const EMPTY_REST_ENTRY: RestCredentialEntry = { required: [], alternatives: [], optional: [] };

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
    module?: string;
    className?: string;
    authType?: string;
    baseUrl?: string;
    discoveredEndpointsJson?: string;
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
 * Resolve an adapter's full REST_CREDENTIAL_MAP entry (required/alternatives/
 * optional field groups; see rest-credential-map.generated.ts). Returns the
 * shared EMPTY_REST_ENTRY sentinel for adapters absent from the map (the
 * legacy single `rest.envKey` -> apiKey path, or no credentials needed).
 */
export function restCredentialEntry(adapter: AdapterCredentialShape): RestCredentialEntry {
  return REST_CREDENTIAL_MAP[adapter.id] ?? EMPTY_REST_ENTRY;
}

function isEnvVarSet(envVar: string, creds: Record<string, string>): boolean {
  return !!(creds[envVar] || process.env[envVar]);
}

/**
 * The alternatives[] group (if any) that is FULLY satisfied by the merged
 * {creds, process.env} view — undefined if none is (or the adapter declares
 * no alternatives).
 */
export function satisfiedRestAlternative(
  adapter: AdapterCredentialShape,
  creds: Record<string, string>,
): readonly RestCredentialField[] | undefined {
  const entry = restCredentialEntry(adapter);
  for (const group of entry.alternatives) {
    if (group.every(field => isEnvVarSet(field.envVar, creds))) return group;
  }
  return undefined;
}

/**
 * Prompt/health-facing flat field list for an adapter's REST credential
 * requirements: every `required` field, PLUS the FIRST `alternatives[]`
 * group's fields when NO alternative group is yet satisfied by `creds`
 * (matches the merged {creds, process.env} view `credentialStatus` uses,
 * so a `chariot add` invoked after some creds are already on disk/env does
 * not re-prompt for an alternative the operator already satisfied via a
 * DIFFERENT group — e.g. username+password already set must not also
 * prompt for bearerToken). `creds` defaults to `{}` for call sites that
 * only need the STATIC declared set (matches pre-alternatives behavior).
 * Does NOT include `optional` fields — those are never prompted-for/
 * required; dispatch reads them directly from restCredentialEntry().
 */
export function restEnvKeys(
  adapter: AdapterCredentialShape,
  creds: Record<string, string> = {},
): readonly RestCredentialField[] {
  const entry = restCredentialEntry(adapter);
  if (entry.alternatives.length === 0) return entry.required;
  const satisfied = satisfiedRestAlternative(adapter, creds);
  return [...entry.required, ...(satisfied ?? entry.alternatives[0])];
}

/**
 * EVERY field an adapter could ever receive a REST credential for —
 * required + every alternatives[] group (flattened, deduped) + optional.
 * Used for purge (cmdRemove) and credential-scan matching, where the goal
 * is "does the operator have ANY of this adapter's possible credentials
 * on disk", not "what should we prompt for right now".
 */
export function restAllEnvKeys(adapter: AdapterCredentialShape): readonly RestCredentialField[] {
  const entry = restCredentialEntry(adapter);
  const seen = new Set<string>();
  const out: RestCredentialField[] = [];
  for (const field of [...entry.required, ...entry.alternatives.flat(), ...entry.optional]) {
    if (!seen.has(field.envVar)) { seen.add(field.envVar); out.push(field); }
  }
  return out;
}

/** Result of {@link buildRestAdapterConfig}: either a fully-built config
 * ready to pass to `new AdapterClass(config)`, or the list of missing
 * required env-var names (fail-closed — never a partial config). */
export type RestAdapterConfigResult =
  | { ok: true; config: Record<string, string> }
  | { ok: false; missing: readonly string[] };

/**
 * Build the `adapterConfig` object a REST adapter constructor receives,
 * from a single merged {@code creds}/`process.env` view. This is the ONE
 * place both live dispatch surfaces (toolHandlers.ts `chariot serve` REST
 * dispatch, and setup.ts `cmdQuery` REST dispatch) must call — CHARIOT-
 * SPEC.md:438 requires that "configured" credentials leave an adapter
 * "Ready to be dispatched", and having two independent adapterConfig-
 * building blocks let the two surfaces diverge: `cmdQuery` built ONLY
 * `apiKey`/`baseUrl`/`endpointsJson`/`authType` from `adapter.rest.envKey`
 * and NEVER consulted REST_CREDENTIAL_MAP, so a multi-field or
 * alternatives-shaped adapter (redshift, paypal, acumatica, ...) always
 * dispatched with an empty/incomplete config and the constructor threw,
 * even with every required key present in the environment
 * (setup.ts:2164-2180 prior to this fix).
 *
 * Field-building order mirrors the working toolHandlers.ts REST dispatch
 * exactly: legacy single-token `rest.envKey` -> `apiKey`, `rest.baseUrl`,
 * `rest.discoveredEndpointsJson` -> `endpointsJson`, `rest.authType` ->
 * `authType`, then REST_CREDENTIAL_MAP `required` fields, then the first
 * satisfied `alternatives[]` group (or the first group's env-vars are
 * reported missing when none is satisfied), then `optional` fields.
 * Fails CLOSED: any missing required/alternative field returns
 * `{ ok: false, missing }` and the caller must refuse dispatch rather than
 * let the adapter constructor throw an uncaught-shaped internal error.
 */
export function buildRestAdapterConfig(
  adapter: AdapterCredentialShape,
  creds: Record<string, string>,
): RestAdapterConfigResult {
  const config: Record<string, string> = {};
  const mergedValue = (envVar: string): string | undefined => creds[envVar] ?? process.env[envVar];

  if (adapter.rest?.envKey) {
    const apiKey = mergedValue(adapter.rest.envKey);
    if (typeof apiKey === 'string' && apiKey.length > 0) config['apiKey'] = apiKey;
  }
  if (adapter.rest?.baseUrl) config['baseUrl'] = adapter.rest.baseUrl;
  if (adapter.rest?.discoveredEndpointsJson) config['endpointsJson'] = adapter.rest.discoveredEndpointsJson;
  if (adapter.rest?.authType) config['authType'] = adapter.rest.authType;

  const restEntry = restCredentialEntry(adapter);
  const missing: string[] = [];
  for (const { field, envVar } of restEntry.required) {
    const value = mergedValue(envVar);
    if (value) config[field] = value; else missing.push(envVar);
  }
  if (restEntry.alternatives.length > 0) {
    const satisfied = satisfiedRestAlternative(adapter, creds);
    if (satisfied) {
      for (const { field, envVar } of satisfied) config[field] = mergedValue(envVar) as string;
    } else {
      for (const { envVar } of restEntry.alternatives[0]) missing.push(envVar);
    }
  }
  for (const { field, envVar } of restEntry.optional) {
    const value = mergedValue(envVar);
    if (value) config[field] = value;
  }

  if (missing.length > 0) return { ok: false, missing };
  return { ok: true, config };
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
  /** ≥1 REST per-field credential (REST_CREDENTIAL_MAP) is required. */
  restFieldsDeclared: boolean;
  /** restFieldsDeclared AND every declared field's env-var resolves in the merged view. */
  restFieldsSatisfied: boolean;
  /** The resolved required REST credential fields (restEnvKeys), exposed once. */
  restFields: readonly RestCredentialField[];
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
  const restEntry = restCredentialEntry(adapter);
  const restFieldsDeclared = restEntry.required.length > 0 || restEntry.alternatives.length > 0;
  const restRequiredMissing: string[] = [];
  for (const { envVar } of restEntry.required) {
    if (isEnvVarSet(envVar, creds)) continue;
    restRequiredMissing.push(envVar);
  }
  const satisfiedAlternative = satisfiedRestAlternative(adapter, creds);
  const restAlternativesSatisfied = restEntry.alternatives.length === 0 || !!satisfiedAlternative;
  // Non-vacuous: an adapter absent from REST_CREDENTIAL_MAP (restFieldsDeclared
  // === false) has zero required fields and zero alternatives, which would
  // otherwise make `restRequiredMissing.length===0 && restAlternativesSatisfied`
  // vacuously true — the exact "zero-cred adapter reports satisfied" class of
  // bug mcpSatisfied's `let mcpSatisfied = mcpDeclared;` pattern (below) exists
  // to prevent. Gate on restFieldsDeclared explicitly.
  const restFieldsSatisfied = restFieldsDeclared && restRequiredMissing.length === 0 && restAlternativesSatisfied;
  for (const envVar of restRequiredMissing) {
    if (!missing.includes(envVar)) missing.push(envVar);
  }
  if (!restAlternativesSatisfied) {
    // Name the FIRST alternative group's keys — matches restEnvKeys' prompt
    // ordering so `chariot add`'s prompt list and `chariot health`'s
    // "missing" diagnostic never disagree on which keys to ask for.
    for (const { envVar } of restEntry.alternatives[0]) {
      if (!missing.includes(envVar)) missing.push(envVar);
    }
  }
  // Exposed once for callers (restEnvKeys' prompt-facing flat list).
  const restFields = restEnvKeys(adapter, creds);
  const discriminators: CredentialDiscriminators = {
    restDeclared, restSatisfied, mcpDeclared, mcpSatisfied, mcpKeys,
    restFieldsDeclared, restFieldsSatisfied, restFields,
  };
  if (!restDeclared && !mcpDeclared && !restFieldsDeclared) return { state: 'no-creds-required', ...discriminators };
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
    const restFieldsDeclared = restEnvKeys(adapter).length > 0;
    if (!restDeclared && !mcpDeclared && !restFieldsDeclared && !(adapter.id in CANONICAL_CREDENTIALED_BRANDS)) {
      gaps.push({ id: adapter.id });
    }
  }
  return gaps;
}
