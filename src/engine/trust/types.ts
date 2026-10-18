/**
 * @epicai/chariot — Trust Layer Types
 * Type definitions for enterprise authentication, authorization,
 * tenant context, and policy evaluation.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { AdapterCategory } from '../federation/AdapterCatalog.js';

// =============================================================================
// Authentication
// =============================================================================

export interface JWTAuthConfig {
  type: 'jwt';
  issuer: string;
  audience: string;
  jwksUri: string;
  clockSkewSeconds: number;
}

export interface MTLSConfig {
  type: 'mtls';
  caCertPath: string;
  requireClientCert: boolean;
  revocationCheck: 'none' | 'ocsp' | 'crl';
  ocspResponderUrl?: string;
  crlPemPath?: string;
}

export type AuthConfig = JWTAuthConfig | MTLSConfig;

// =============================================================================
// Tenant Context
// =============================================================================

/**
 * Principal kind for a TenantContext. Distinguishes a human operator from
 * an autonomous agent or a service/machine-to-machine caller.
 *
 * Wiz 2 finding (gap #3): TenantContext previously had NO principal-kind
 * field at all, so nothing distinguished a human dashboard user from an
 * agent or service principal — an agent could silently inherit a grant
 * that was only ever intended for a human operator.
 *
 * Optional and MUST default to 'human' wherever it is consulted
 * (AccessPolicyEngine.principalMatches, the native rbac principal-scope
 * checks) so every existing caller that predates this field keeps its
 * current grants unchanged. Only a rule/mapping that explicitly restricts
 * itself to specific principal kinds is affected.
 */
export type PrincipalType = 'human' | 'agent' | 'service';

export interface TenantContext {
  tenantId: string;
  principalId: string;
  roles: string[];
  tier: 'free' | 'pro' | 'enterprise';
  attributes: Record<string, string>;
  /**
   * Principal kind. Optional for backward compatibility — legacy context
   * builders (contextFromJWT, contextFromCert, createDevContext in
   * TenantContext.ts) predate this field and do not stamp it. Every
   * consumer treats an absent value as 'human'.
   */
  principalType?: PrincipalType;
}

/**
 * Minimal structural contract for an adapter-verification status lookup,
 * satisfied by `VerifiedCatalog.getVerification()`
 * (src/catalog/VerifiedCatalog.ts) without FederationManager needing to
 * import the `catalog` package — that package already imports FROM
 * `engine`, so an `engine -> catalog` import would create a dependency
 * cycle. Any object exposing a matching `getVerification` method can be
 * passed as `FederationManagerOptions.verifiedCatalog`.
 */
export interface AdapterVerificationLookup {
  getVerification(adapterName: string): { status: 'verified' | 'failed' | 'pending' | 'stale' };
}

// =============================================================================
// Policy
// =============================================================================

export type PolicyEffect = 'allow' | 'deny';

export interface PolicyCondition {
  field: string;
  operator: 'eq' | 'neq' | 'in' | 'not-in' | 'exists';
  value: string | string[];
}

export interface PolicyRule {
  id: string;
  effect: PolicyEffect;
  principal: {
    roles?: string[];
    attributes?: Record<string, string>;
    /**
     * Restrict this rule to specific principal kinds (gap #3). Absent or
     * empty = matches any principal kind — identical to pre-existing
     * behavior, so every rule authored before this field existed is
     * unaffected. Set to `['human']` to mark a grant human-only: an
     * agent/service TenantContext (principalType !== 'human') then fails
     * principal matching for this rule even when its roles/attributes
     * would otherwise match, closing the gap where an agent principal
     * could silently hold a human-only grant.
     */
    principalTypes?: PrincipalType[];
  };
  resource: {
    toolCategories?: AdapterCategory[];
    toolNames?: string[];
    adapters?: string[];
  };
  conditions?: PolicyCondition[];
  priority: number;
}

export interface PolicyDecision {
  allow: boolean;
  reason?: string;
  ruleId?: string;
  redactedArgs?: Record<string, unknown>;
}

// =============================================================================
// Egress Policy
// =============================================================================

/**
 * Adapter-egress policy rule. Evaluated by AccessPolicyEngine.evaluateEgress
 * before any outbound network call is made from a federated adapter.
 *
 * Selection:
 *   - tenantIds: tenants the rule applies to (empty = all tenants)
 *   - adapters: adapter names the rule applies to (empty = all adapters)
 *   - tools: tool names the rule applies to (empty = all tools)
 *   - hostPatterns: hostname match list. Each entry is either an exact
 *     host (e.g. `api.openai.com`) or a glob (e.g. `*.openai.com`).
 *     Empty = matches any host (use with effect=deny for a tenant-wide
 *     network shutoff; or effect=allow for "this tenant may reach any
 *     host"). Glob matches the FULL hostname, not a path.
 *   - portRange: optional [low, high]. Omitted = any port.
 *   - protocols: optional ['https','http'] subset. Omitted = any.
 *
 * Effect: allow or deny. Higher priority wins; deny breaks tie at same
 * priority. Default-deny applies when no rule matches.
 */
export interface EgressRule {
  id: string;
  effect: PolicyEffect;
  priority: number;
  tenantIds?: string[];
  adapters?: string[];
  tools?: string[];
  hostPatterns?: string[];
  portRange?: [number, number];
  protocols?: Array<'http' | 'https'>;
}

/**
 * Inputs to AccessPolicyEngine.evaluateEgress. Built by the federation
 * layer from the adapter config + tool dispatch context.
 */
export interface EgressContext {
  tenantId: string;
  adapterName: string;
  toolName?: string;
  host: string;
  port?: number;
  protocol?: 'http' | 'https';
  /**
   * §8.9::11 — request-scoped principal identity carried from the
   * authenticated boundary through dispatch. Present only when the caller
   * supplied a full TenantContext; absent on the unauthenticated OSS/local
   * path, which therefore asserts no roles and can gain no grant.
   *
   * NOTE: `egressRuleMatches` does not currently branch on roles/attributes —
   * these are carried and audited, not yet consumed as an authorization
   * input. Adding a role/attribute condition to EgressRule is what would make
   * them load-bearing.
   */
  principalId?: string;
  roles?: string[];
  attributes?: Record<string, string>;
}

/**
 * Outcome of an egress check. Identical shape to PolicyDecision plus
 * the destination tuple for audit/logging.
 */
export interface EgressDecision {
  allow: boolean;
  reason: string;
  ruleId?: string;
  host: string;
  port?: number;
  protocol?: 'http' | 'https';
}

// =============================================================================
// Secrets
// =============================================================================

export interface SecretsConfig {
  provider: 'env' | 'hashicorp-vault' | 'aws-secrets-manager' | 'azure-key-vault';
  address?: string;
  token?: string;
  roleId?: string;
  secretId?: string;
  region?: string;
  vaultName?: string;
  cacheTtlMs?: number;
}

// =============================================================================
// Trust Configuration (top-level)
// =============================================================================

export interface TrustConfig {
  auth: AuthConfig;
  secrets: SecretsConfig;
  policy: {
    rulesPath?: string;
    rules?: PolicyRule[];
    defaultEffect: PolicyEffect;
 /** Egress rules evaluated before any outbound adapter dispatch. */
    egressRules?: EgressRule[];
    /** Default effect for egress when no rule matches. Defaults to 'deny'. */
    egressDefaultEffect?: PolicyEffect;
  };
  artifacts?: {
    verifyDigests: boolean;
    enforceSLSA?: 'SLSA_L1' | 'SLSA_L2' | 'SLSA_L3';
  };
}
