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

export interface TenantContext {
  tenantId: string;
  principalId: string;
  roles: string[];
  tier: 'free' | 'pro' | 'enterprise';
  attributes: Record<string, string>;
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
