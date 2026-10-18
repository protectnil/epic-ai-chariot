/**
 * @epicai/chariot — Tenant Context
 * Request-scoped tenant/principal/role propagation.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { PrincipalType, TenantContext } from './types.js';

const DEV_CONTEXT: TenantContext = {
  tenantId: 'dev',
  principalId: 'dev-user',
  roles: ['admin'],
  tier: 'enterprise',
  attributes: {},
  principalType: 'human',
};

/**
 * Create a development-mode tenant context.
 * Used when NODE_ENV=development and no auth is configured.
 * The local developer at the keyboard is a human principal.
 */
export function createDevContext(): TenantContext {
  return { ...DEV_CONTEXT };
}

/**
 * Parse a caller-supplied principal-kind value into a PrincipalType.
 * Accepts the three recognized kinds case-insensitively; returns
 * undefined for anything else (missing claim, wrong type, unknown
 * string) so the caller can apply the documented safe default of
 * 'human' — identical to pre-partition behavior. Mirrors
 * `normalize_principal_type` in native/src/rbac.rs.
 */
export function parsePrincipalType(value: unknown): PrincipalType | undefined {
  if (typeof value !== 'string') return undefined;
  const lower = value.toLowerCase();
  if (lower === 'human' || lower === 'agent' || lower === 'service') return lower;
  return undefined;
}

/**
 * Create a tenant context from JWT claims.
 *
 * Principal kind (gap #3 — Wiz 2 human/agent/service partition): honored
 * ONLY from an explicit `principal_type` / `principalType` claim minted
 * by the issuer. Absent or unrecognized → 'human', which preserves the
 * exact pre-partition behavior for every existing token. No other claim
 * is used to infer principal kind — inference heuristics here would let
 * classification drift from what the issuer actually attested.
 */
export function contextFromJWT(claims: Record<string, unknown>): TenantContext {
  return {
    tenantId: String(claims.tenant_id ?? claims.org_id ?? claims.sub ?? 'unknown'),
    principalId: String(claims.sub ?? 'unknown'),
    roles: Array.isArray(claims.roles) ? claims.roles as string[] : [],
    tier: parseTier(claims.tier),
    attributes: typeof claims.attributes === 'object' && claims.attributes !== null
      ? claims.attributes as Record<string, string>
      : {},
    principalType:
      parsePrincipalType(claims.principal_type ?? claims.principalType) ?? 'human',
  };
}

/**
 * Create a tenant context from an mTLS client certificate.
 *
 * Principal kind: always 'service'. An mTLS client certificate
 * authenticates a machine workload, not a person at a keyboard — there
 * is no human interactive flow that presents a client cert here, so the
 * cert path is by definition a machine-to-machine (service) principal.
 */
export function contextFromCert(cert: { subject: { CN?: string }; subjectaltname?: string }): TenantContext {
  const cn = cert.subject?.CN ?? 'unknown';
  return {
    tenantId: cn.split('.')[0] ?? cn,
    principalId: cn,
    roles: ['authenticated'],
    tier: 'enterprise',
    attributes: {
      ...(cert.subjectaltname ? { san: cert.subjectaltname } : {}),
    },
    principalType: 'service',
  };
}

function parseTier(value: unknown): 'free' | 'pro' | 'enterprise' {
  if (value === 'free' || value === 'pro' || value === 'enterprise') return value;
  return 'free';
}
