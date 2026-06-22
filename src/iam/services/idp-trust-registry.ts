/**
 * IAM — ID-JAG trusted-issuer registry + JWKS port.
 *
 * Provides two ports the id-jag-validator consumes:
 *
 *   TrustRegistryPort — Mongo-backed CRUD for per-tenant trusted IdP
 *     entries (TrustedIssuerDocument). Read by the validator at
 *     pipeline step 3 to resolve `iss`. CRUD endpoints land in
 *     routes/admin-trust.ts (commit 5).
 *
 *   JwksPort — fetches the public key for a given (jwksUri, kid, alg)
 *     using jose's `createRemoteJWKSet`. One cache instance per
 *     jwksUri; jose handles per-key memoisation, kid-cache-miss
 *     refresh, and the max-keys cap internally per its own contract.
 *
 * HTTPS-only enforcement on `jwksUri` is performed at this layer
 * (registerTrustedIssuer + the JwksPort fetchKey path both reject
 * non-https URIs). The validator does not re-check.
 */

import { createRemoteJWKSet } from 'jose';
import type { JWK, JWTHeaderParameters } from 'jose';
import type { Filter } from 'mongodb';

import { getCollection } from '../db.js';
import { ensureHttps } from '../utils/url.js';
import type { TrustedIssuerDocument } from '../types.js';
import type {
  JwksPort,
  TrustRegistryPort,
  TrustedIssuerView,
  VerifyKey,
} from './id-jag-validator.js';

const COLLECTION = 'iam_id_jag_trusted_issuers';
const DEFAULT_ALG_ALLOWLIST = ['RS256', 'ES256'];

/** Internal cache of one jose RemoteJWKSet getter per jwksUri. */
const _jwksGetters = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function projectView(doc: TrustedIssuerDocument): TrustedIssuerView {
  // Phase 0 baseline correction: surface requireSamlNameIdSubId and
  // samlNameIdIssuers so the validator's §3.2.2 + §9.5 (use-gated)
  // reject paths can actually fire. The validator-facing
  // TrustedIssuerView at id-jag-validator.ts:96-112 has always
  // declared these fields; the registry implementation never
  // plumbed them through. Without this projection the §3.2.2
  // strict-reject path is dead code.
  return {
    iss: doc.issuer,
    audience: doc.audience,
    jwksUri: doc.jwksUri,
    allowedAlgorithms: doc.allowedAlgorithms,
    ...(doc.requireSamlNameIdSubId !== undefined ? { requireSamlNameIdSubId: doc.requireSamlNameIdSubId } : {}),
    ...(doc.samlNameIdIssuers !== undefined ? { samlNameIdIssuers: doc.samlNameIdIssuers } : {}),
    ...(doc.requiresTenantContext !== undefined ? { requiresTenantContext: doc.requiresTenantContext } : {}),
    ...(doc.expectedTenants !== undefined ? { expectedTenants: doc.expectedTenants } : {}),
    ...(doc.tenantScopedClientIds !== undefined ? { tenantScopedClientIds: doc.tenantScopedClientIds } : {}),
  };
}

// ── TrustRegistryPort (validator-facing) ─────────────────────────────────────

export const trustRegistry: TrustRegistryPort = {
  async getTrustedIssuer(tenantId, iss) {
    const col = await getCollection<TrustedIssuerDocument>(COLLECTION);
    const doc = await col.findOne({ tenantId, issuer: iss, active: true });
    return doc ? projectView(doc) : null;
  },
};

// ── JwksPort (validator-facing) ──────────────────────────────────────────────

function getJwksGetter(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let getter = _jwksGetters.get(jwksUri);
  if (!getter) {
    ensureHttps(jwksUri, 'jwksUri');
    // jose's createRemoteJWKSet defaults: 30-day cache max, force-refresh
    // when a presented `kid` misses the cache. Suitable for ID-JAG.
    getter = createRemoteJWKSet(new URL(jwksUri));
    _jwksGetters.set(jwksUri, getter);
  }
  return getter;
}

export const jwksPort: JwksPort = {
  async fetchKey(jwksUri, kid, alg): Promise<VerifyKey> {
    const getter = getJwksGetter(jwksUri);
    // jose's getter signature is (protectedHeader, token?) => Promise<key>.
    // Key selection only consults the header — passing undefined for
    // the optional token is the documented call shape when there is no
    // surrounding JWS to inspect.
    const header: JWTHeaderParameters = { alg };
    if (kid) header.kid = kid;
    const key = await getter(header, undefined);
    return key as VerifyKey;
  },
};

// Test seam: drop all cached JWKS getters. Used by unit tests and by
// admin handlers when a trusted-issuer entry is rotated.
export function clearJwksCache(jwksUri?: string): void {
  if (jwksUri === undefined) {
    _jwksGetters.clear();
    return;
  }
  _jwksGetters.delete(jwksUri);
}

// ── CRUD (admin-facing; consumed by routes/admin-trust.ts in commit 5) ───────

export interface RegisterTrustedIssuerInput {
  tenantId: string;
  issuer: string;
  jwksUri: string;
  audience: string;
  allowedAlgorithms?: string[];
  /**
   * draft-04 §3.2.2 USE-gate. See `TrustedIssuerDocument` for semantics.
   * Operator config: when set true, the AS uses sub_id for resolution
   * and the strict-reject paths fire.
   */
  requireSamlNameIdSubId?: boolean;
  /**
   * draft-04 §9.5 SAML-issuer allowlist. See `TrustedIssuerDocument`
   * for semantics. Consulted only when requireSamlNameIdSubId === true.
   */
  samlNameIdIssuers?: string[];
  /** draft-04 §6.1 conditional USE-gate. */
  requiresTenantContext?: boolean;
  /** draft-04 §6.4 conditional allowlist. */
  expectedTenants?: string[];
  /** draft-04 §6.2 tenant-scoped client_id binding. */
  tenantScopedClientIds?: Record<string, string[]>;
  createdBy: string;
}

export interface RegisterTrustedIssuerResult {
  document: TrustedIssuerDocument;
  /** True when this call inserted a new row; false on a rotation (upsert matched an existing row). */
  upserted: boolean;
}

export async function registerTrustedIssuer(
  input: RegisterTrustedIssuerInput,
): Promise<RegisterTrustedIssuerResult> {
  ensureHttps(input.jwksUri, 'jwksUri');
  const algs = input.allowedAlgorithms ?? DEFAULT_ALG_ALLOWLIST;
  if (algs.some((a) => a.toLowerCase() === 'none')) {
    throw new Error('allowedAlgorithms must not include "none"');
  }
  if (algs.length === 0) {
    throw new Error('allowedAlgorithms must not be empty');
  }
  const col = await getCollection<TrustedIssuerDocument>(COLLECTION);
  // Per-(tenant, issuer) uniqueness — second registration upserts to
  // active:true and refreshes config rather than creating a duplicate row.
  // `createdAt` + `createdBy` are preserved on re-registration via
  // $setOnInsert; the on-disk `createdBy` therefore identifies the
  // ORIGINAL admin even when a later admin rotates jwksUri/audience/algs.
  //
  // Quality round-1: distinguish initial-add from rotation by comparing
  // doc.createdAt to the `now` we just passed to $setOnInsert. If they
  // match exactly, the row was inserted; otherwise an existing row was
  // updated. The caller surfaces this in the audit detail so SOC 2
  // change-management evidence can tell "added" from "rotated".
  const now = new Date();
  // §3.2.2 / §9.5 / §6.x operator config persistence uses PATCH
  // semantics on the security-gate fields: when the caller OMITS
  // a field (passes `undefined`), the prior on-disk value is
  // preserved. This protects a rotation POST (e.g. operator rotates
  // JWKS URI without re-sending §6 fields) from silently clearing
  // §6.1/§6.2/§6.4 tenant-context gates and downgrading the trust
  // policy. To EXPLICITLY clear a gate the caller passes the empty
  // value (false / [] / {}); the validator treats empty as
  // "not configured" (permissive), preserving the §6.2 alternative
  // model. The non-security mandatory fields (jwksUri / audience /
  // allowedAlgorithms / active) keep PUT semantics — operator MUST
  // re-send a current jwksUri on every rotation.
  const securityGateFields: Partial<TrustedIssuerDocument> = {};
  if (input.requireSamlNameIdSubId !== undefined) {
    securityGateFields.requireSamlNameIdSubId = input.requireSamlNameIdSubId;
  }
  if (input.samlNameIdIssuers !== undefined) {
    securityGateFields.samlNameIdIssuers = input.samlNameIdIssuers;
  }
  if (input.requiresTenantContext !== undefined) {
    securityGateFields.requiresTenantContext = input.requiresTenantContext;
  }
  if (input.expectedTenants !== undefined) {
    securityGateFields.expectedTenants = input.expectedTenants;
  }
  if (input.tenantScopedClientIds !== undefined) {
    securityGateFields.tenantScopedClientIds = input.tenantScopedClientIds;
  }
  const doc = await col.findOneAndUpdate(
    { tenantId: input.tenantId, issuer: input.issuer },
    {
      $set: {
        jwksUri: input.jwksUri,
        audience: input.audience,
        allowedAlgorithms: algs,
        active: true,
        ...securityGateFields,
      },
      $setOnInsert: {
        tenantId: input.tenantId,
        issuer: input.issuer,
        createdAt: now,
        createdBy: input.createdBy,
      },
    },
    { upsert: true, returnDocument: 'after' },
  );
  clearJwksCache(input.jwksUri); // Force re-fetch on next validation.
  if (!doc) {
    throw new Error('trusted issuer upsert did not persist');
  }
  const upserted = doc.createdAt instanceof Date && doc.createdAt.getTime() === now.getTime();
  return { document: doc, upserted };
}

/**
 * List trusted issuers for the tenant. By default returns only the
 * active set — soft-deleted (active:false) rows are hidden so the
 * admin list view matches the dispatcher gate semantics. Pass
 * `{ includeInactive: true }` to view the full history (used by audit
 * tooling, not by the public admin UI).
 */
export async function listTrustedIssuers(
  tenantId: string,
  opts?: { includeInactive?: boolean },
): Promise<TrustedIssuerDocument[]> {
  const col = await getCollection<TrustedIssuerDocument>(COLLECTION);
  const filter: Filter<TrustedIssuerDocument> = opts?.includeInactive
    ? { tenantId }
    : { tenantId, active: true };
  // Drop tenantId from each row — the caller already knows the tenant
  // (the route reads it from the authenticated session), so re-shipping
  // it on every row is redundant wire bytes. Other fields are preserved
  // because they are operator-visible config the admin UI displays.
  return col.find(filter, { projection: { tenantId: 0 } }).toArray();
}

export async function revokeTrustedIssuer(
  tenantId: string,
  issuer: string,
): Promise<boolean> {
  const col = await getCollection<TrustedIssuerDocument>(COLLECTION);
  const res = await col.updateOne({ tenantId, issuer }, { $set: { active: false } });
  return res.modifiedCount === 1;
}

/**
 * Test seam: caller can override Mongo lookups when needed. Not used in
 * production; the validator consumes `trustRegistry` directly.
 *
 * Returns the projected port-view directly instead of forging a fake
 * TrustedIssuerDocument with a sentinel ObjectId — the port contract
 * (TrustedIssuerView) is all the caller will read.
 */
export function buildInMemoryTrustRegistry(
  entries: Array<
    Omit<TrustedIssuerDocument, '_id' | 'createdAt' | 'createdBy' | 'active'> & {
      active?: boolean;
    }
  >,
): TrustRegistryPort {
  return {
    async getTrustedIssuer(tenantId, iss) {
      const hit = entries.find(
        (e) => e.tenantId === tenantId && e.issuer === iss && e.active !== false,
      );
      if (!hit) return null;
      return {
        iss: hit.issuer,
        audience: hit.audience,
        jwksUri: hit.jwksUri,
        allowedAlgorithms: hit.allowedAlgorithms,
      };
    },
  };
}

// Re-export the JWK type so test fixtures can build expected views.
export type { JWK };
