/**
 * IAM — ID-JAG scope-mapping registry.
 *
 * Per-tenant CRUD for IdP claim → adapter/operation mappings. The
 * id-jag-issuer at /enterprise/oauth/token reads these to translate
 * an inbound assertion's claim values (e.g. `groups: ["okta-eng"]`)
 * into the Chariot session's `adapterIds` + `allowedOperations` so
 * downstream RBAC at chariot_call can enforce per-tool grants.
 *
 * Per-tenant uniqueness key: (tenantId, fromClaim, fromValue). Two
 * different claim values may map to overlapping adapter sets; this is
 * the spec-approved fan-in pattern.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { ObjectId } from 'mongodb';
import type { Filter } from 'mongodb';

import { getCollection } from '../db.js';
import type { ScopeMappingDocument } from '../types.js';

const COLLECTION = 'iam_id_jag_scope_mappings';

export interface RegisterScopeMappingInput {
  tenantId: string;
  fromClaim: string;
  fromValue: string;
  toAdapterIds: string[];
  toAllowedOperations: Record<string, string[]>;
  createdBy: string;
}

/**
 * Register a claim→scope mapping. Per-(tenantId, fromClaim, fromValue)
 * uniqueness via upsert — re-registration refreshes adapterIds /
 * allowedOperations and reactivates the entry. `createdAt`/`createdBy`
 * are preserved on re-registration via $setOnInsert so original-author
 * attribution stays on the document; subsequent author changes live
 * in the audit trail.
 */
export interface RegisterScopeMappingResult {
  document: ScopeMappingDocument;
  /** True when this call inserted a new row; false on a rotation. */
  upserted: boolean;
}

export async function registerScopeMapping(
  input: RegisterScopeMappingInput,
): Promise<RegisterScopeMappingResult> {
  if (!input.fromClaim || input.fromClaim.length === 0) {
    throw new Error('fromClaim must be a non-empty string');
  }
  if (!input.fromValue || input.fromValue.length === 0) {
    throw new Error('fromValue must be a non-empty string');
  }
  if (input.toAdapterIds.length === 0) {
    throw new Error('toAdapterIds must not be empty');
  }
  // Defensive — toAllowedOperations keys SHOULD be a subset of toAdapterIds
  // but the spec allows extras (no-op grants for adapters not yet
  // included). We accept the input as-is; the issuer ignores grants
  // for adapterIds not in the resolved set.
  const col = await getCollection<ScopeMappingDocument>(COLLECTION);
  const now = new Date();
  const doc = await col.findOneAndUpdate(
    { tenantId: input.tenantId, fromClaim: input.fromClaim, fromValue: input.fromValue },
    {
      $set: {
        toAdapterIds: input.toAdapterIds,
        toAllowedOperations: input.toAllowedOperations,
        active: true,
      },
      $setOnInsert: {
        tenantId: input.tenantId,
        fromClaim: input.fromClaim,
        fromValue: input.fromValue,
        createdAt: now,
        createdBy: input.createdBy,
      },
    },
    { upsert: true, returnDocument: 'after' },
  );
  if (!doc) {
    throw new Error('scope mapping upsert did not persist');
  }
  const upserted = doc.createdAt instanceof Date && doc.createdAt.getTime() === now.getTime();
  return { document: doc, upserted };
}

/**
 * List scope mappings for the tenant. Active-only by default; pass
 * `{ includeInactive: true }` to view the full history.
 */
export async function listScopeMappings(
  tenantId: string,
  opts?: { includeInactive?: boolean },
): Promise<ScopeMappingDocument[]> {
  const col = await getCollection<ScopeMappingDocument>(COLLECTION);
  const filter: Filter<ScopeMappingDocument> = opts?.includeInactive
    ? { tenantId }
    : { tenantId, active: true };
  // Drop tenantId from each row — redundant on the wire (caller's
  // session is already tenant-scoped) and the largest repeated field.
  return col.find(filter, { projection: { tenantId: 0 } }).toArray();
}

/**
 * Soft-delete a scope mapping by its document _id (tenant-scoped).
 * Mirrors the `active: false` flag pattern used by the trust + client
 * registries — preserves the historical record for audit but prevents
 * the issuer from honoring it on future token exchanges.
 */
export async function revokeScopeMapping(
  tenantId: string,
  id: ObjectId,
): Promise<boolean> {
  const col = await getCollection<ScopeMappingDocument>(COLLECTION);
  const res = await col.updateOne({ _id: id, tenantId }, { $set: { active: false } });
  return res.modifiedCount === 1;
}
