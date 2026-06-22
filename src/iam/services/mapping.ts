/**
 * IAM — Group→Adapter Mapping Service
 *
 * The canonical document shape is `adapterIds: string[]` — one mapping per
 * group, listing every adapter the group is entitled to. Pre-1.1 deployments
 * may still have documents under the legacy singular `adapterId: string`
 * shape; every read below passes through `normalizeMapping()` so callers
 * only ever see the canonical form. Every write emits the canonical shape
 * (and in-place $unset-strips the legacy field).
 */

import type { ObjectId, UpdateFilter } from 'mongodb';
import { getCollection } from '../db.js';
import type { GroupAdapterMappingDocument } from '../types.js';

const COLLECTION = 'iam_group_adapter_mappings';

/**
 * Real on-disk shape across all deployed versions. Private to this module:
 * callers see only the canonical `GroupAdapterMappingDocument`.
 */
interface StoredGroupAdapterMapping {
  _id: ObjectId;
  tenantId: string;
  groupId: string;
  adapterIds?: string[];   // canonical (1.1+)
  adapterId?: string;      // legacy (1.0.x)
  allowedOperations: string[];
  maxQueriesPerHour: number;
  createdAt: Date;
  updatedAt: Date;
}

function normalizeMapping(
  stored: StoredGroupAdapterMapping,
): GroupAdapterMappingDocument {
  const adapterIds = stored.adapterIds
    ?? (stored.adapterId ? [stored.adapterId] : []);
  return {
    _id: stored._id,
    tenantId: stored.tenantId,
    groupId: stored.groupId,
    adapterIds,
    allowedOperations: stored.allowedOperations,
    maxQueriesPerHour: stored.maxQueriesPerHour,
    createdAt: stored.createdAt,
    updatedAt: stored.updatedAt,
  };
}

// ── Reads ───────────────────────────────────────────────────────────────────

export async function list(tenantId: string): Promise<GroupAdapterMappingDocument[]> {
  const col = await getCollection<StoredGroupAdapterMapping>(COLLECTION);
  const stored = await col.find({ tenantId }).toArray();
  return stored.map(normalizeMapping);
}

export async function getByGroupId(
  tenantId: string,
  groupId: string,
): Promise<GroupAdapterMappingDocument | null> {
  const col = await getCollection<StoredGroupAdapterMapping>(COLLECTION);
  const stored = await col.findOne({ tenantId, groupId });
  return stored ? normalizeMapping(stored) : null;
}

/**
 * Union of adapter IDs across a set of group IDs for a tenant. Hot path on
 * session issue — a runtime crash here takes down auth, which is why reads
 * must tolerate legacy documents instead of trusting the declared type.
 */
export async function resolveAdapterIds(
  tenantId: string,
  groupIds: string[],
): Promise<string[]> {
  if (groupIds.length === 0) return [];

  const col = await getCollection<StoredGroupAdapterMapping>(COLLECTION);
  const stored = await col
    .find({ tenantId, groupId: { $in: groupIds } })
    .toArray();

  const adapterSet = new Set<string>();
  for (const raw of stored) {
    for (const id of normalizeMapping(raw).adapterIds) {
      adapterSet.add(id);
    }
  }
  return [...adapterSet];
}

/**
 * Resolve per-(adapterId, operation) grants for a user across all
 * group mappings. Returns a Record mapping each adapterId to the union of
 * `allowedOperations` declared on every group mapping that includes that
 * adapterId. Used by issueToken() to stamp the JWT with the
 * `allowedOperations` claim that chariot_call enforces at request time.
 *
 * Empty groupIds → empty record (deny-by-default at the call site). A user
 * whose groups map to adapters but whose mapping documents have empty
 * `allowedOperations` arrays gets adapterId keys with empty arrays — the
 * call-site enforcement treats those as deny.
 */
export async function resolveAllowedOperations(
  tenantId: string,
  groupIds: string[],
): Promise<Record<string, string[]>> {
  if (groupIds.length === 0) return {};

  const col = await getCollection<StoredGroupAdapterMapping>(COLLECTION);
  const stored = await col
    .find({ tenantId, groupId: { $in: groupIds } })
    .toArray();

  const result: Record<string, Set<string>> = {};
  for (const raw of stored) {
    const m = normalizeMapping(raw);
    const ops = Array.isArray(m.allowedOperations) ? m.allowedOperations : [];
    for (const adapterId of m.adapterIds) {
      const bucket = result[adapterId] ?? new Set<string>();
      for (const op of ops) bucket.add(op);
      result[adapterId] = bucket;
    }
  }

  const out: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(result)) out[k] = [...v];
  return out;
}

// ── Writes ──────────────────────────────────────────────────────────────────

/**
 * Update a mapping by its document `_id` (tenant-scoped). The same atomic
 * write `$unset`s the legacy singular `adapterId` field whenever the plural
 * `adapterIds` is written, so a legacy document upgrades in place.
 */
export async function updateById(
  tenantId: string,
  id: ObjectId,
  fields: {
    adapterIds: string[];
    allowedOperations?: string[];
    maxQueriesPerHour?: number;
  },
): Promise<GroupAdapterMappingDocument | null> {
  const update: UpdateFilter<StoredGroupAdapterMapping> = {
    $set: {
      updatedAt: new Date(),
      adapterIds: fields.adapterIds,
      ...(fields.allowedOperations !== undefined && { allowedOperations: fields.allowedOperations }),
      ...(fields.maxQueriesPerHour !== undefined && { maxQueriesPerHour: fields.maxQueriesPerHour }),
    },
    $unset: { adapterId: '' },
  };

  const col = await getCollection<StoredGroupAdapterMapping>(COLLECTION);
  const result = await col.findOneAndUpdate(
    { _id: id, tenantId },
    update,
    { returnDocument: 'after' },
  );
  return result ? normalizeMapping(result) : null;
}
