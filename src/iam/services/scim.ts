/**
 * IAM — SCIM 2.0 Service
 *
 * User and Group provisioning per RFC 7644 with JIT provisioning,
 * Okta-compatible PATCH handling, and deprovisioning safeguards.
 */

import { ObjectId } from 'mongodb';
import type { Filter } from 'mongodb';
import { getCollection } from '../db.js';
import { resolveAdapterIds } from './mapping.js';
import { revokeAllUserSessions, revokeAllUserRefreshTokens } from './session.js';
import type {
  EnterpriseUserDocument,
  EnterpriseGroupDocument,
  ScimUser,
  ScimGroup,
  ScimPatchOp,
  ScimListResponse,
  AdapterCredentialDocument,
} from '../types.js';

const USERS_COLLECTION = 'iam_users';
const GROUPS_COLLECTION = 'iam_groups';

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Parse a 24-character hex string into a MongoDB ObjectId.
 * Returns null if the input is not a valid ObjectId-shaped string.
 *
 * Used at every entry point that takes a user-supplied id (SCIM PATCH/PUT/
 * DELETE by id) to convert the string to an ObjectId before querying Mongo.
 * Returning null instead of throwing lets callers surface a clean 404
 * rather than a library-thrown BSONTypeError.
 */
function toObjectId(id: string): ObjectId | null {
  if (typeof id !== 'string' || !/^[0-9a-fA-F]{24}$/.test(id)) return null;
  return new ObjectId(id);
}

/**
 * Build a user filter that scopes by ObjectId + tenant. Returns null when
 * the id is malformed so the caller can return a 404 without querying.
 */
function userFilterById(
  id: string,
  tenantId: string,
): Filter<EnterpriseUserDocument> | null {
  const objectId = toObjectId(id);
  if (!objectId) return null;
  return { _id: objectId, tenantId };
}

/**
 * Same as `userFilterById` for groups.
 */
function groupFilterById(
  id: string,
  tenantId: string,
): Filter<EnterpriseGroupDocument> | null {
  const objectId = toObjectId(id);
  if (!objectId) return null;
  return { _id: objectId, tenantId };
}

/**
 * Narrow an `unknown` metadata value to a string. Used when reading
 * `user.metadata.givenName` / `user.metadata.familyName` — the declared
 * type is `Record<string, unknown>` so direct assignment to `string`
 * fields would fail under `no-unsafe-assignment`.
 */
function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

// ═══════════════════════════════════════════════════════════════════════════
// SCIM Response Converters
// ═══════════════════════════════════════════════════════════════════════════

export function toScimUser(user: EnterpriseUserDocument, baseUrl = ''): ScimUser {
  const userIdStr = user._id.toString();
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: userIdStr,
    externalId: user.externalId ?? '',
    userName: user.userName ?? user.email,
    displayName: user.displayName,
    name: {
      givenName: asString(user.metadata?.givenName, user.givenName ?? ''),
      familyName: asString(user.metadata?.familyName, user.familyName ?? ''),
    },
    emails: [{ value: user.email ?? user.userName, primary: true }],
    active: user.active,
    groups: (user.groups ?? []).map((gid) => ({ value: gid, display: '' })),
    meta: {
      resourceType: 'User',
      created: user.createdAt?.toISOString(),
      lastModified: user.updatedAt?.toISOString(),
      location: baseUrl ? `${baseUrl}/Users/${userIdStr}` : '',
    },
  };
}

export function toScimGroup(group: EnterpriseGroupDocument, baseUrl = ''): ScimGroup {
  const groupIdStr = group._id.toString();
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    id: groupIdStr,
    externalId: group.externalId,
    displayName: group.displayName,
    members: (group.members ?? []).map((mid) => ({ value: mid, display: '' })),
    meta: {
      resourceType: 'Group',
      created: group.createdAt?.toISOString(),
      lastModified: group.updatedAt?.toISOString(),
      location: baseUrl ? `${baseUrl}/Groups/${groupIdStr}` : '',
    },
  };
}

function scimList<T>(
  resources: T[],
  total: number,
  startIndex = 1,
): ScimListResponse<T> {
  return {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: total,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// Group-membership helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Resolve a user's adapter IDs from their group memberships via the mapping service.
 */
export async function resolveUserAdapters(
  tenantId: string,
  groupIds: string[],
): Promise<string[]> {
  return resolveAdapterIds(tenantId, groupIds);
}

/**
 * After group membership changes, update each affected user's groups array.
 *
 * `memberIds` are expected to be stringified ObjectIds (SCIM member value
 * field). Non-ObjectId strings are ignored with a warning log.
 */
export async function syncGroupMembership(
  tenantId: string,
  groupId: string,
  memberIds: string[],
): Promise<void> {
  const usersCol = await getCollection<EnterpriseUserDocument>(USERS_COLLECTION);

  for (const memberId of memberIds) {
    const memberObjectId = toObjectId(memberId);
    if (!memberObjectId) {
       
      console.warn(`[iam/scim] syncGroupMembership: skipping non-ObjectId member '${memberId}'`);
      continue;
    }
    const user = await usersCol.findOne({ _id: memberObjectId, tenantId });
    if (!user) continue;

    const currentGroups = new Set(user.groups ?? []);
    currentGroups.add(groupId);
    const groupsArray = [...currentGroups];

    await usersCol.updateOne(
      { _id: user._id },
      { $set: { groups: groupsArray, updatedAt: new Date() } },
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Users
// ═══════════════════════════════════════════════════════════════════════════

/**
 * List users with basic SCIM filter support (userName eq "x").
 */
export async function listUsers(
  tenantId: string,
  filter?: string,
  startIndex = 1,
  count = 100,
): Promise<ScimListResponse<ScimUser>> {
  const col = await getCollection<EnterpriseUserDocument>(USERS_COLLECTION);
  const query: Filter<EnterpriseUserDocument> = { tenantId };

  // Basic SCIM filter: userName eq "value"
  if (filter) {
    const eqMatch = filter.match(/^(\w+)\s+eq\s+"([^"]+)"$/i);
    if (eqMatch) {
      const [, field, value] = eqMatch;
      if (field === 'userName') {
        (query as { userName?: string }).userName = value;
      } else if (field === 'externalId') {
        (query as { externalId?: string }).externalId = value;
      }
    }
  }

  const skip = Math.max(0, startIndex - 1);
  const [users, total] = await Promise.all([
    col.find(query).skip(skip).limit(count).toArray(),
    col.countDocuments(query),
  ]);

  return scimList(users.map((u) => toScimUser(u)), total, startIndex);
}

export async function getUser(
  tenantId: string,
  userId: string,
): Promise<EnterpriseUserDocument | null> {
  const filter = userFilterById(userId, tenantId);
  if (!filter) return null;
  const col = await getCollection<EnterpriseUserDocument>(USERS_COLLECTION);
  return col.findOne(filter);
}

export async function createUser(
  tenantId: string,
  data: Partial<EnterpriseUserDocument>,
): Promise<EnterpriseUserDocument> {
  if (!data.userName) {
    throw new Error('createUser: userName is required');
  }
  const col = await getCollection<EnterpriseUserDocument>(USERS_COLLECTION);
  const now = new Date();

  const user: Omit<EnterpriseUserDocument, '_id'> = {
    tenantId,
    externalId: data.externalId ?? '',
    userName: data.userName,
    displayName: data.displayName ?? '',
    email: data.email ?? data.userName,
    active: data.active ?? true,
    groups: data.groups ?? [],
    metadata: data.metadata ?? {},
    createdAt: now,
    updatedAt: now,
  };

  const result = await col.insertOne(user as EnterpriseUserDocument);
  return { ...user, _id: result.insertedId };
}

export async function replaceUser(
  tenantId: string,
  userId: string,
  data: Partial<EnterpriseUserDocument>,
): Promise<EnterpriseUserDocument | null> {
  const filter = userFilterById(userId, tenantId);
  if (!filter) return null;

  const col = await getCollection<EnterpriseUserDocument>(USERS_COLLECTION);
  const now = new Date();

  const existing = await col.findOne(filter);
  if (!existing) return null;

  const setData: Partial<EnterpriseUserDocument> = {
    externalId: data.externalId ?? existing.externalId,
    userName: data.userName ?? existing.userName,
    displayName: data.displayName ?? existing.displayName,
    email: data.email ?? existing.email,
    active: data.active ?? true,
    groups: data.groups ?? existing.groups,
    metadata: data.metadata ?? existing.metadata,
    updatedAt: now,
  };

  const result = await col.findOneAndUpdate(
    filter,
    { $set: setData },
    { returnDocument: 'after' },
  );

  if (!result) return null;

  // Deprovisioning: if user was active and is now inactive
  if (existing.active && !result.active) {
    await handleDeprovisioning(tenantId, userId);
  }

  return result;
}

/**
 * SCIM PATCH — handles Okta-style operations:
 * - Replace active (boolean)
 * - Replace displayName
 * - Replace name.givenName / name.familyName (mapped to metadata)
 * - Direct value without path (Okta sends { op: 'replace', value: { active: false } })
 */
// the previous `patchUser` service helper was dead code — the
// HTTP route in src/iam/routes/scim.ts has owned PATCH /Users/:id for
// every release of 3.x. Two implementations drifted (the route added
// fixes the service never received). Removed the dead helper so there
// is one canonical PATCH path. Future PATCH changes go in the route.

export async function deleteUser(
  tenantId: string,
  userId: string,
): Promise<boolean> {
  const filter = userFilterById(userId, tenantId);
  if (!filter) return false;

  const col = await getCollection<EnterpriseUserDocument>(USERS_COLLECTION);

  // Deprovision before deletion
  await handleDeprovisioning(tenantId, userId);

  const result = await col.deleteOne(filter);
  return result.deletedCount > 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Deprovisioning
// ═══════════════════════════════════════════════════════════════════════════

/**
 * CRITICAL: On deactivation/deletion, revoke all sessions and
 * mark adapter credentials as revoked.
 */
async function handleDeprovisioning(
  tenantId: string,
  userId: string,
): Promise<void> {
  // Revoke all active sessions AND refresh tokens. Refresh tokens survive
  // access-token revocation otherwise — a deprovisioned user could mint a new
  // session via /refresh until the refresh token's 30-day TTL expires.
  await revokeAllUserSessions(tenantId, userId);
  await revokeAllUserRefreshTokens(tenantId, userId);

  // Revoke adapter credentials. `connectedBy` stores the user's email on
  // user-scoped credentials; for deprovisioning by userId we match on
  // both the ObjectId-stringified user id and any email the user owned.
  // Callers should also ensure the user document itself is in the
  // deactivated state before invoking this to avoid races.
  const credCol = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');
  await credCol.updateMany(
    {
      tenantId,
      connectedBy: userId,
      status: { $ne: 'revoked' },
    },
    { $set: { status: 'revoked', revokedAt: new Date() } },
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Groups
// ═══════════════════════════════════════════════════════════════════════════

export async function listGroups(
  tenantId: string,
  filter?: string,
  startIndex = 1,
  count = 100,
): Promise<ScimListResponse<ScimGroup>> {
  const col = await getCollection<EnterpriseGroupDocument>(GROUPS_COLLECTION);
  const query: Filter<EnterpriseGroupDocument> = { tenantId };

  if (filter) {
    const eqMatch = filter.match(/^(\w+)\s+eq\s+"([^"]+)"$/i);
    if (eqMatch) {
      const [, field, value] = eqMatch;
      if (field === 'displayName') {
        (query as { displayName?: string }).displayName = value;
      }
    }
  }

  const skip = Math.max(0, startIndex - 1);
  const [groups, total] = await Promise.all([
    col.find(query).skip(skip).limit(count).toArray(),
    col.countDocuments(query),
  ]);

  return scimList(groups.map((g) => toScimGroup(g)), total, startIndex);
}

export async function getGroup(
  tenantId: string,
  groupId: string,
): Promise<EnterpriseGroupDocument | null> {
  const filter = groupFilterById(groupId, tenantId);
  if (!filter) return null;
  const col = await getCollection<EnterpriseGroupDocument>(GROUPS_COLLECTION);
  return col.findOne(filter);
}

export async function createGroup(
  tenantId: string,
  data: Partial<EnterpriseGroupDocument>,
): Promise<EnterpriseGroupDocument> {
  if (!data.displayName) {
    throw new Error('createGroup: displayName is required');
  }

  const col = await getCollection<EnterpriseGroupDocument>(GROUPS_COLLECTION);
  const now = new Date();

  const group: Omit<EnterpriseGroupDocument, '_id'> = {
    tenantId,
    externalId: data.externalId ?? '',
    displayName: data.displayName,
    members: data.members ?? [],
    createdAt: now,
    updatedAt: now,
  };

  const result = await col.insertOne(group as EnterpriseGroupDocument);
  return { ...group, _id: result.insertedId };
}

export async function replaceGroup(
  tenantId: string,
  groupId: string,
  data: Partial<EnterpriseGroupDocument>,
): Promise<EnterpriseGroupDocument | null> {
  const filter = groupFilterById(groupId, tenantId);
  if (!filter) return null;

  if (!data.displayName) {
    throw new Error('replaceGroup: displayName is required');
  }

  const col = await getCollection<EnterpriseGroupDocument>(GROUPS_COLLECTION);

  const now = new Date();
  const setData: Partial<EnterpriseGroupDocument> = {
    displayName: data.displayName,
    externalId: data.externalId,
    members: data.members ?? [],
    updatedAt: now,
  };

  const result = await col.findOneAndUpdate(
    filter,
    { $set: setData },
    { returnDocument: 'after' },
  );

  if (result && data.members) {
    await syncGroupMembership(tenantId, groupId, data.members);
  }

  return result ?? null;
}

/**
 * SCIM PATCH for groups — handles add/remove members.
 */
export async function patchGroup(
  tenantId: string,
  groupId: string,
  patchOp: ScimPatchOp,
): Promise<EnterpriseGroupDocument | null> {
  const filter = groupFilterById(groupId, tenantId);
  if (!filter) return null;

  const col = await getCollection<EnterpriseGroupDocument>(GROUPS_COLLECTION);

  const existing = await col.findOne(filter);
  if (!existing) return null;

  let members = [...(existing.members ?? [])];

  for (const op of patchOp.Operations) {
    // Extract member values from various SCIM formats
    const memberValues: string[] = [];
    if (Array.isArray(op.value)) {
      for (const item of op.value as Array<{ value: string }>) {
        if (item.value) memberValues.push(item.value);
      }
    } else if (op.value && typeof op.value === 'object' && 'value' in (op.value as Record<string, unknown>)) {
      memberValues.push((op.value as { value: string }).value);
    }

    switch (op.op) {
      case 'add': {
        for (const mid of memberValues) {
          if (!members.includes(mid)) {
            members.push(mid);
          }
        }
        break;
      }
      case 'remove': {
        if (op.path?.startsWith('members[value eq')) {
          const valMatch = op.path.match(/members\[value eq "([^"]+)"\]/);
          if (valMatch) {
            members = members.filter((m) => m !== valMatch[1]);
          }
        } else {
          const removeSet = new Set(memberValues);
          members = members.filter((m) => !removeSet.has(m));
        }
        break;
      }
      case 'replace': {
        if (op.path === 'members') {
          members = memberValues;
        }
        break;
      }
    }
  }

  const result = await col.findOneAndUpdate(
    filter,
    { $set: { members, updatedAt: new Date() } },
    { returnDocument: 'after' },
  );

  // Sync memberships for affected users
  await syncGroupMembership(tenantId, groupId, members);

  return result ?? null;
}

export async function deleteGroup(
  tenantId: string,
  groupId: string,
): Promise<boolean> {
  const filter = groupFilterById(groupId, tenantId);
  if (!filter) return false;

  const col = await getCollection<EnterpriseGroupDocument>(GROUPS_COLLECTION);

  const result = await col.deleteOne(filter);
  if (result.deletedCount > 0) {
    // Remove this group from all users' groups arrays
    const usersCol = await getCollection<EnterpriseUserDocument>(USERS_COLLECTION);
    await usersCol.updateMany(
      { tenantId, groups: groupId },
      { $pull: { groups: groupId } },
    );
  }
  return result.deletedCount > 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// JIT Provisioning
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Just-In-Time provisioning: create or update a user on first SSO login,
 * assigning them to the specified groups and resolving adapter access.
 */
export async function jitProvision(
  tenantId: string,
  email: string,
  displayName?: string,
  givenName?: string,
  familyName?: string,
  groupNames?: string[],
): Promise<EnterpriseUserDocument> {
  const usersCol = await getCollection<EnterpriseUserDocument>(USERS_COLLECTION);
  const groupsCol = await getCollection<EnterpriseGroupDocument>(GROUPS_COLLECTION);

  // Find or create the user
  const user = await usersCol.findOne({ tenantId, userName: email });

  // Resolve group IDs from display names. Group _id is an ObjectId in
  // storage; we stringify it for the user.groups array which is declared
  // as string[] (display-friendly IDs).
  const groupIds: string[] = [];
  if (groupNames && groupNames.length > 0) {
    for (const name of groupNames) {
      const group = await groupsCol.findOne({ tenantId, displayName: name });
      if (group) {
        groupIds.push(group._id.toString());
      }
    }
  }

  const now = new Date();

  if (user) {
    // Update existing user
    await usersCol.updateOne(
      { _id: user._id },
      {
        $set: {
          displayName: displayName ?? user.displayName,
          metadata: {
            ...user.metadata,
            givenName: givenName ?? asString(user.metadata?.givenName),
            familyName: familyName ?? asString(user.metadata?.familyName),
          },
          groups: groupIds,
          active: true,
          updatedAt: now,
        },
      },
    );

    return { ...user, groups: groupIds, active: true, updatedAt: now };
  }

  // Create new user
  const newUser: Omit<EnterpriseUserDocument, '_id'> = {
    tenantId,
    externalId: '',
    userName: email,
    displayName: displayName ?? email,
    email,
    active: true,
    groups: groupIds,
    metadata: { givenName: givenName ?? '', familyName: familyName ?? '' },
    createdAt: now,
    updatedAt: now,
  };

  const result = await usersCol.insertOne(newUser as EnterpriseUserDocument);
  return { ...newUser, _id: result.insertedId };
}
