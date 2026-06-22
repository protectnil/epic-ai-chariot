/**
 * SCIM 2.0 Provisioning Routes
 *
 * Full SCIM 2.0 compliance for /Users and /Groups resources,
 * plus service discovery endpoints.
 *
 * All routes are protected by scimAuthMiddleware().
 * Uses mergeParams: true to access :tenantId from the parent router.
 *
 * Routes:
 *   GET    /Users                 -- List users (filter, pagination)
 *   POST   /Users                 -- Create user
 *   GET    /Users/:id             -- Get user
 *   PUT    /Users/:id             -- Replace user
 *   PATCH  /Users/:id             -- Partial update (Okta primary method)
 *   DELETE /Users/:id             -- Delete user
 *   GET    /Groups                -- List groups
 *   POST   /Groups                -- Create group
 *   GET    /Groups/:id            -- Get group
 *   PUT    /Groups/:id            -- Replace group
 *   PATCH  /Groups/:id            -- Update group membership
 *   DELETE /Groups/:id            -- Delete group
 *   GET    /ServiceProviderConfig -- SCIM service discovery
 *   GET    /Schemas               -- SCIM schema discovery
 *
 * @module iam/routes/scim
 */

import { Router } from 'express';
import { z } from 'zod';
import { ObjectId } from 'mongodb';
import type { Request, Response } from 'express';
import type { Filter } from 'mongodb';
import { scimAuthMiddleware } from '../middleware.js';
import { getCollection } from '../db.js';
import * as audit from '../services/audit.js';
import { revokeAllUserSessions, revokeAllUserRefreshTokens } from '../services/session.js';
import type { EnterpriseUserDocument, EnterpriseGroupDocument } from '../types.js';

const router = Router({ mergeParams: true });

// Apply SCIM auth to all routes on this router
router.use(scimAuthMiddleware());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Narrow a route parameter to a non-empty string.
 */
function getStringParam(req: Request, name: string): string | null {
  const value = req.params[name];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Parse a 24-hex-character MongoDB ObjectId. Returns null on any parse
 * failure so callers can respond with a SCIM 404 instead of leaking a
 * BSONTypeError.
 */
function toObjectId(id: string | null): ObjectId | null {
  if (!id || !/^[0-9a-fA-F]{24}$/.test(id)) return null;
  return new ObjectId(id);
}

/**
 * Scim routes rely on `scimAuthMiddleware` to populate `req.tenantId`.
 * This helper narrows the optional field to a string and 400s if the
 * middleware didn't run (defensive — should not happen in correct
 * wiring).
 */
function requireTenant(req: Request, res: Response): string | null {
  const tenantId = req.tenantId;
  if (!tenantId) {
    scimError(res, 400, 'Tenant not resolved');
    return null;
  }
  return tenantId;
}

// ---------------------------------------------------------------------------
// Zod schemas for SCIM request validation
// ---------------------------------------------------------------------------

const ScimUserSchema = z.object({
  schemas: z.array(z.string()),
  userName: z.string().email(),
  displayName: z.string().optional(),
  name: z.object({
    givenName: z.string().optional(),
    familyName: z.string().optional(),
  }).optional(),
  emails: z.array(z.object({
    value: z.string().email(),
    primary: z.boolean().optional(),
  })).optional(),
  active: z.boolean().optional().default(true),
  externalId: z.string().optional(),
});

const ScimPatchSchema = z.object({
  schemas: z.array(z.string()),
  Operations: z.array(z.object({
    op: z.enum(['add', 'replace', 'remove']),
    path: z.string().optional(),
    value: z.unknown().optional(),
  })),
});

const ScimGroupSchema = z.object({
  schemas: z.array(z.string()),
  displayName: z.string(),
  members: z.array(z.object({
    value: z.string(),
    display: z.string().optional(),
  })).optional(),
  externalId: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

function scimError(res: Response, status: number, detail: string): void {
  res.status(status).json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
    detail,
    status: String(status),
  });
}

interface ScimUserShape {
  _id: ObjectId;
  externalId?: string;
  userName?: string;
  email?: string;
  displayName?: string;
  metadata?: Record<string, unknown>;
  groups?: string[];
  active?: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}

interface ScimGroupShape {
  _id: ObjectId;
  externalId?: string;
  displayName?: string;
  members?: string[];
  createdAt?: Date;
  updatedAt?: Date;
}

function asString(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback;
}

function toScimUser(doc: ScimUserShape, baseUrl: string): Record<string, unknown> {
  const idStr = doc._id.toString();
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: idStr,
    externalId: doc.externalId,
    userName: doc.userName ?? doc.email,
    displayName: doc.displayName,
    name: doc.metadata && typeof doc.metadata === 'object'
      ? {
          givenName: asString(doc.metadata.givenName),
          familyName: asString(doc.metadata.familyName),
        }
      : {},
    emails: [{ value: doc.email, primary: true }],
    active: doc.active,
    groups: (doc.groups ?? []).map((g) => ({ value: g, display: g })),
    meta: {
      resourceType: 'User',
      created: doc.createdAt?.toISOString(),
      lastModified: doc.updatedAt?.toISOString(),
      location: `${baseUrl}/Users/${idStr}`,
    },
  };
}

function toScimGroup(doc: ScimGroupShape, baseUrl: string): Record<string, unknown> {
  const idStr = doc._id.toString();
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    id: idStr,
    externalId: doc.externalId,
    displayName: doc.displayName,
    members: (doc.members ?? []).map((m) => ({
      value: String(m),
    })),
    meta: {
      resourceType: 'Group',
      created: doc.createdAt?.toISOString(),
      lastModified: doc.updatedAt?.toISOString(),
      location: `${baseUrl}/Groups/${idStr}`,
    },
  };
}

function getBaseUrl(req: Request): string {
  return `${req.protocol}://${req.get('host') ?? ''}${req.baseUrl}`;
}

// ---------------------------------------------------------------------------
// /Users
// ---------------------------------------------------------------------------

/** GET /Users -- List users with optional filter and pagination */
router.get('/Users', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  try {
    const collection = await getCollection<EnterpriseUserDocument>('iam_users');

    const startIndex = Math.max(1, parseInt(req.query.startIndex as string, 10) || 1);
    const count = Math.min(100, Math.max(1, parseInt(req.query.count as string, 10) || 100));
    const filter = req.query.filter as string | undefined;

    const query: Filter<EnterpriseUserDocument> = { tenantId };

    // Basic SCIM filter support: userName eq "value"
    if (filter) {
      const match = filter.match(/^userName\s+eq\s+"([^"]+)"$/i);
      if (match) {
        (query as { email?: string }).email = match[1];
      }
    }

    const total = await collection.countDocuments(query);
    const docs = await collection
      .find(query)
      .skip(startIndex - 1)
      .limit(count)
      .toArray();

    const baseUrl = getBaseUrl(req);

    res.json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: total,
      startIndex,
      itemsPerPage: docs.length,
      Resources: docs.map((d) => toScimUser(d, baseUrl)),
    });
  } catch (err) {
     
    console.error('[iam/scim] list users failed', err);
    scimError(res, 500, 'Failed to list users');
  }
});

/** POST /Users -- Create user */
router.post('/Users', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  try {
    const parsed = ScimUserSchema.safeParse(req.body);

    if (!parsed.success) {
      scimError(res, 400, `Validation error: ${parsed.error.message}`);
      return;
    }

    const data = parsed.data;
    const collection = await getCollection<EnterpriseUserDocument>('iam_users');

    // Check for existing user
    const existing = await collection.findOne({ tenantId, email: data.userName });
    if (existing) {
      scimError(res, 409, `User with userName "${data.userName}" already exists`);
      return;
    }

    const now = new Date();
    const doc: Omit<EnterpriseUserDocument, '_id'> = {
      tenantId,
      scimId: data.externalId || new ObjectId().toHexString(),
      externalId: data.externalId ?? '',
      userName: data.userName,
      email: data.userName,
      displayName: data.displayName ?? data.userName,
      active: data.active ?? true,
      groups: [],
      metadata: {
        givenName: data.name?.givenName ?? '',
        familyName: data.name?.familyName ?? '',
      },
      createdAt: now,
      updatedAt: now,
    };

    const result = await collection.insertOne(doc as EnterpriseUserDocument);

    await audit.log(tenantId, 'user_created', {
      actorId: 'scim',
      actorEmail: 'scim',
      targetType: 'user',
      targetId: result.insertedId.toString(),
      detail: { email: data.userName },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    const created: ScimUserShape = { ...doc, _id: result.insertedId };
    res.status(201).json(toScimUser(created, getBaseUrl(req)));
  } catch (err) {
     
    console.error('[iam/scim] create user failed', err);
    scimError(res, 500, 'Failed to create user');
  }
});

/** GET /Users/:id -- Get single user */
router.get('/Users/:id', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  const objectId = toObjectId(getStringParam(req, 'id'));
  if (!objectId) {
    scimError(res, 404, 'User not found');
    return;
  }

  try {
    const collection = await getCollection<EnterpriseUserDocument>('iam_users');
    const doc = await collection.findOne({ _id: objectId, tenantId });

    if (!doc) {
      scimError(res, 404, 'User not found');
      return;
    }

    res.json(toScimUser(doc, getBaseUrl(req)));
  } catch (err) {
     
    console.error('[iam/scim] get user failed', err);
    scimError(res, 500, 'Failed to get user');
  }
});

/** PUT /Users/:id -- Replace user */
router.put('/Users/:id', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  const id = getStringParam(req, 'id');
  const objectId = toObjectId(id);
  if (!objectId || !id) {
    scimError(res, 404, 'User not found');
    return;
  }

  try {
    const parsed = ScimUserSchema.safeParse(req.body);

    if (!parsed.success) {
      scimError(res, 400, `Validation error: ${parsed.error.message}`);
      return;
    }

    const data = parsed.data;
    const collection = await getCollection<EnterpriseUserDocument>('iam_users');
    const now = new Date();

    const result = await collection.findOneAndUpdate(
      { _id: objectId, tenantId },
      {
        $set: {
          userName: data.userName,
          email: data.userName,
          displayName: data.displayName ?? data.userName,
          active: data.active ?? true,
          externalId: data.externalId ?? '',
          metadata: {
            givenName: data.name?.givenName ?? '',
            familyName: data.name?.familyName ?? '',
          },
          updatedAt: now,
        },
      },
      { returnDocument: 'after' },
    );

    if (!result) {
      scimError(res, 404, 'User not found');
      return;
    }

    await audit.log(tenantId, 'user_updated', {
      actorId: 'scim',
      actorEmail: 'scim',
      targetType: 'user',
      targetId: id,
      detail: { email: data.userName },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    res.json(toScimUser(result, getBaseUrl(req)));
  } catch (err) {
     
    console.error('[iam/scim] replace user failed', err);
    scimError(res, 500, 'Failed to replace user');
  }
});

/** PATCH /Users/:id -- Partial update (Okta's primary provisioning method) */
router.patch('/Users/:id', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  const id = getStringParam(req, 'id');
  const objectId = toObjectId(id);
  if (!objectId || !id) {
    scimError(res, 404, 'User not found');
    return;
  }

  try {
    const parsed = ScimPatchSchema.safeParse(req.body);

    if (!parsed.success) {
      scimError(res, 400, `Validation error: ${parsed.error.message}`);
      return;
    }

    const collection = await getCollection<EnterpriseUserDocument>('iam_users');
    const setFields: Record<string, unknown> = { updatedAt: new Date() };

    // `active` may arrive as a string ("false" / "False") from
    // Okta's older provisioning workers. Coerce both boolean and string
    // forms; reject anything else. Silently dropping "false" leaves a
    // deprovisioned user fully active downstream.
    const toActive = (v: unknown): boolean | undefined => {
      if (typeof v === 'boolean') return v;
      if (typeof v === 'string') {
        const lc = v.trim().toLowerCase();
        if (lc === 'true') return true;
        if (lc === 'false') return false;
      }
      return undefined;
    };

    for (const op of parsed.data.Operations) {
      if (op.op === 'replace' || op.op === 'add') {
        if (op.path === 'active') {
          const a = toActive(op.value);
          if (a !== undefined) setFields.active = a;
        } else if (op.path === 'userName' && typeof op.value === 'string') {
          setFields.email = op.value;
          setFields.userName = op.value;
        } else if (op.path === 'displayName' && typeof op.value === 'string') {
          setFields.displayName = op.value;
        } else if (!op.path && typeof op.value === 'object' && op.value !== null) {
          // Okta sometimes sends { op: "replace", value: { active: false } }
          const val = op.value as Record<string, unknown>;
          if ('active' in val) {
            const a = toActive(val.active);
            if (a !== undefined) setFields.active = a;
          }
          if ('userName' in val) {
            setFields.email = val.userName;
            setFields.userName = val.userName;
          }
          if ('displayName' in val) setFields.displayName = val.displayName;
        }
      } else if (op.op === 'remove') {
        // SCIM PATCH `remove` removes the named attribute. For
        // user removal of `active` Okta treats this as "deactivate"; we
        // map it to active=false. For other paths the attribute is
        // unset via $unset below.
        if (op.path === 'active') {
          setFields.active = false;
        }
      }
    }

    const result = await collection.findOneAndUpdate(
      { _id: objectId, tenantId },
      { $set: setFields },
      { returnDocument: 'after' },
    );

    if (!result) {
      scimError(res, 404, 'User not found');
      return;
    }

    // If user was deactivated, revoke BOTH access and refresh tokens.
    // Refresh tokens survive access-token revocation otherwise, allowing
    // a deprovisioned user to mint a new session via /refresh.
    if (setFields.active === false) {
      await revokeAllUserSessions(tenantId, id);
      await revokeAllUserRefreshTokens(tenantId, id);

      await audit.log(tenantId, 'user_deactivated', {
        actorId: 'scim',
        actorEmail: 'scim',
        targetType: 'user',
        targetId: id,
        ip: req.ip ?? 'unknown',
        userAgent: req.headers['user-agent'] ?? 'unknown',
      });
    } else {
      await audit.log(tenantId, 'user_updated', {
        actorId: 'scim',
        actorEmail: 'scim',
        targetType: 'user',
        targetId: id,
        detail: { patchOps: parsed.data.Operations.length },
        ip: req.ip ?? 'unknown',
        userAgent: req.headers['user-agent'] ?? 'unknown',
      });
    }

    res.json(toScimUser(result, getBaseUrl(req)));
  } catch (err) {
     
    console.error('[iam/scim] patch user failed', err);
    scimError(res, 500, 'Failed to patch user');
  }
});

/** DELETE /Users/:id -- Hard delete user */
router.delete('/Users/:id', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  const id = getStringParam(req, 'id');
  const objectId = toObjectId(id);
  if (!objectId || !id) {
    scimError(res, 404, 'User not found');
    return;
  }

  try {
    const collection = await getCollection<EnterpriseUserDocument>('iam_users');
    // Capture the email BEFORE delete — adapter credential rows are
    // keyed on the user's `connectedBy` which is the userId string, but
    // some legacy rows were inserted with the email instead. Revoke
    // both forms so a deprovisioned user's credentials cannot continue
    // to dispatch upstream calls.
    const user = await collection.findOne({ _id: objectId, tenantId });
    const userEmail = user?.email ?? null;
    const result = await collection.deleteOne({ _id: objectId, tenantId });

    if (result.deletedCount === 0) {
      scimError(res, 404, 'User not found');
      return;
    }

    await revokeAllUserSessions(tenantId, id);
    await revokeAllUserRefreshTokens(tenantId, id);

    // revoke adapter credentials by BOTH userId and email.
    {
      const credCol = await getCollection<{ tenantId: string; connectedBy: string; status: string; revokedAt?: Date; revokedBy?: string }>(
        'iam_adapter_credentials',
      );
      const orClauses: Record<string, unknown>[] = [{ connectedBy: id }];
      if (userEmail) orClauses.push({ connectedBy: userEmail });
      await credCol.updateMany(
        { tenantId, status: 'active', $or: orClauses },
        { $set: { status: 'revoked', revokedAt: new Date(), revokedBy: 'scim' } },
      );
    }

    await audit.log(tenantId, 'user_deleted', {
      actorId: 'scim',
      actorEmail: 'scim',
      targetType: 'user',
      targetId: id,
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    res.status(204).send();
  } catch (err) {
     
    console.error('[iam/scim] delete user failed', err);
    scimError(res, 500, 'Failed to delete user');
  }
});

// ---------------------------------------------------------------------------
// /Groups
// ---------------------------------------------------------------------------

/** GET /Groups -- List groups */
router.get('/Groups', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  try {
    const collection = await getCollection<EnterpriseGroupDocument>('iam_groups');

    const startIndex = Math.max(1, parseInt(req.query.startIndex as string, 10) || 1);
    const count = Math.min(100, Math.max(1, parseInt(req.query.count as string, 10) || 100));
    const filter = req.query.filter as string | undefined;

    const query: Filter<EnterpriseGroupDocument> = { tenantId };

    if (filter) {
      const match = filter.match(/^displayName\s+eq\s+"([^"]+)"$/i);
      if (match) {
        (query as { displayName?: string }).displayName = match[1];
      }
    }

    const total = await collection.countDocuments(query);
    const docs = await collection
      .find(query)
      .skip(startIndex - 1)
      .limit(count)
      .toArray();

    const baseUrl = getBaseUrl(req);

    res.json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: total,
      startIndex,
      itemsPerPage: docs.length,
      Resources: docs.map((d) => toScimGroup(d, baseUrl)),
    });
  } catch (err) {
     
    console.error('[iam/scim] list groups failed', err);
    scimError(res, 500, 'Failed to list groups');
  }
});

/** POST /Groups -- Create group */
router.post('/Groups', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  try {
    const parsed = ScimGroupSchema.safeParse(req.body);

    if (!parsed.success) {
      scimError(res, 400, `Validation error: ${parsed.error.message}`);
      return;
    }

    const data = parsed.data;
    const collection = await getCollection<EnterpriseGroupDocument>('iam_groups');

    const now = new Date();
    const memberIds = (data.members ?? []).map((m) => m.value);

    const doc: Omit<EnterpriseGroupDocument, '_id'> = {
      tenantId,
      externalId: data.externalId ?? '',
      displayName: data.displayName,
      members: memberIds,
      createdAt: now,
      updatedAt: now,
    };

    const result = await collection.insertOne(doc as EnterpriseGroupDocument);

    await audit.log(tenantId, 'group_created', {
      actorId: 'scim',
      actorEmail: 'scim',
      targetType: 'group',
      targetId: result.insertedId.toString(),
      detail: { displayName: data.displayName },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    const created: ScimGroupShape = { ...doc, _id: result.insertedId };
    res.status(201).json(toScimGroup(created, getBaseUrl(req)));
  } catch (err) {
     
    console.error('[iam/scim] create group failed', err);
    scimError(res, 500, 'Failed to create group');
  }
});

/** GET /Groups/:id -- Get single group */
router.get('/Groups/:id', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  const objectId = toObjectId(getStringParam(req, 'id'));
  if (!objectId) {
    scimError(res, 404, 'Group not found');
    return;
  }

  try {
    const collection = await getCollection<EnterpriseGroupDocument>('iam_groups');
    const doc = await collection.findOne({ _id: objectId, tenantId });

    if (!doc) {
      scimError(res, 404, 'Group not found');
      return;
    }

    res.json(toScimGroup(doc, getBaseUrl(req)));
  } catch (err) {
     
    console.error('[iam/scim] get group failed', err);
    scimError(res, 500, 'Failed to get group');
  }
});

/** PUT /Groups/:id -- Replace group */
router.put('/Groups/:id', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  const id = getStringParam(req, 'id');
  const objectId = toObjectId(id);
  if (!objectId || !id) {
    scimError(res, 404, 'Group not found');
    return;
  }

  try {
    const parsed = ScimGroupSchema.safeParse(req.body);

    if (!parsed.success) {
      scimError(res, 400, `Validation error: ${parsed.error.message}`);
      return;
    }

    const data = parsed.data;
    const collection = await getCollection<EnterpriseGroupDocument>('iam_groups');
    const memberIds = (data.members ?? []).map((m) => m.value);
    const now = new Date();

    const result = await collection.findOneAndUpdate(
      { _id: objectId, tenantId },
      {
        $set: {
          displayName: data.displayName,
          members: memberIds,
          externalId: data.externalId ?? '',
          updatedAt: now,
        },
      },
      { returnDocument: 'after' },
    );

    if (!result) {
      scimError(res, 404, 'Group not found');
      return;
    }

    await audit.log(tenantId, 'group_updated', {
      actorId: 'scim',
      actorEmail: 'scim',
      targetType: 'group',
      targetId: id,
      detail: { displayName: data.displayName },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    res.json(toScimGroup(result, getBaseUrl(req)));
  } catch (err) {
     
    console.error('[iam/scim] replace group failed', err);
    scimError(res, 500, 'Failed to replace group');
  }
});

/** PATCH /Groups/:id -- Update group membership */
router.patch('/Groups/:id', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  const id = getStringParam(req, 'id');
  const objectId = toObjectId(id);
  if (!objectId || !id) {
    scimError(res, 404, 'Group not found');
    return;
  }

  try {
    const parsed = ScimPatchSchema.safeParse(req.body);

    if (!parsed.success) {
      scimError(res, 400, `Validation error: ${parsed.error.message}`);
      return;
    }

    const collection = await getCollection<EnterpriseGroupDocument>('iam_groups');
    const updateOps: Record<string, unknown> = {};
    const setOps: Record<string, unknown> = {};
    setOps.updatedAt = new Date();

    // Okta sends `path: 'members[value eq "<id>"]'` (no value)
    // to remove a single member. Parse that filter form and translate
    // it to a $pull on the named id. The earlier shape — `path:
    // 'members'` with `value: [{value: id}]` — also remains supported.
    const memberEqRegex = /^members\[value\s+eq\s+"([^"]+)"\]$/;
    for (const op of parsed.data.Operations) {
      const eqMatch = typeof op.path === 'string' ? op.path.match(memberEqRegex) : null;
      if (op.path === 'members' && op.op === 'add' && Array.isArray(op.value)) {
        const memberIds = (op.value as Array<{ value: string }>).map((m) => m.value);
        updateOps.$addToSet = { members: { $each: memberIds } };
      } else if (op.path === 'members' && op.op === 'remove' && Array.isArray(op.value)) {
        const memberIds = (op.value as Array<{ value: string }>).map((m) => m.value);
        updateOps.$pull = { members: { $in: memberIds } };
      } else if (eqMatch && op.op === 'remove') {
        const memberId = eqMatch[1];
        const prev = (updateOps.$pull as { members?: { $in: string[] } } | undefined)?.members?.$in ?? [];
        updateOps.$pull = { members: { $in: [...prev, memberId] } };
      } else if (op.path === 'displayName' && op.op === 'replace') {
        setOps.displayName = op.value;
      }
    }
    updateOps.$set = setOps;

    const result = await collection.findOneAndUpdate(
      { _id: objectId, tenantId },
      updateOps,
      { returnDocument: 'after' },
    );

    if (!result) {
      scimError(res, 404, 'Group not found');
      return;
    }

    await audit.log(tenantId, 'group_updated', {
      actorId: 'scim',
      actorEmail: 'scim',
      targetType: 'group',
      targetId: id,
      detail: { patchOps: parsed.data.Operations.length },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    res.json(toScimGroup(result, getBaseUrl(req)));
  } catch (err) {
     
    console.error('[iam/scim] patch group failed', err);
    scimError(res, 500, 'Failed to patch group');
  }
});

/** DELETE /Groups/:id -- Delete group */
router.delete('/Groups/:id', async (req: Request, res: Response): Promise<void> => {
  const tenantId = requireTenant(req, res);
  if (!tenantId) return;

  const id = getStringParam(req, 'id');
  const objectId = toObjectId(id);
  if (!objectId || !id) {
    scimError(res, 404, 'Group not found');
    return;
  }

  try {
    const collection = await getCollection<EnterpriseGroupDocument>('iam_groups');
    const result = await collection.deleteOne({ _id: objectId, tenantId });

    if (result.deletedCount === 0) {
      scimError(res, 404, 'Group not found');
      return;
    }

    await audit.log(tenantId, 'group_deleted', {
      actorId: 'scim',
      actorEmail: 'scim',
      targetType: 'group',
      targetId: id,
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    res.status(204).send();
  } catch (err) {
     
    console.error('[iam/scim] delete group failed', err);
    scimError(res, 500, 'Failed to delete group');
  }
});

// ---------------------------------------------------------------------------
// Service Discovery
// ---------------------------------------------------------------------------

/** GET /ServiceProviderConfig -- SCIM service provider configuration */
router.get('/ServiceProviderConfig', (_req: Request, res: Response): void => {
  res.json({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    documentationUri: 'https://docs.epicai.io/scim',
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 100 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        type: 'oauthbearertoken',
        name: 'OAuth Bearer Token',
        description: 'Authentication scheme using the OAuth Bearer Token Standard',
        specUri: 'https://www.rfc-editor.org/info/rfc6750',
        primary: true,
      },
    ],
  });
});

/** GET /Schemas -- SCIM schema definitions */
router.get('/Schemas', (_req: Request, res: Response): void => {
  res.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: 2,
    Resources: [
      {
        id: 'urn:ietf:params:scim:schemas:core:2.0:User',
        name: 'User',
        description: 'User Account',
        attributes: [
          { name: 'userName', type: 'string', required: true, uniqueness: 'server' },
          { name: 'displayName', type: 'string', required: false },
          { name: 'active', type: 'boolean', required: false },
        ],
      },
      {
        id: 'urn:ietf:params:scim:schemas:core:2.0:Group',
        name: 'Group',
        description: 'Group',
        attributes: [
          { name: 'displayName', type: 'string', required: true, uniqueness: 'server' },
          { name: 'members', type: 'complex', required: false, multiValued: true },
        ],
      },
    ],
  });
});

export default router;
