/**
 * Admin API Routes
 *
 * Protected by enterpriseAuthMiddleware() + enterpriseAdminGuard().
 * All actions are audit-logged.
 *
 * Routes:
 *   GET    /group-mappings       -- List all group-to-adapter mappings
 *   POST   /group-mappings       -- Create mapping (with conflict check)
 *   PUT    /group-mappings/:id   -- Update mapping
 *   DELETE /group-mappings/:id   -- Delete mapping
 *   GET    /users                -- List users with resolved adapter access
 *   GET    /users/:id            -- Get user detail
 *   POST   /users/:id/force-logout -- Invalidate all sessions for user
 *   GET    /groups               -- List groups with adapter mapping join
 *   GET    /audit-logs           -- Query audit log
 *   GET    /tenant               -- Get tenant settings
 *   PUT    /tenant               -- Update tenant settings
 *
 * @module iam/routes/admin
 */

import { Router } from 'express';
import { z } from 'zod';
import type { Request, Response } from 'express';
import {
  enterpriseAuthMiddleware,
  enterpriseAdminGuard,
  requireEnterpriseAuth,
  invalidateMfaRequiredCache,
} from '../middleware.js';
import { getStringParam, parseObjectId } from './helpers.js';
import { getCollection } from '../db.js';
import * as audit from '../services/audit.js';
import * as mappingService from '../services/mapping.js';
import { clientIp, userAgent } from '../utils/url.js';
import {
  revokeAllUserSessions,
  revokeAllTenantSessions,
  revokeAllUserRefreshTokens,
} from '../services/session.js';
import type {
  EnterpriseGroupDocument,
  EnterpriseUserDocument,
  GroupAdapterMappingDocument,
  TenantDocument,
} from '../types.js';

const router = Router();

// All admin routes require authentication + admin role
router.use(enterpriseAuthMiddleware());
router.use(enterpriseAdminGuard());

// ---------------------------------------------------------------------------
// Request body schemas
// ---------------------------------------------------------------------------

const createMappingBodySchema = z.object({
  groupId: z.string().min(1).max(256),
  adapterIds: z.array(z.string().min(1).max(128)).min(1).max(500),
  allowedOperations: z.array(z.string().min(1).max(64)).max(100).optional(),
  maxQueriesPerHour: z.number().int().min(0).max(1_000_000).optional(),
});

const updateMappingBodySchema = z.object({
  adapterIds: z.array(z.string().min(1).max(128)).min(1).max(500),
  allowedOperations: z.array(z.string().min(1).max(64)).max(100).optional(),
  maxQueriesPerHour: z.number().int().min(0).max(1_000_000).optional(),
});

const allowedTenantSettingsSchema = z
  .object({
    sessionTimeoutMinutes: z.number().int().min(1).max(1440).optional(),
    maxConcurrentSessions: z.number().int().min(0).max(100).optional(),
    mfaRequired: z.boolean().optional(),
    ipAllowList: z.array(z.string().min(1).max(64)).max(100).optional(),
    allowedAdapterIds: z.array(z.string().min(1).max(128)).max(5000).optional(),
    scimEnabled: z.boolean().optional(),
    adminGroupName: z.string().min(1).max(128).optional(),
    // Per-tenant Resource AS audience identifier. Validated by the
    // ID-JAG issuer against bare-audience `resource` claims. Must be a
    // URI (RFC 3986) — accepts http(s) URLs, urn: identifiers, and the
    // api:// form Azure AD / Entra ID uses for app-ID URIs. Rejects
    // empty string + values with embedded userinfo (security: embedded
    // credentials would persist in tenant.settings.audience and leak
    // via admin GET reads).
    audience: z
      .string()
      .min(1)
      .max(2048)
      .refine(
        (s): boolean => {
          try {
            const u = new URL(s);
            return u.username === '' && u.password === '';
          } catch {
            // Allow urn: and other non-URL URI schemes that the WHATWG
            // URL parser may not accept. Surface-level regex sanity:
            // must look like <scheme>:<rest> per RFC 3986.
            return /^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]+$/.test(s);
          }
        },
        { message: 'must be a URI; embedded userinfo (user:pass@) not allowed' },
      )
      .optional(),
    // Opt-in for IdPs that do not federate group membership.
    // See TenantSettings.idJagPreserveGroupsWhenAbsent.
    idJagPreserveGroupsWhenAbsent: z.boolean().optional(),
  })
  .strict();

const updateTenantBodySchema = z
  .object({
    name: z.string().min(1).max(256).optional(),
    settings: allowedTenantSettingsSchema.optional(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Group-Adapter Mappings
// ---------------------------------------------------------------------------

/** GET /group-mappings -- List all mappings for the tenant */
router.get('/group-mappings', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  try {
    // Use the mapping service so legacy singular `adapterId` documents are
    // transparently normalized to the canonical plural `adapterIds` shape
    // before the response is serialized.
    const mappings = await mappingService.list(tenantId);
    res.json({ mappings });
  } catch (err) {
     
    console.error('[iam/admin] list group-mappings failed', err);
    res.status(500).json({ error: 'Failed to list group mappings' });
  }
});

/** POST /group-mappings -- Create a new mapping (conflict check on groupId) */
router.post('/group-mappings', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const parsed = createMappingBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Invalid request body',
      detail: parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '),
    });
    return;
  }
  const { groupId, adapterIds, allowedOperations, maxQueriesPerHour } = parsed.data;

  try {
    // Conflict check (one mapping per group per tenant) goes through the
    // service so a legacy singular-`adapterId` document is found as well.
    const existing = await mappingService.getByGroupId(tenantId, groupId);
    if (existing) {
      res.status(409).json({
        error: 'Mapping already exists for this group',
        existingId: existing._id,
      });
      return;
    }

    const col = await getCollection<GroupAdapterMappingDocument>('iam_group_adapter_mappings');
    const now = new Date();
    const doc = {
      tenantId,
      groupId,
      adapterIds,
      allowedOperations: allowedOperations ?? [],
      maxQueriesPerHour: maxQueriesPerHour ?? 1000,
      createdAt: now,
      updatedAt: now,
    } satisfies Omit<GroupAdapterMappingDocument, '_id'>;

    const result = await col.insertOne(doc as GroupAdapterMappingDocument);

    await audit.log(tenantId, 'mapping_created', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'mapping',
      targetId: result.insertedId.toString(),
      detail: { groupId, adapterIds },
      ip: clientIp(req),
      userAgent: userAgent(req),
    });

    res.status(201).json({ ...doc, _id: result.insertedId });
  } catch (err) {
     
    console.error('[iam/admin] create group-mapping failed', err);
    res.status(500).json({ error: 'Failed to create group mapping' });
  }
});

/** PUT /group-mappings/:id -- Update an existing mapping */
router.put('/group-mappings/:id', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const id = getStringParam(req, 'id');
  const objectId = parseObjectId(id);
  if (!objectId) {
    res.status(404).json({ error: 'Mapping not found' });
    return;
  }

  const parsed = updateMappingBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Invalid request body',
      detail: parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '),
    });
    return;
  }
  const { adapterIds, allowedOperations, maxQueriesPerHour } = parsed.data;

  try {
    // Delegate to the mapping service so the legacy `adapterId` field is
    // stripped ($unset) and the returned document is normalized through
    // `normalizeMapping()`. Both are necessary to prevent mixed-shape docs
    // from leaking into the API response.
    const result = await mappingService.updateById(tenantId, objectId, {
      adapterIds,
      allowedOperations,
      maxQueriesPerHour,
    });

    if (!result) {
      res.status(404).json({ error: 'Mapping not found' });
      return;
    }

    await audit.log(tenantId, 'mapping_updated', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'mapping',
      targetId: id ?? '',
      detail: { adapterIds },
      ip: clientIp(req),
      userAgent: userAgent(req),
    });

    res.json(result);
  } catch (err) {
     
    console.error('[iam/admin] update group-mapping failed', err);
    res.status(500).json({ error: 'Failed to update group mapping' });
  }
});

/** DELETE /group-mappings/:id -- Delete a mapping */
router.delete('/group-mappings/:id', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const id = getStringParam(req, 'id');
  const objectId = parseObjectId(id);
  if (!objectId) {
    res.status(404).json({ error: 'Mapping not found' });
    return;
  }

  try {
    const col = await getCollection<GroupAdapterMappingDocument>('iam_group_adapter_mappings');
    const result = await col.deleteOne({ _id: objectId, tenantId });

    if (result.deletedCount === 0) {
      res.status(404).json({ error: 'Mapping not found' });
      return;
    }

    await audit.log(tenantId, 'mapping_deleted', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'mapping',
      targetId: id ?? '',
      ip: clientIp(req),
      userAgent: userAgent(req),
    });

    res.status(204).send();
  } catch (err) {
     
    console.error('[iam/admin] delete group-mapping failed', err);
    res.status(500).json({ error: 'Failed to delete group mapping' });
  }
});

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/** GET /users -- List users for the tenant */
router.get('/users', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  try {
    const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string, 10) || 50));
    const skip = (page - 1) * limit;

    const query: Record<string, unknown> = { tenantId };

    // Optional active filter
    if (req.query.active !== undefined) {
      query.active = req.query.active === 'true';
    }

    const collection = await getCollection<EnterpriseUserDocument>('iam_users');
    const [users, total] = await Promise.all([
      collection.find(query).skip(skip).limit(limit).toArray(),
      collection.countDocuments(query),
    ]);

    res.json({ users, total, page, limit });
  } catch (err) {
     
    console.error('[iam/admin] list users failed', err);
    res.status(500).json({ error: 'Failed to list users' });
  }
});

/** GET /users/:id -- Get user detail */
router.get('/users/:id', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  const id = getStringParam(req, 'id');
  const objectId = parseObjectId(id);
  if (!objectId) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  try {
    const collection = await getCollection<EnterpriseUserDocument>('iam_users');
    const user = await collection.findOne({ _id: objectId, tenantId });

    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.json({ user });
  } catch (err) {
     
    console.error('[iam/admin] get user failed', err);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

/** POST /users/:id/force-logout -- Invalidate all sessions for a user */
router.post('/users/:id/force-logout', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const id = getStringParam(req, 'id');
  if (!id) {
    res.status(400).json({ error: 'Missing user id' });
    return;
  }

  try {
    // Revoke BOTH access tokens (per-user JTIs) AND refresh tokens. Without
    // both, a user with a valid refresh cookie could simply hit /refresh and
    // mint a new session immediately after force-logout — defeating the point.
    await revokeAllUserSessions(tenantId, id);
    await revokeAllUserRefreshTokens(tenantId, id);

    await audit.log(tenantId, 'session_force_revoked', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'user',
      targetId: id,
      ip: clientIp(req),
      userAgent: userAgent(req),
    });

    res.json({ success: true, message: 'All sessions revoked' });
  } catch (err) {
     
    console.error('[iam/admin] force-logout failed', err);
    res.status(500).json({ error: 'Failed to force logout user' });
  }
});

// ---------------------------------------------------------------------------
// Groups (with adapter mapping join)
// ---------------------------------------------------------------------------

/** GET /groups -- List groups with their adapter mappings */
router.get('/groups', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  try {
    // Node-side join. Mapping docs store `groupId: string` while groups
    // use `_id: ObjectId` — a `$expr: $eq` aggregation between the two is
    // strict on type and never matches. Routing through `mappingService.list`
    // also normalizes any legacy singular-`adapterId` documents.
    const groupsCol = await getCollection<EnterpriseGroupDocument>('iam_groups');
    const [groups, mappings] = await Promise.all([
      groupsCol.find({ tenantId }).toArray(),
      mappingService.list(tenantId),
    ]);

    const byGroupId = new Map(mappings.map((m) => [m.groupId, m]));
    const joined = groups.map((group) => ({
      ...group,
      adapterMapping:
        byGroupId.get(group._id.toString())
          ?? byGroupId.get(group.externalId)
          ?? null,
    }));

    res.json({ groups: joined });
  } catch (err) {
     
    console.error('[iam/admin] list groups failed', err);
    res.status(500).json({ error: 'Failed to list groups' });
  }
});

// ---------------------------------------------------------------------------
// Audit Logs
// ---------------------------------------------------------------------------

/** GET /audit-logs -- Query audit events with filters */
router.get('/audit-logs', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  try {
 // validate every operator-supplied filter with Zod so
    // Mongo never sees an object-shaped query parameter. Untrusted
    // values flow into `collection.find(query)` below and would
    // otherwise allow NoSQL-injection via `?eventType[$ne]=` style
    // payloads.
    const auditQuerySchema = z.object({
      page: z.coerce.number().int().min(1).max(10_000).default(1),
      limit: z.coerce.number().int().min(1).max(200).default(50),
      eventType: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._-]+$/).optional(),
      actorEmail: z.string().email().max(254).optional(),
      since: z.coerce.date().optional(),
      until: z.coerce.date().optional(),
    });
    const parsed = auditQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid audit query', issues: parsed.error.issues });
      return;
    }
    const { page, limit, eventType, actorEmail, since, until } = parsed.data;
    const skip = (page - 1) * limit;

    const query: Record<string, unknown> = { tenantId };
    if (eventType) query.eventType = eventType;
    if (actorEmail) query.actorEmail = actorEmail;
    if (since || until) {
      const dateFilter: Record<string, Date> = {};
      if (since) dateFilter.$gte = since;
      if (until) dateFilter.$lte = until;
      query.timestamp = dateFilter;
    }

    const collection = await getCollection('iam_audit_events');
    const [events, total] = await Promise.all([
      collection.find(query).sort({ timestamp: -1 }).skip(skip).limit(limit).toArray(),
      collection.countDocuments(query),
    ]);

    res.json({ events, total, page, limit });
  } catch (err) {
     
    console.error('[iam/admin] query audit-logs failed', err);
    res.status(500).json({ error: 'Failed to query audit logs' });
  }
});

// ---------------------------------------------------------------------------
// Tenant Settings
// ---------------------------------------------------------------------------

/** GET /tenant -- Get tenant configuration */
router.get('/tenant', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  try {
    const col = await getCollection<TenantDocument>('iam_tenants');

    const tenant = await col.findOne({ tenantId });

    if (!tenant) {
      res.status(404).json({ error: 'Tenant not found' });
      return;
    }

    // Strip sensitive fields before returning
    const { scimBearerTokenHash: _stripped, ...safeFields } = tenant;
    void _stripped;
    res.json({ tenant: safeFields });
  } catch (err) {
     
    console.error('[iam/admin] get tenant failed', err);
    res.status(500).json({ error: 'Failed to get tenant settings' });
  }
});

/** PUT /tenant -- Update tenant settings */
router.put('/tenant', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const parsed = updateTenantBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Invalid request body',
      detail: parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '),
    });
    return;
  }
  const { name: displayName, settings } = parsed.data;

  try {
    const col = await getCollection<TenantDocument>('iam_tenants');

    // Read current state BEFORE mutation so we can detect mfaRequired toggle.
    const priorTenant = await col.findOne({ tenantId });
    if (!priorTenant) {
      res.status(404).json({ error: 'Tenant not found' });
      return;
    }
    const priorMfaRequired = priorTenant.settings?.mfaRequired === true;
    const incomingMfaRequired = settings?.mfaRequired;
    const willEnableMfa = !priorMfaRequired && incomingMfaRequired === true;

    const setFields: Record<string, unknown> = { updatedAt: new Date() };

    if (settings) {
      // Zod-validated — only the allowed keys are present. Flatten into
      // nested setters so partial updates only touch the provided fields.
      for (const [key, value] of Object.entries(settings)) {
        if (value !== undefined) {
          setFields[`settings.${key}`] = value;
        }
      }
    }

    if (displayName !== undefined) {
      setFields.name = displayName;
    }

    // FAIL-CLOSED on MFA enablement: revoke all tenant sessions BEFORE
    // persisting the policy change. If revocation fails (Redis down), we
    // refuse the toggle entirely so the tenant never lands in a state where
    // mfaRequired=true but old sessions are still live.
    if (willEnableMfa) {
      try {
        await revokeAllTenantSessions(tenantId);
      } catch (revokeErr) {
         
        console.error('[iam/admin] mfaRequired enable: session revocation failed; aborting toggle', revokeErr);
        res.status(503).json({
          error: 'Cannot enable MFA: session revocation failed',
          detail: 'Session store is unreachable. Please retry in a moment. The tenant policy was NOT changed.',
        });
        return;
      }
    }

    const result = await col.findOneAndUpdate(
      { tenantId },
      { $set: setFields },
      { returnDocument: 'after' },
    );

    if (!result) {
      res.status(404).json({ error: 'Tenant not found' });
      return;
    }

    // Bust the in-memory policy cache on any mfaRequired toggle so the next
    // request sees the current setting without waiting for TTL. (Revocation
    // already happened above for the false→true case.)
    const newMfaRequired = result.settings?.mfaRequired === true;
    if (priorMfaRequired !== newMfaRequired) {
      invalidateMfaRequiredCache(tenantId);
    }

    await audit.log(tenantId, 'settings_updated', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'tenant',
      targetId: tenantId,
      detail: { updatedFields: Object.keys(setFields) },
      ip: clientIp(req),
      userAgent: userAgent(req),
    });

    // Strip sensitive fields
    const { scimBearerTokenHash: _stripped, ...safeFields } = result;
    void _stripped;
    res.json({ tenant: safeFields });
  } catch (err) {
     
    console.error('[iam/admin] update tenant failed', err);
    res.status(500).json({ error: 'Failed to update tenant settings' });
  }
});

export default router;
