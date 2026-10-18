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
import * as tenantService from '../services/tenant.js';
import { clientIp, userAgent } from '../utils/url.js';
import {
  revokeAllUserSessions,
  revokeAllTenantSessions,
  revokeAllUserRefreshTokens,
} from '../services/session.js';
import { reconcileChainLength } from '../../engine/audit/length-attestation.js';
import { resolveEpicAiDir } from '../../engine/audit/serveAuditSink.js';
// CHARIOT::§9.8.1::3 — CH-03 multi-key verification set (old + new keys
// retained across rotation), replacing the single CHARIOT_AUDIT_VERIFY_KEY
// read that could not verify a record signed under a retired key.
import { resolveVerifyKeys } from '../../engine/audit/chainSigner.js';
import { chariotEmitter } from '../../observability/emitter.js';
import type { ChariotMetrics } from '../../observability/metrics.js';
import { createLogger } from '../../engine/logger.js';
import type {
  EnterpriseGroupDocument,
  EnterpriseUserDocument,
  GroupAdapterMappingDocument,
  TenantDocument,
} from '../types.js';

// Production logging goes through the project logger (never console.*).
const log = createLogger('iam-admin');

const router = Router({ mergeParams: true });

// All admin routes require authentication + admin role
router.use(enterpriseAuthMiddleware());
router.use(enterpriseAdminGuard());

// CHARIOT::§16.3 (CHARIOT-SPEC.md:1375, rulings item 91(3)) — "Surfaced via
// `GET /enterprise/{tenantId}/admin/metrics` (JSON) ...". The live
// ChariotMetrics instance is process-wide (one Chariot install, one
// ChariotState — see src/engine/server/ChariotState.ts:593's `chariotMetrics
// ?: ChariotMetrics` field), constructed once at boot in
// src/engine/bin/setup.ts and injected here via setChariotMetricsSource()
// right after createEnterpriseRoutes() is wired — this module is never
// imported before that point, so the setter always runs before any
// request can reach the /metrics route below.
let chariotMetricsSource: ChariotMetrics | undefined;
export function setChariotMetricsSource(metrics: ChariotMetrics | undefined): void {
  chariotMetricsSource = metrics;
}

// ---------------------------------------------------------------------------
// Request body schemas
// ---------------------------------------------------------------------------

// Principal-kind scope (gap #3 — Wiz 2 human/agent/service partition).
// Optional; omitted/empty = mapping applies to every principal kind
// (legacy behavior). `['human']` marks the grant human-only: agent and
// service sessions are stripped of these adapters by
// adapterFilterMiddleware via filterAdapterIdsForPrincipal.
const principalScopeSchema = z
  .array(z.enum(['human', 'agent', 'service']))
  .max(3)
  .optional();

const createMappingBodySchema = z.object({
  groupId: z.string().min(1).max(256),
  adapterIds: z.array(z.string().min(1).max(128)).min(1).max(500),
  allowedOperations: z.array(z.string().min(1).max(64)).max(100).optional(),
  maxQueriesPerHour: z.number().int().min(0).max(1_000_000).optional(),
  principalScope: principalScopeSchema,
});

const updateMappingBodySchema = z.object({
  adapterIds: z.array(z.string().min(1).max(128)).min(1).max(500),
  allowedOperations: z.array(z.string().min(1).max(64)).max(100).optional(),
  maxQueriesPerHour: z.number().int().min(0).max(1_000_000).optional(),
  principalScope: principalScopeSchema,
});

const allowedTenantSettingsSchema = z
  .object({
    sessionTimeoutMinutes: z.number().int().min(1).max(1440).optional(),
    maxConcurrentSessions: z.number().int().min(0).max(100).optional(),
    mfaRequired: z.boolean().optional(),
    ipAllowList: z.array(z.string().min(1).max(64)).max(100).optional(),
    allowedAdapterIds: z.array(z.string().min(1).max(128)).max(5000).optional(),
    scimEnabled: z.boolean().optional(),
    idleTimeoutMinutes: z.number().int().min(0).max(1440).optional(),
    jitProvisioningEnabled: z.boolean().optional(),
    logRetentionDays: z.number().int().min(1).max(3650).optional(),
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
     
    log.error('[iam/admin] list group-mappings failed', { error: err instanceof Error ? err.message : String(err) });
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
  const { groupId, adapterIds, allowedOperations, maxQueriesPerHour, principalScope } = parsed.data;

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
      ...(principalScope !== undefined ? { principalScope } : {}),
      createdAt: now,
      updatedAt: now,
    } satisfies Omit<GroupAdapterMappingDocument, '_id'>;

    const result = await col.insertOne(doc as GroupAdapterMappingDocument);

    await audit.log(tenantId, 'mapping_created', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'mapping',
      targetId: result.insertedId.toString(),
      detail: { groupId, adapterIds, ...(principalScope !== undefined ? { principalScope } : {}) },
      ip: clientIp(req),
      userAgent: userAgent(req),
    });

    res.status(201).json({ ...doc, _id: result.insertedId });
  } catch (err) {
     
    log.error('[iam/admin] create group-mapping failed', { error: err instanceof Error ? err.message : String(err) });
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
  const { adapterIds, allowedOperations, maxQueriesPerHour, principalScope } = parsed.data;

  try {
    // Delegate to the mapping service so the legacy `adapterId` field is
    // stripped ($unset) and the returned document is normalized through
    // `normalizeMapping()`. Both are necessary to prevent mixed-shape docs
    // from leaking into the API response.
    const result = await mappingService.updateById(tenantId, objectId, {
      adapterIds,
      allowedOperations,
      maxQueriesPerHour,
      principalScope,
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
      detail: { adapterIds, ...(principalScope !== undefined ? { principalScope } : {}) },
      ip: clientIp(req),
      userAgent: userAgent(req),
    });

    res.json(result);
  } catch (err) {
     
    log.error('[iam/admin] update group-mapping failed', { error: err instanceof Error ? err.message : String(err) });
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
     
    log.error('[iam/admin] delete group-mapping failed', { error: err instanceof Error ? err.message : String(err) });
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
     
    log.error('[iam/admin] list users failed', { error: err instanceof Error ? err.message : String(err) });
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
     
    log.error('[iam/admin] get user failed', { error: err instanceof Error ? err.message : String(err) });
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
     
    log.error('[iam/admin] force-logout failed', { error: err instanceof Error ? err.message : String(err) });
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
     
    log.error('[iam/admin] list groups failed', { error: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: 'Failed to list groups' });
  }
});

// ---------------------------------------------------------------------------
// Audit Logs
// ---------------------------------------------------------------------------

/**
 * GET /audit-logs -- Query audit events with filters (CHARIOT::§9.6::1)
 *
 * Accepts since/until/eventType/actor filters, streams the JSON response
 * body (events are written to `res` as the Mongo cursor yields them, never
 * materialized as a single in-memory array), and — before serving any
 * event — reconciles the tenant's full chain length against the highest
 * verified length attestation on record (CHARIOT::§9.8.3::4), halting the
 * export on detected tail truncation.
 */
router.get('/audit-logs', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  // CHARIOT::§16.1 Audit (CHARIOT-SPEC.md:1349, rulings item 91/105) — the
  // export genuinely begins here, before the §9.8.3::4 halt checks below
  // (which may still stop it — a halted export is NOT export_completed,
  // it is audit.attestation_unverifiable/audit.tail_truncation_detected,
  // both already emitted at their own halt point).
  chariotEmitter.send('audit.export_started', { data: { tenantId } });

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
      // CHARIOT::§9.6::1 — generic actor filter (maps to the actorId field
      // every audit record carries), distinct from the email-shaped
      // actorEmail filter already supported.
      actor: z.string().min(1).max(254).optional(),
      actorEmail: z.string().email().max(254).optional(),
      since: z.coerce.date().optional(),
      until: z.coerce.date().optional(),
    });
    const parsed = auditQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid audit query', issues: parsed.error.issues });
      return;
    }
    const { page, limit, eventType, actor, actorEmail, since, until } = parsed.data;
    const skip = (page - 1) * limit;

    const query: Record<string, unknown> = { tenantId };
    if (eventType) query.eventType = eventType;
    if (actor) query.actorId = actor;
    if (actorEmail) query.actorEmail = actorEmail;
    if (since || until) {
      const dateFilter: Record<string, Date> = {};
      if (since) dateFilter.$gte = since;
      if (until) dateFilter.$lte = until;
      query.timestamp = dateFilter;
    }

    const collection = await getCollection('iam_audit_events');

    // CHARIOT::§9.8.3::4 — reconcile the tenant's FULL, unfiltered chain
    // length (not the filtered page count below) against the highest
    // verified length attestation for this chain (chainId == tenantId, per
    // the existing iam_audit_counters `audit:{tenantId}` convention).
    const currentLength = await collection.countDocuments({ tenantId });
    // CHARIOT::§9.8.1::3 — CH-03 multi-key set: the persistent,
    // rotation-maintained verify-key store (verifyKeyStore.ts, review gate
    // finding F2) merged with CHARIOT_AUDIT_VERIFY_KEYS (old + new retained
    // keys) and the legacy single CHARIOT_AUDIT_VERIFY_KEY/
    // CHARIOT_AUDIT_SIGNING_KEY fallback, so a record signed under a
    // RETIRED (but still-retained) key verifies here exactly as it did
    // before rotation.
    const epicAiDir = resolveEpicAiDir();
    const verifyKeys = resolveVerifyKeys(epicAiDir);
    const reconciliation = await reconcileChainLength(epicAiDir, tenantId, currentLength, verifyKeys);
    if (reconciliation.unverifiable) {
      // CHARIOT::§9.8.3::4 fail-closed: attestations exist for this chain but none
      // can be verified (no verify key configured in CHARIOT_AUDIT_VERIFY_KEYS /
      // CHARIOT_AUDIT_VERIFY_KEY / CHARIOT_AUDIT_SIGNING_KEY, or every signature
      // fails against every retained key). The reconciliation the clause requires
      // cannot be performed, so the export is halted rather than served unverified.
      chariotEmitter.send('audit.attestation_unverifiable', {
        severity: 'critical',
        alertWorthy: true,
        data: { chainId: tenantId, currentLength: reconciliation.currentLength, verifyKeyConfigured: verifyKeys.size > 0 },
        message:
          `Audit chain length attestations exist for tenant ${tenantId} but none could be verified ` +
          `(verification key ${verifyKeys.size > 0 ? 'rejected every attestation' : 'not configured'}); export halted.`,
      });
      res.status(409).json({
        error: 'audit chain length attestations unverifiable — export halted',
        chainId: tenantId,
        currentLength: reconciliation.currentLength,
        verifyKeyConfigured: verifyKeys.size > 0,
      });
      return;
    }
    if (reconciliation.truncated) {
      chariotEmitter.send('audit.tail_truncation_detected', {
        severity: 'critical',
        alertWorthy: true,
        data: {
          chainId: tenantId,
          attestedLength: reconciliation.attestedLength,
          currentLength: reconciliation.currentLength,
        },
        message:
          `Audit chain tail truncation detected for tenant ${tenantId}: ` +
          `attested length ${reconciliation.attestedLength}, current length ${reconciliation.currentLength}.`,
      });
      res.status(409).json({
        error: 'audit chain tail truncation detected — export halted',
        chainId: tenantId,
        attestedLength: reconciliation.attestedLength,
        currentLength: reconciliation.currentLength,
      });
      return;
    }

    const total = await collection.countDocuments(query);

    // CHARIOT::§9.6::1 — stream the response body: iterate the Mongo cursor
    // and write each event as it arrives instead of collecting the full
    // matching page into one in-memory array first, so a large export
    // window does not buffer in memory.
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.write('{"events":[');
    let wroteFirst = false;
    let eventCount = 0;
    const cursor = collection.find(query).sort({ timestamp: -1 }).skip(skip).limit(limit);
    try {
      for await (const event of cursor) {
        if (wroteFirst) res.write(',');
        wroteFirst = true;
        eventCount++;
        res.write(JSON.stringify(event));
      }
    } finally {
      await cursor.close();
    }
    res.write(`],"total":${total},"page":${page},"limit":${limit}}`);
    res.end();
    // CHARIOT::§16.1 Audit (CHARIOT-SPEC.md:1349, rulings item 91/105) —
    // only reached on the genuine success path (every halt above returns
    // before this point).
    chariotEmitter.send('audit.export_completed', {
      data: { tenantId, total, page, limit, eventCount },
    });
  } catch (err) {

    log.error('[iam/admin] query audit-logs failed', { error: err instanceof Error ? err.message : String(err) });
    if (res.headersSent) {
      // Streaming had already started — the response body is now truncated
      // JSON; the only honest option left is to end the connection so the
      // client observes a broken/incomplete response rather than a
      // silently-valid-looking but wrong one.
      res.end();
    } else {
      res.status(500).json({ error: 'Failed to query audit logs' });
    }
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
     
    log.error('[iam/admin] get tenant failed', { error: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: 'Failed to get tenant settings' });
  }
});

/** PUT /tenant -- Update tenant settings */
// §10.8::3 — tenant suspension / resumption (wires services/tenant.suspend|activate).
router.post('/tenant/suspend', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;
  const t = await tenantService.suspend(tenantId);
  if (!t) { res.status(404).json({ error: 'Tenant not found' }); return; }
  await audit.log(tenantId, 'tenant_suspended', {
    actorId: user.sub, actorEmail: user.email, targetType: 'tenant', targetId: tenantId,
    ip: clientIp(req), userAgent: userAgent(req),
  });
  res.json({ success: true, active: false });
});

router.post('/tenant/activate', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;
  const t = await tenantService.activate(tenantId);
  if (!t) { res.status(404).json({ error: 'Tenant not found' }); return; }
  await audit.log(tenantId, 'tenant_activated', {
    actorId: user.sub, actorEmail: user.email, targetType: 'tenant', targetId: tenantId,
    ip: clientIp(req), userAgent: userAgent(req),
  });
  res.json({ success: true, active: true });
});

// §10.8::1 — tenant delete (completes CRUD). Audit is written BEFORE the delete
// so the record exists on the tenant's own chain while the tenant still exists.
router.delete('/tenant', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;
  const deleted = await tenantService.deleteTenant(tenantId);
  if (!deleted) { res.status(404).json({ error: 'Tenant not found' }); return; }
  // Audit AFTER a confirmed delete (no phantom event for a nonexistent tenant).
  // The audit chain lives in iam_audit_events, keyed by tenantId, and survives
  // removal of the iam_tenants row.
  await audit.log(tenantId, 'tenant_deleted', {
    actorId: user.sub, actorEmail: user.email, targetType: 'tenant', targetId: tenantId,
    ip: clientIp(req), userAgent: userAgent(req),
  });
  res.json({ success: true, deleted: true });
});

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
         
        log.error('[iam/admin] mfaRequired enable: session revocation failed; aborting toggle', { error: revokeErr instanceof Error ? revokeErr.message : String(revokeErr) });
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
     
    log.error('[iam/admin] update tenant failed', { error: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: 'Failed to update tenant settings' });
  }
});

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/**
 * GET /metrics -- CHARIOT::§16.3 (CHARIOT-SPEC.md:1375, rulings item
 * 91(3)) tenant-facing JSON metrics summary. RBAC-gated exactly like
 * /audit-logs above: router-level enterpriseAuthMiddleware() +
 * enterpriseAdminGuard() (both applied above before any route in this
 * file), plus the per-route requireEnterpriseAuth() call every other
 * route in this file uses to obtain the verified tenantId. This is
 * DISTINCT from the global, Prometheus-format `GET /metrics`
 * (src/observability/prometheusRoute.ts) — that one is unauthenticated-
 * by-tenant-session (bearer-token gated instead) and mounted only when
 * CHARIOT_PROMETHEUS_EXPORTER=1; this route is always mounted (same as
 * every other /enterprise/:tenantId/admin/* route) and always requires a
 * valid enterprise admin session.
 */
router.get('/metrics', (req: Request, res: Response): void => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;

  if (!chariotMetricsSource) {
    // Not an error the tenant caused — the process-wide ChariotMetrics
    // instance simply has not been wired yet (e.g. a synthetic
    // ChariotState in a test harness, or a boot ordering edge case).
    // 503, not 500 — this is a "try again shortly" condition, not a bug.
    res.status(503).json({ error: 'Metrics not available' });
    return;
  }

  res.json(chariotMetricsSource.getSummary());
});

export default router;
