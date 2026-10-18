/**
 * Adapter Connection Routes
 *
 * Manage per-user and shared (org-wide) adapter credential connections.
 * Collection: iam_adapter_credentials
 *
 * Routes:
 *   GET    /available                  -- Adapters available to user (filtered)
 *   GET    /connected                  -- User's connected adapters
 *   POST   /:id/connect               -- Connect adapter (encrypt API key)
 *   DELETE /:id/disconnect             -- Disconnect adapter
 *   POST   /admin/:id/connect-shared   -- Admin: connect shared credential
 *   DELETE /admin/:id/disconnect-shared -- Admin: disconnect shared credential
 *
 * @module iam/routes/adapters
 */

import { Router } from 'express';
import { z } from 'zod';
import type { Request, Response } from 'express';
import {
  enterpriseAuthMiddleware,
  enterpriseAdminGuard,
  adapterFilterMiddleware,
  requireEnterpriseAuth,
} from '../middleware.js';
import { getCollection } from '../db.js';
import { encryptFields } from '../crypto.js';
import * as audit from '../services/audit.js';
import type { AdapterCredentialDocument } from '../types.js';
import { createLogger } from '../../engine/logger.js';
import { CREDENTIAL_VALUE_CONTROL_CHAR_RE } from '../../cli/credentials.js';

// Production logging goes through the project logger (never console.*).
const moduleLog = createLogger('iam.adapters-routes');

const router = Router({ mergeParams: true });

// All adapter routes require authentication
router.use(enterpriseAuthMiddleware());

/**
 * Narrow a route parameter to a string. Express 5's `req.params` type is
 * `string | string[]` because some wildcard patterns can produce arrays;
 * for our single-segment `/:id/...` routes the value is always a string
 * at runtime, but TypeScript needs the explicit narrow. Returns `null`
 * when the parameter is missing or an array — callers must then reject
 * the request with 400.
 */
function getStringParam(req: Request, name: string): string | null {
  const value = req.params[name];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

// ---------------------------------------------------------------------------
// Request body schemas
// ---------------------------------------------------------------------------

/**
 * §10.5 (rulings item 106) — optional confidential-client fields for the
 * per-user OAuth vendor-token refresh call (src/iam/services/credentials.ts).
 * `clientId`/`clientSecret` are the TENANT's own vendor OAuth app
 * registration (distinct from `apiKey`/`apiSecret`, the per-user token
 * pair). Same `min(1).max(4096)` bound as `apiKey`/`apiSecret` above, PLUS
 * a control-char rejection using this codebase's established credential-
 * value pattern (`CREDENTIAL_VALUE_CONTROL_CHAR_RE`, `src/cli/credentials.ts`
 * — the same regex the local `.env` credential loader and the CLI env-file
 * writer already enforce): a client_id/secret carrying a CR/LF or other
 * control byte must never reach an HTTP Basic Authorization header
 * (`buildClientAuthHeader` in credentials.ts) unsanitized. NOTE: `apiKey`/
 * `apiSecret` immediately above do NOT currently have this same check —
 * verified against this file's source before writing this comment, not
 * assumed; flagged in the build report rather than silently left
 * inconsistent or silently "fixed" as an unauthorized scope expansion.
 */
const credentialFieldSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine((v) => !CREDENTIAL_VALUE_CONTROL_CHAR_RE.test(v), {
    message: 'must not contain control characters',
  });

const connectAdapterSchema = z.object({
  apiKey: z.string().min(1).max(4096),
  apiSecret: z.string().min(1).max(4096).optional(),
  credentialType: z
    .enum(['api_key', 'oauth2', 'basic_auth'])
    .optional()
    .default('api_key'),
});

/**
 * §10.5 (rulings item 106) scoped `POST /:id/connect` (per-user) ONLY —
 * deliberately NOT applied to `connectAdapterSchema` (shared by
 * `/admin/:id/connect-shared` below too), since the ruling's build scope
 * names `/:id/connect` specifically and a shared org-wide credential's
 * confidential-client story was not ruled on. Using a single extended
 * schema for both routes would have silently accepted-and-then-dropped
 * `clientId`/`clientSecret` on the shared-connect path (validated by zod,
 * then never read by that handler) — worse than not accepting them at
 * all. `.extend()` keeps `connectAdapterSchema`'s own fields/messages
 * byte-identical for every existing caller of either route.
 */
export const connectAdapterSchemaWithClientAuth = connectAdapterSchema
  .extend({
    clientId: credentialFieldSchema.optional(),
    clientSecret: credentialFieldSchema.optional(),
  })
  .refine((data) => (data.clientId === undefined) === (data.clientSecret === undefined), {
    message: 'clientId and clientSecret must both be provided or both omitted',
    path: ['clientId'],
  });

// ---------------------------------------------------------------------------
// User-facing routes
// ---------------------------------------------------------------------------

/**
 * GET /available -- List adapters available to the current user.
 * Uses adapterFilterMiddleware to enforce group-based access.
 */
router.get(
  '/available',
  adapterFilterMiddleware(),
  (req: Request, res: Response): void => {
    try {
      const allowedIds = req.allowedAdapterIds ?? [];

      // Return the list of allowed adapter IDs.
      // In a full implementation this would join against the adapter catalog.
      res.json({
        adapters: allowedIds.map((id) => ({ id, available: true })),
      });
    } catch (err) {
       
      moduleLog.error('[iam/adapters] /available failed', { error: err instanceof Error ? err.message : String(err) });
      res.status(500).json({ error: 'Failed to list available adapters' });
    }
  },
);

/** GET /connected -- List the current user's connected adapters with status */
router.get('/connected', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  try {
    const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');

    // Return credentials this user personally connected PLUS any org-wide
    // shared credentials for the tenant (shared=true). Never expose the
    // encrypted payload or IV.
    const credentials = await col
      .find(
        {
          tenantId,
          adapterId: { $exists: true },
          $or: [{ connectedBy: user.email }, { shared: true }],
        },
        { projection: { encrypted: 0, iv: 0 } },
      )
      .toArray();

    res.json({ adapters: credentials });
  } catch (err) {
     
    moduleLog.error('[iam/adapters] /connected failed', { error: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: 'Failed to list connected adapters' });
  }
});

/**
 * POST /:id/connect -- Connect an adapter for the current user.
 * Encrypts the provided API key / credentials before storing.
 */
router.post('/:id/connect', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const parsed = connectAdapterSchemaWithClientAuth.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Invalid request body',
      detail: parsed.error.issues.map((i) => i.message).join('; '),
    });
    return;
  }
  const { apiKey, apiSecret, credentialType, clientId, clientSecret } = parsed.data;
  const adapterId = getStringParam(req, 'id');
  if (!adapterId) {
    res.status(400).json({ error: 'Missing adapter id' });
    return;
  }

  try {
    // Encrypt using the crypto module. CH-10 (§12.2): bind the AAD to this
    // adapterId so the ciphertext cannot be relocated to a different
    // adapter's row within the same tenant and still decrypt.
    //
    // §10.5 (rulings item 106): clientSecret rides in the SAME fields
    // object as apiKey/apiSecret — encrypted into the SAME `encrypted`/
    // `iv` blob via this ONE encryptFields call — never a plaintext
    // document field (see AdapterCredentialDocument's `clientId` doc
    // comment, types.ts, for why this shape was chosen over a second
    // encrypted:iv field pair). `clientId` alone is plain (types.ts).
    const fields: Record<string, string | undefined> = { apiKey, apiSecret, clientSecret };
    const { encrypted, iv } = encryptFields(fields, tenantId, adapterId);

    const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');
    const now = new Date();

    const doc = {
      tenantId,
      adapterId,
      credentialType,
      encrypted,
      iv,
      connectedBy: user.email,
      userId: user.sub, // §10.5::3: per-user credential is owned by this user
      connectedAt: now,
      status: 'active' as const,
    };

    // Upsert: allow reconnecting an existing adapter. `clientSecret` (inside
    // `fields` above) is folded into `encrypted`/`iv`, which are ALWAYS
    // fully replaced by every connect call — a reconnect that omits
    // clientSecret correctly drops it, since the whole ciphertext blob is
    // rebuilt from just this call's fields, never merged with the old one.
    // `clientId` is a PLAIN top-level field, outside that blob, so it needs
    // its own explicit clear: a reconnect that provides apiKey but omits
    // clientId must $unset the prior clientId, or a stale client_id would
    // survive paired with a blob that no longer has a matching
    // clientSecret — an inconsistent, silently-broken confidential-client
    // credential. $set alone (conditionally spreading clientId in only
    // when present) does NOT clear it when absent, so this is $set+$unset.
    await col.updateOne(
      { tenantId, adapterId, connectedBy: user.email },
      clientId !== undefined
        ? { $set: { ...doc, clientId } }
        : { $set: doc, $unset: { clientId: '' } },
      { upsert: true },
    );

    await audit.log(tenantId, 'adapter_connected', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'credential',
      targetId: adapterId,
      // §10.5 (rulings item 106): the audit record carries only a
      // presence flag for confidential-client auth (hasClientAuth), never
      // clientId or clientSecret themselves — a hash-chained audit record
      // is durable and reviewable (src/iam/services/audit.ts), so a
      // secret written here would be a permanent plaintext leak distinct
      // from (and worse than) the vault's own encrypted-at-rest storage.
      detail: { credentialType, hasClientAuth: clientId !== undefined },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    // §10.5 (rulings item 106): the response never echoes clientSecret (or
    // apiKey/apiSecret, which this route already never echoed) — only the
    // fields it echoed before this unit.
    res.status(201).json({ success: true, adapterId, status: 'active' });
  } catch (err) {

    moduleLog.error('[iam/adapters] connect failed', { error: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: 'Failed to connect adapter' });
  }
});

/** DELETE /:id/disconnect -- Disconnect an adapter for the current user */
router.delete('/:id/disconnect', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const adapterId = getStringParam(req, 'id');
  if (!adapterId) {
    res.status(400).json({ error: 'Missing adapter id' });
    return;
  }

  try {
    const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');

    const result = await col.deleteOne({
      tenantId,
      adapterId,
      connectedBy: user.email,
    });

    if (result.deletedCount === 0) {
      res.status(404).json({ error: 'Adapter connection not found' });
      return;
    }

    await audit.log(tenantId, 'adapter_disconnected', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'credential',
      targetId: adapterId,
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    res.status(204).send();
  } catch (err) {
     
    moduleLog.error('[iam/adapters] disconnect failed', { error: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: 'Failed to disconnect adapter' });
  }
});

// ---------------------------------------------------------------------------
// Admin-only shared credential routes
// ---------------------------------------------------------------------------

/**
 * POST /admin/:id/connect-shared -- Admin connects an org-wide shared credential.
 */
router.post(
  '/admin/:id/connect-shared',
  enterpriseAdminGuard(),
  async (req: Request, res: Response): Promise<void> => {
    const auth = requireEnterpriseAuth(req, res);
    if (!auth) return;
    const { tenantId, user } = auth;

    const parsed = connectAdapterSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'Invalid request body',
        detail: parsed.error.issues.map((i) => i.message).join('; '),
      });
      return;
    }
    const { apiKey, apiSecret, credentialType } = parsed.data;
    const adapterId = getStringParam(req, 'id');
    if (!adapterId) {
      res.status(400).json({ error: 'Missing adapter id' });
      return;
    }

    try {
      // CH-10 (§12.2): bind the AAD to this adapterId — see the per-user
      // connect route above for the relocation-attack rationale.
      const fields: Record<string, string | undefined> = { apiKey, apiSecret };
      const { encrypted, iv } = encryptFields(fields, tenantId, adapterId);

      const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');
      const now = new Date();

      const doc = {
        tenantId,
        adapterId,
        credentialType,
        encrypted,
        iv,
        connectedBy: user.email,
        userId: null, // §10.5::3: org-wide shared credentials carry userId:null
        connectedAt: now,
        status: 'active' as const,
        shared: true, // marker for org-wide credentials
      };

      // Upsert shared credential (one per tenant per adapter)
      await col.updateOne(
        { tenantId, adapterId, shared: true },
        { $set: doc },
        { upsert: true },
      );

      await audit.log(tenantId, 'credential_connected', {
        actorId: user.sub,
        actorEmail: user.email,
        targetType: 'credential',
        targetId: adapterId,
        detail: { shared: true, credentialType },
        ip: req.ip ?? 'unknown',
        userAgent: req.headers['user-agent'] ?? 'unknown',
      });

      res.status(201).json({ success: true, adapterId, shared: true, status: 'active' });
    } catch (err) {
       
      moduleLog.error('[iam/adapters] connect-shared failed', { error: err instanceof Error ? err.message : String(err) });
      res.status(500).json({ error: 'Failed to connect shared adapter' });
    }
  },
);

/**
 * DELETE /admin/:id/disconnect-shared -- Admin disconnects an org-wide credential.
 */
router.delete(
  '/admin/:id/disconnect-shared',
  enterpriseAdminGuard(),
  async (req: Request, res: Response): Promise<void> => {
    const auth = requireEnterpriseAuth(req, res);
    if (!auth) return;
    const { tenantId, user } = auth;

    const adapterId = getStringParam(req, 'id');
    if (!adapterId) {
      res.status(400).json({ error: 'Missing adapter id' });
      return;
    }

    try {
      const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');

      const result = await col.deleteOne({ tenantId, adapterId, shared: true });

      if (result.deletedCount === 0) {
        res.status(404).json({ error: 'Shared adapter connection not found' });
        return;
      }

      await audit.log(tenantId, 'credential_revoked', {
        actorId: user.sub,
        actorEmail: user.email,
        targetType: 'credential',
        targetId: adapterId,
        detail: { shared: true },
        ip: req.ip ?? 'unknown',
        userAgent: req.headers['user-agent'] ?? 'unknown',
      });

      res.status(204).send();
    } catch (err) {
       
      moduleLog.error('[iam/adapters] disconnect-shared failed', { error: err instanceof Error ? err.message : String(err) });
      res.status(500).json({ error: 'Failed to disconnect shared adapter' });
    }
  },
);

export default router;
