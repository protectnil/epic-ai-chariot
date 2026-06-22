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

const router = Router();

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

const connectAdapterSchema = z.object({
  apiKey: z.string().min(1).max(4096),
  apiSecret: z.string().min(1).max(4096).optional(),
  credentialType: z
    .enum(['api_key', 'oauth2', 'basic_auth'])
    .optional()
    .default('api_key'),
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
       
      console.error('[iam/adapters] /available failed', err);
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
     
    console.error('[iam/adapters] /connected failed', err);
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
    // Encrypt using the crypto module
    const fields: Record<string, string | undefined> = { apiKey, apiSecret };
    const { encrypted, iv } = encryptFields(fields, tenantId);

    const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');
    const now = new Date();

    const doc = {
      tenantId,
      adapterId,
      credentialType,
      encrypted,
      iv,
      connectedBy: user.email,
      connectedAt: now,
      status: 'active' as const,
    };

    // Upsert: allow reconnecting an existing adapter
    await col.updateOne(
      { tenantId, adapterId, connectedBy: user.email },
      { $set: doc },
      { upsert: true },
    );

    await audit.log(tenantId, 'adapter_connected', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'credential',
      targetId: adapterId,
      detail: { credentialType },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    res.status(201).json({ success: true, adapterId, status: 'active' });
  } catch (err) {
     
    console.error('[iam/adapters] connect failed', err);
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
     
    console.error('[iam/adapters] disconnect failed', err);
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
      const fields: Record<string, string | undefined> = { apiKey, apiSecret };
      const { encrypted, iv } = encryptFields(fields, tenantId);

      const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');
      const now = new Date();

      const doc = {
        tenantId,
        adapterId,
        credentialType,
        encrypted,
        iv,
        connectedBy: user.email,
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
       
      console.error('[iam/adapters] connect-shared failed', err);
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
       
      console.error('[iam/adapters] disconnect-shared failed', err);
      res.status(500).json({ error: 'Failed to disconnect shared adapter' });
    }
  },
);

export default router;
