/**
 * Session Routes
 *
 * Routes:
 *   GET  /session -- Return current user info from session
 *   POST /logout  -- Revoke session, clear cookie, audit log
 *
 * @module iam/routes/session
 */

import { Router } from 'express';
import type { Request, Response } from 'express';
import { ObjectId } from 'mongodb';
import { enterpriseAuthMiddleware, requireEnterpriseAuth } from '../middleware.js';
import {
  revokeSession,
  issueToken,
  issueRefreshToken,
  consumeRefreshToken,
  revokeRefreshToken,
  getUserRevocationVersion,
} from '../services/session.js';
import { getByTenantId } from '../services/tenant.js';
import { getCollection } from '../db.js';
import * as audit from '../services/audit.js';
import type { EnterpriseUserDocument } from '../types.js';

const router = Router();

/** GET /session -- Return the authenticated user's session information */
router.get('/session', enterpriseAuthMiddleware(), (req: Request, res: Response): void => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { user } = auth;

  res.json({
    userId: user.userId,
    email: user.email,
    tenantId: user.tenantId,
    displayName: user.displayName,
    groups: user.groups,
    allowedAdapterIds: user.allowedAdapterIds,
    iat: user.iat,
    exp: user.exp,
  });
});

/** POST /logout -- Revoke the current session and clear cookies */
router.post(
  '/logout',
  enterpriseAuthMiddleware(),
  async (req: Request, res: Response): Promise<void> => {
    const auth = requireEnterpriseAuth(req, res);
    if (!auth) return;
    const { user } = auth;

    try {
      const jti = user.jti;

      if (jti) {
        await revokeSession(jti);
      }

      // Revoke refresh token if present
      const cookies = req.cookies as Record<string, string | undefined> | undefined;
      const rawRefresh = cookies?.enterprise_refresh_token;
      if (rawRefresh) {
        await revokeRefreshToken(rawRefresh);
      }

      // Clear cookies and respond BEFORE audit so an audit failure cannot
      // block a successful revocation. Tokens are already gone in Redis.
      res.clearCookie('enterprise_token');
      res.clearCookie('enterprise_refresh_token');
      res.json({ success: true, message: 'Logged out' });

      // Fire-and-forget audit
      audit.log(user.tenantId, 'logout', {
        actorId: user.sub ?? user.userId,
        actorEmail: user.email,
        targetType: 'user',
        targetId: user.sub ?? user.userId,
        ip: req.ip ?? 'unknown',
        userAgent: req.headers['user-agent'] ?? 'unknown',
      }).catch((auditErr: unknown) => {
         
        console.error('[iam/session] logout audit log failed', auditErr);
      });
    } catch (err) {
       
      console.error('[iam/session] logout failed', err);
      res.status(500).json({ error: 'Failed to logout' });
    }
  },
);

/**
 * POST /refresh -- Exchange a refresh token for a new access token + rotated refresh token.
 *
 * No auth middleware — this is how a client re-authenticates when the access token expires.
 * The refresh token is single-use: the old one is deleted and a new one is issued.
 * The old access token (JTI) is revoked before the new one is issued.
 */
router.post('/refresh', async (req: Request, res: Response): Promise<void> => {
  const cookies = req.cookies as Record<string, string | undefined> | undefined;
  const rawRefresh = cookies?.enterprise_refresh_token;

  if (!rawRefresh) {
    res.status(401).json({ error: 'No refresh token' });
    return;
  }

  try {
    const consumed = await consumeRefreshToken(rawRefresh);

    if (!consumed) {
      res.clearCookie('enterprise_refresh_token');
      res.status(401).json({ error: 'Refresh token invalid or expired' });
      return;
    }

    const { payload, observedUserVer } = consumed;
    const { jti: oldJti, userId, tenantId } = payload;

    // Revoke the old access token
    await revokeSession(oldJti);

    // Reload user and tenant for fresh RBAC state
    const usersCol = await getCollection<EnterpriseUserDocument>('iam_users');
    let user: EnterpriseUserDocument | null = null;
    try {
      user = await usersCol.findOne({ tenantId, _id: new ObjectId(userId) });
    } catch {
      user = await usersCol.findOne({ tenantId, _id: userId as unknown as ObjectId });
    }

    if (!user || !user.active) {
      res.status(401).json({ error: 'User not found or inactive' });
      return;
    }

    const tenant = await getByTenantId(tenantId);
    if (!tenant || !tenant.active) {
      res.status(401).json({ error: 'Tenant not found or suspended' });
      return;
    }

    // Re-check tenant MFA policy at refresh time. If the tenant has enabled
    // MFA since this refresh token was minted, refuse to mint a verified
    // session — the user must complete primary auth + TOTP again.
    const tenantRequiresMfa = tenant.settings?.mfaRequired === true;
    const sessionWasVerified = payload.mfaVerified === true;

    if (tenantRequiresMfa && !sessionWasVerified) {
      res.clearCookie('enterprise_token');
      res.clearCookie('enterprise_refresh_token');
      res.status(401).json({
        error: 'MFA verification required',
        code: 'MFA_REQUIRED',
        detail: 'Tenant policy now requires MFA. Please log in again.',
      });
      return;
    }

    // Preserve the verified-state of the prior session so a refresh does not
    // downgrade MFA verification (and is not silently upgrading either).
    const newMfaVerified = sessionWasVerified || !tenantRequiresMfa;
    const newToken = await issueToken(user, tenant, { mfaVerified: newMfaVerified });
    const newJti = (JSON.parse(
      Buffer.from(newToken.split('.')[1], 'base64url').toString(),
    ) as { jti: string }).jti;

    const newRefreshToken = await issueRefreshToken(newJti, userId, tenantId, newMfaVerified);

    // TOCTOU close (race-free): re-read the monotonic revocation version
    // and compare against the version observed BY consume itself. Using
    // observedUserVer (returned from consumeRefreshToken) instead of a
    // separate post-consume snapshot eliminates the window where a revoke
    // could land between consume's check and a fresh snapshot read.
    // INCR is atomic, so finalUserVer > observedUserVer is true iff at
    // least one revoke landed after consume validated the token.
    const finalUserVer = await getUserRevocationVersion(tenantId, userId);
    if (finalUserVer > observedUserVer) {
      await revokeSession(newJti);
      await revokeRefreshToken(newRefreshToken);
      res.clearCookie('enterprise_token');
      res.clearCookie('enterprise_refresh_token');
      res.status(401).json({
        error: 'Session revoked',
        detail: 'Your session was revoked while this request was in flight. Please log in again.',
      });
      return;
    }

    // Set cookies and send response BEFORE audit — an audit storage failure
    // must not strand the user after their old token has already been consumed.
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);
    const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    res.cookie('enterprise_token', newToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      expires: expiresAt,
    });
    res.cookie('enterprise_refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      expires: refreshExpiresAt,
    });
    res.json({ ok: true });

    // Fire-and-forget audit after response is committed.
    audit.log(tenantId, 'token_refreshed', {
      actorId: userId,
      actorEmail: user.email,
      targetType: 'user',
      targetId: userId,
      detail: { previousJti: oldJti, newJti },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    }).catch((auditErr: unknown) => {
       
      console.error('[iam/session] refresh audit log failed', auditErr);
    });
  } catch (err) {
     
    console.error('[iam/session] refresh failed', err);
    res.status(401).json({ error: 'Token refresh failed' });
  }
});

export default router;
