/**
 * MFA Routes (TOTP)
 *
 * All routes require an `enterprise_mfa_pending` cookie issued by the
 * SAML or OIDC callback when the tenant has `mfaRequired: true`.
 *
 * Routes:
 *   GET  /mfa/setup          -- Generate TOTP secret and return otpauth:// URL
 *   POST /mfa/setup/verify   -- Verify enrollment code, save secret, complete login
 *   POST /mfa/verify         -- Verify TOTP code for already-enrolled user
 *
 * @module iam/routes/mfa
 */

import { Router } from 'express';
import type { Request, Response } from 'express';
import { ObjectId } from 'mongodb';
import {
  getMfaPendingPayload,
  setMfaPendingTotpSecret,
  clearMfaPendingToken,
  issueToken,
  issueRefreshToken,
} from '../services/session.js';
import {
  generateTotpSecret,
  verifyTotpCode,
  isMfaEnrolled,
  saveMfaSecret,
  getUserMfaSecret,
  decryptTotpSecret,
} from '../services/mfa.js';
import { getCollection } from '../db.js';
import { getByTenantId } from '../services/tenant.js';
import * as audit from '../services/audit.js';
import { isAuthRateLimited, recordAuthFailure, clearAuthFailures } from '../services/auth-rate-limit.js';
import { clientIp as extractClientIp, userAgent as extractUserAgent } from '../utils/url.js';
import type { EnterpriseUserDocument } from '../types.js';

const router = Router();

const COOKIE_PENDING = 'enterprise_mfa_pending';
const COOKIE_TOKEN = 'enterprise_token';
const COOKIE_REFRESH = 'enterprise_refresh_token';

// ── Helper: read and validate the MFA pending cookie ────────────────────────

async function resolvePending(
  req: Request,
  res: Response,
): Promise<{ pendingToken: string; payload: import('../services/session.js').MfaPendingPayload } | null> {
  const cookies = req.cookies as Record<string, string | undefined> | undefined;
  const pendingToken = cookies?.[COOKIE_PENDING];

  if (!pendingToken) {
    res.status(401).json({ error: 'MFA session not found. Complete primary authentication first.' });
    return null;
  }

  const payload = await getMfaPendingPayload(pendingToken);
  if (!payload) {
    res.clearCookie(COOKIE_PENDING);
    res.status(401).json({ error: 'MFA session expired or invalid. Please log in again.' });
    return null;
  }

  return { pendingToken, payload };
}

// ── Helper: complete login after MFA verification ───────────────────────────

async function completeMfaLogin(
  req: Request,
  res: Response,
  pendingToken: string,
  payload: import('../services/session.js').MfaPendingPayload,
): Promise<void> {
  const { tenantId, userId, email } = payload;

  const usersCol = await getCollection<EnterpriseUserDocument>('iam_users');
  let user: EnterpriseUserDocument | null = null;

  // userId may be a stringified ObjectId or a string email-based ID
  try {
    user = await usersCol.findOne({ tenantId, _id: new ObjectId(userId) });
  } catch {
    user = await usersCol.findOne({ tenantId, email });
  }

  if (!user) {
    res.status(500).json({ error: 'User not found after MFA verification.' });
    return;
  }

  const tenant = await getByTenantId(tenantId);
  if (!tenant) {
    res.status(500).json({ error: 'Tenant not found.' });
    return;
  }

  const token = await issueToken(user, tenant, { mfaVerified: true });
  const refreshToken = await issueRefreshToken(
    // Extract jti from the newly issued token (decode without verify — we just issued it)
    (JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()) as { jti: string }).jti,
    userId,
    tenantId,
    true, // session is MFA-verified
  );

  await clearMfaPendingToken(pendingToken);
  await clearAuthFailures(extractClientIp(req), tenantId);

  // Set cookies and send response BEFORE audit so an audit storage failure
  // cannot strand the user with consumed tokens and no session.
  const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);
  const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

  res.cookie(COOKIE_TOKEN, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    expires: expiresAt,
  });
  res.cookie(COOKIE_REFRESH, refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    expires: refreshExpiresAt,
  });
  res.clearCookie(COOKIE_PENDING);
  res.redirect('/');

  // Fire-and-forget audit — must not block or fail the auth response.
  audit.log(tenantId, 'login', {
    actorId: userId,
    actorEmail: email,
    targetType: 'user',
    targetId: userId,
    detail: { method: 'mfa-totp', mfaCompleted: true },
    ip: extractClientIp(req),
    userAgent: extractUserAgent(req),
  }).catch((err: unknown) => {
     
    console.error('[iam/mfa] audit log failed after successful MFA login', err);
  });
}

// ── GET /mfa/setup ───────────────────────────────────────────────────────────

/**
 * Return a TOTP secret and otpauth:// URL for QR enrollment.
 * Writes the temp secret into the pending Redis state for the verify step.
 */
router.get('/mfa/setup', async (req: Request, res: Response): Promise<void> => {
  const ctx = await resolvePending(req, res);
  if (!ctx) return;

  const { pendingToken, payload } = ctx;

  // If already enrolled, reject — use /mfa/verify instead
  if (await isMfaEnrolled(payload.tenantId, payload.userId)) {
    res.status(409).json({ error: 'MFA already enrolled. Use /auth/mfa/verify to complete login.' });
    return;
  }

  const { secret, otpauthUrl } = await generateTotpSecret(payload.email);
  await setMfaPendingTotpSecret(pendingToken, secret);

  res.json({ otpauthUrl, secret });
});

// ── POST /mfa/setup/verify ───────────────────────────────────────────────────

/**
 * Verify the TOTP code during enrollment.
 * On success: saves the secret, issues session + refresh token, clears pending.
 */
router.post('/mfa/setup/verify', async (req: Request, res: Response): Promise<void> => {
  const ctx = await resolvePending(req, res);
  if (!ctx) return;

  const { pendingToken, payload } = ctx;
  const body = req.body as Record<string, unknown> | undefined;
  const token = typeof body?.token === 'string' ? body.token.trim() : '';

  if (!token) {
    res.status(400).json({ error: 'token is required' });
    return;
  }

  const clientIp = extractClientIp(req);
  if (await isAuthRateLimited(clientIp, payload.tenantId)) {
    res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
    return;
  }

  // The temp secret was stored by GET /mfa/setup
  const updatedPayload = await getMfaPendingPayload(pendingToken);
  const tempSecret = updatedPayload?.tempTotpSecret;

  if (!tempSecret) {
    res.status(400).json({ error: 'No setup in progress. Call GET /auth/mfa/setup first.' });
    return;
  }

  const valid = await verifyTotpCode(tempSecret, token);

  if (!valid) {
    await recordAuthFailure(clientIp, payload.tenantId);
    res.status(401).json({ error: 'Invalid TOTP code.' });
    return;
  }

  await saveMfaSecret(payload.tenantId, payload.userId, tempSecret);
  await completeMfaLogin(req, res, pendingToken, payload);
});

// ── POST /mfa/verify ─────────────────────────────────────────────────────────

/**
 * Verify TOTP code for an already-enrolled user.
 * On success: issues session + refresh token, clears pending.
 */
router.post('/mfa/verify', async (req: Request, res: Response): Promise<void> => {
  const ctx = await resolvePending(req, res);
  if (!ctx) return;

  const { pendingToken, payload } = ctx;
  const body = req.body as Record<string, unknown> | undefined;
  const token = typeof body?.token === 'string' ? body.token.trim() : '';

  if (!token) {
    res.status(400).json({ error: 'token is required' });
    return;
  }

  const clientIp = extractClientIp(req);
  if (await isAuthRateLimited(clientIp, payload.tenantId)) {
    res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
    return;
  }

  const mfaDoc = await getUserMfaSecret(payload.tenantId, payload.userId);

  if (!mfaDoc) {
    // User needs to enroll first
    res.status(409).json({ error: 'MFA not enrolled. Call GET /auth/mfa/setup first.' });
    return;
  }

  let plaintextSecret: string;
  try {
    plaintextSecret = decryptTotpSecret(mfaDoc.encrypted, mfaDoc.iv, payload.tenantId);
  } catch {
     
    console.error('[iam/mfa] TOTP secret decryption failed', { tenantId: payload.tenantId, userId: payload.userId });
    res.status(500).json({ error: 'MFA secret unavailable.' });
    return;
  }

  const valid = await verifyTotpCode(plaintextSecret, token);

  if (!valid) {
    await recordAuthFailure(clientIp, payload.tenantId);
    res.status(401).json({ error: 'Invalid TOTP code.' });
    return;
  }

  await completeMfaLogin(req, res, pendingToken, payload);
});

export default router;
