/**
 * SAML 2.0 Authentication Routes
 *
 * SP-initiated and IdP-initiated SSO flows.
 *
 * Routes:
 *   GET  /saml/login    -- Redirect to IdP (SP-initiated)
 *   POST /saml/callback -- Consume assertion, JIT provision, issue session
 *
 * @module iam/routes/saml
 */

import { Router } from 'express';
import { SAML } from '@node-saml/node-saml';
import type { Request, Response } from 'express';
import { getByTenantId } from '../services/tenant.js';
import { getCollection } from '../db.js';
import { issueToken, issueRefreshToken, issueMfaPendingToken, setIdJagSubjectToken } from '../services/session.js';
import { isMfaEnrolled } from '../services/mfa.js';
import { samlAssertedMfa } from '../services/idp-mfa.js';
import * as audit from '../services/audit.js';
import { isAuthRateLimited, recordAuthFailure, clearAuthFailures } from '../services/auth-rate-limit.js';
import type { EnterpriseUserDocument } from '../types.js';

const router = Router();

/**
 * GET /saml/login
 *
 * SP-initiated SAML flow. Builds an AuthnRequest and redirects the user
 * to the tenant's configured IdP entry point.
 */
router.get('/saml/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const tenantId = req.tenantId || (req.query.tenant as string) || (req.headers['x-tenant-id'] as string);

    if (!tenantId) {
      res.status(400).json({ error: 'Tenant not resolved' });
      return;
    }

    const tenant = await getByTenantId(tenantId);

    const samlCfg = tenant?.sso?.saml || tenant?.settings?.saml;
    if (!samlCfg) {
      res.status(404).json({ error: 'SAML not configured for this tenant' });
      return;
    }

    const samlConfig = samlCfg;

    const saml = new SAML({
      entryPoint: samlConfig.entryPoint,
      issuer: samlConfig.issuer,
      idpCert: samlConfig.cert,
      callbackUrl: samlConfig.callbackUrl,
      wantAssertionsSigned: samlConfig.wantAssertionsSigned ?? true,
      wantAuthnResponseSigned: samlConfig.wantAuthnResponseSigned ?? true,
      signatureAlgorithm: samlConfig.signatureAlgorithm ?? 'sha256',
    });

    const loginUrl = await saml.getAuthorizeUrlAsync(
      '',
      req.headers.host ?? '',
      {},
    );

    res.redirect(loginUrl);
  } catch {
    res.status(500).json({ error: 'Failed to initiate SAML login' });
  }
});

/**
 * POST /saml/callback
 *
 * Consumes a SAML assertion from the IdP. Handles both SP-initiated
 * (response to our AuthnRequest) and IdP-initiated (unsolicited) flows.
 *
 * On success:
 *   1. Extracts NameID (email) and group attributes from the assertion
 *   2. JIT-provisions the user if they don't exist locally
 *   3. Issues an enterprise session cookie
 *   4. Logs an audit event
 *   5. Redirects to the application
 */
router.post('/saml/callback', async (req: Request, res: Response): Promise<void> => {
  try {
    const tenantId = req.tenantId || (req.query.tenant as string) || (req.headers['x-tenant-id'] as string);

    if (!tenantId) {
      res.status(400).json({ error: 'Tenant not resolved' });
      return;
    }

    // SOC 2: Rate-limit failed authentication attempts
    const clientIp = req.ip ?? 'unknown';
    if (await isAuthRateLimited(clientIp, tenantId)) {
      res.status(429).json({ error: 'Too many failed login attempts. Try again in 15 minutes.' });
      return;
    }

    const tenant = await getByTenantId(tenantId);

    const samlCfg = tenant?.sso?.saml || tenant?.settings?.saml;
    if (!samlCfg) {
      res.status(400).json({ error: 'SAML not configured for this tenant' });
      return;
    }

    const samlConfig = samlCfg;

    const saml = new SAML({
      entryPoint: samlConfig.entryPoint,
      issuer: samlConfig.issuer,
      idpCert: samlConfig.cert,
      callbackUrl: samlConfig.callbackUrl,
      wantAssertionsSigned: samlConfig.wantAssertionsSigned ?? true,
      wantAuthnResponseSigned: samlConfig.wantAuthnResponseSigned ?? true,
      signatureAlgorithm: samlConfig.signatureAlgorithm ?? 'sha256',
    });

    const { profile } = await saml.validatePostResponseAsync(req.body);

    if (!profile || !profile.nameID) {
      res.status(401).json({ error: 'Invalid SAML assertion: missing NameID' });
      return;
    }

    const email = profile.nameID;
    const attrs = profile as Record<string, unknown>;
    const displayName = (attrs.displayName as string) ?? email;
    const givenName = (attrs.givenName as string) ?? '';
    const familyName = (attrs.familyName as string) ?? '';

    // Extract groups from assertion attributes (configurable attribute name)
    const groupAttr = attrs.groups ?? attrs.memberOf ?? [];
    const groups: string[] = Array.isArray(groupAttr)
      ? (groupAttr as string[])
      : [groupAttr as string];

    // JIT provision: upsert user
    const usersCol = await getCollection<EnterpriseUserDocument>('iam_users');
    const now = new Date();

    const user = await usersCol.findOneAndUpdate(
      { tenantId, email },
      {
        $set: {
          displayName,
          groups,
          active: true,
          updatedAt: now,
        },
        $setOnInsert: {
          tenantId,
          externalId: email,
          userName: email,
          email,
          metadata: { givenName, familyName },
          createdAt: now,
        },
      },
      { upsert: true, returnDocument: 'after' },
    );

    // `upsert:true, returnDocument:'after'` guarantees a document at runtime,
    // but the driver's type is `T | null`. Guard explicitly.
    if (!user) {
       
      console.error(
        `[iam/saml] JIT provisioning returned null for tenant=${tenantId} email=${email}`,
      );
      res.status(500).json({ error: 'Failed to provision user' });
      return;
    }

    // SOC 2: Clear failure counter on successful primary auth
    await clearAuthFailures(clientIp, tenantId);

    // Delegate to the IdP. Inspect the SAML assertion's
    // AuthnContextClassRef before falling through to Chariot-side TOTP. If
    // the IdP already performed MFA, forcing a second factor here is double
    // MFA and a UX regression for Okta/Entra/Ping customers whose IdPs
    // already enforce step-up at sign-in time.
    const parsedAssertion = profile.getAssertion?.();
    const idpMfa = samlAssertedMfa(parsedAssertion);

    // MFA gate: if tenant requires TOTP AND the IdP did NOT already perform
    // MFA, redirect to the Chariot TOTP flow instead of issuing a full
    // session. When the IdP DID perform MFA, the session is verified.
    if (tenant.settings?.mfaRequired && !idpMfa.asserted) {
      const userId = user._id.toString();
      const enrolled = await isMfaEnrolled(tenantId, userId);
      const pendingToken = await issueMfaPendingToken({
        userId,
        tenantId,
        email,
        displayName: user.displayName,
      });

      res.cookie('enterprise_mfa_pending', pendingToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 600_000, // 10 minutes
      });

      res.redirect(enrolled ? '/auth/mfa/verify' : '/auth/mfa/setup');
      return;
    }

    // Issue session token. Stamp `mfaVerified: true` when either (a) the
    // tenant doesn't require MFA, or (b) the IdP asserted MFA on its side.
    const mfaVerified = !tenant.settings?.mfaRequired || idpMfa.asserted;
    const token = await issueToken(user, tenant, { mfaVerified });
    const jti = (JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString(),
    ) as { jti: string }).jti;
    const refreshToken = await issueRefreshToken(jti, user._id.toString(), tenantId, mfaVerified);

    // P6 — persist the inbound SAML 2.0 Assertion as subject_token for
    // the Chariot-as-Client ID-JAG fan-out path (draft-04 §4.3 / §4.5,
    // RFC 7522). The subject_token presented at the IdP's token-
    // exchange endpoint MUST be the SAML 2.0 ASSERTION (the inner
    // <saml:Assertion> element), NOT the outer <samlp:Response>
    // envelope, and base64url-encoded per RFC 7522 §2.1.
    // The issuer MUST be the IdP's entity ID (the <saml:Issuer> of the
    // assertion) so the MCP-dispatch layer can look up the
    // iam_id_jag_idp_clients registration for that IdP. samlConfig.issuer
    // is the Service Provider entity ID (Chariot's identifier in the
    // AuthnRequest); using it would key the registry on the SP, not
    // the IdP — every fan-out lookup would miss.
    let assertionXml: string | undefined;
    if (typeof parsedAssertion === 'string') {
      assertionXml = parsedAssertion;
    } else if (parsedAssertion && typeof (parsedAssertion as { toString?: () => string }).toString === 'function') {
      // Some node-saml versions expose the assertion as an XML
      // DOM node whose toString() yields the XML string.
      const s = (parsedAssertion as { toString: () => string }).toString();
      if (typeof s === 'string' && s.startsWith('<')) assertionXml = s;
    }
    const idpIssuerFromProfile = (profile as { issuer?: string } | undefined)?.issuer;
    let assertionExp = Math.floor(Date.now() / 1000) + 8 * 3600;
    const notOnOrAfter = (parsedAssertion as { Conditions?: { NotOnOrAfter?: string } } | undefined)
      ?.Conditions?.NotOnOrAfter;
    if (typeof notOnOrAfter === 'string') {
      const parsedExp = Date.parse(notOnOrAfter);
      if (Number.isFinite(parsedExp)) assertionExp = Math.floor(parsedExp / 1000);
    }
    if (
      typeof assertionXml === 'string'
      && assertionXml.length > 0
      && typeof idpIssuerFromProfile === 'string'
      && idpIssuerFromProfile.length > 0
    ) {
      try {
        await setIdJagSubjectToken(tenantId, jti, {
          token: Buffer.from(assertionXml, 'utf8').toString('base64url'),
          type: 'saml2',
          exp: assertionExp,
          issuer: idpIssuerFromProfile,
        });
      } catch (e) {
        console.warn('[iam/saml] setIdJagSubjectToken failed (non-fatal)', e);
      }
    }

    // Compute cookie expiry (8 hours access / 30 days refresh)
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);
    const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    // Audit log
    const relayStateValue = (req.body as Record<string, unknown> | undefined)?.RelayState;
    await audit.log(tenantId, 'login', {
      actorId: user._id.toString(),
      actorEmail: email,
      targetType: 'user',
      targetId: user._id.toString(),
      detail: {
        method: 'saml',
        idpInitiated: !relayStateValue,
        idpAssertedMfa: idpMfa.asserted,
        authnContextClassRefs: idpMfa.authnContextClassRefs,
        mfaRequired: Boolean(tenant.settings?.mfaRequired),
      },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    // Set session cookies and redirect
    res.cookie('enterprise_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      expires: expiresAt,
    });
    res.cookie('enterprise_refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      expires: refreshExpiresAt,
    });

    // SAML RelayState is attacker-controlled. Only allow relative paths
    // (starting with exactly one "/" followed by a non-slash character).
    // Anything else — absolute URLs, protocol-relative URLs, javascript:,
    // data:, empty string — falls back to the safe default "/".
    // This blocks the classic SAML open-redirect vector where an attacker
    // forges a SAML response with `RelayState=https://evil.example/`.
    const body = req.body as Record<string, unknown> | undefined;
    const rawRelayState = typeof body?.RelayState === 'string'
      ? body.RelayState
      : '';
    const redirectUrl = isSafeRelayState(rawRelayState) ? rawRelayState : '/';
    res.redirect(redirectUrl);
  } catch {
    // SOC 2: Record failed auth attempt
    const failIp = req.ip ?? 'unknown';
    const failTenant = req.tenantId || (req.query.tenant as string) || '';
    if (failTenant) {
      try {
        await recordAuthFailure(failIp, failTenant);
      } catch (rateLimitErr) {
        // Surface rate-limit bookkeeping failures distinctly so they don't
        // mask the underlying auth failure, but do not let them block the
        // 401 response to the client.
         
        console.error('[iam/saml] recordAuthFailure failed', rateLimitErr);
      }
    }
    // Do not leak the underlying SAML library error to the client.
    // The detailed error (signature validation failure, cert mismatch,
    // clock skew, etc.) is useful for operators but dangerous for callers.
    res.status(401).json({ error: 'SAML assertion validation failed' });
  }
});

/**
 * Validate that a SAML RelayState value is a safe redirect target.
 *
 * Accepts ONLY relative paths of the form `/something...` — exactly one
 * leading slash followed by a non-slash character. This deliberately
 * rejects:
 *   - Absolute URLs (`https://evil.example/...`)
 *   - Protocol-relative URLs (`//evil.example/...`)
 *   - `javascript:` / `data:` / `file:` / `vbscript:` pseudo-URLs
 *   - Empty strings (fall back to `/` via the caller)
 *   - Backslash-prefixed paths (`\evil.example` — Windows quirk)
 *   - Paths with embedded newlines (CRLF injection)
 *   - Any whitespace
 */
function isSafeRelayState(value: string): boolean {
  if (value.length === 0 || value.length > 2048) return false;
  // Reject protocol-relative, empty, or malformed paths. Must start with
  // exactly one "/" followed by a character that is NOT another slash or
  // backslash.
  if (!/^\/[^/\\]/.test(value)) return false;
  // Reject any control characters or whitespace (CRLF injection, tab, NUL).
   
  if (/[\s\u0000-\u001f\u007f]/.test(value)) return false;
  return true;
}

export default router;
