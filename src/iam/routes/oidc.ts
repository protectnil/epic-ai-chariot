/**
 * OIDC Authentication Routes
 *
 * Authorization Code flow with PKCE for any OIDC-compliant IdP.
 *
 * Routes:
 *   GET /oidc/authorize -- Generate PKCE challenge, set state cookie, redirect
 *   GET /oidc/callback  -- Exchange code, validate state, JIT provision, session
 *
 * @module iam/routes/oidc
 */

import { Router } from 'express';
import * as client from 'openid-client';
import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import { getByTenantId } from '../services/tenant.js';
import { getCollection } from '../db.js';
import { issueToken, issueRefreshToken, issueMfaPendingToken, setIdJagSubjectToken } from '../services/session.js';
import { isMfaEnrolled } from '../services/mfa.js';
import { oidcAssertedMfa } from '../services/idp-mfa.js';
import * as audit from '../services/audit.js';
import { isAuthRateLimited, recordAuthFailure, clearAuthFailures } from '../services/auth-rate-limit.js';
import { clientIp as clientIpHelper } from '../utils/url.js';
import { chariotEmitter } from '../../observability/emitter.js';
import { decryptFields, splitEncryptedIv, VaultUpgradePersistFailedError } from '../crypto.js';
import { COLLECTION as IAM_TENANTS_COLLECTION } from '../services/tenant.js';
import type { EnterpriseUserDocument, OidcConfig } from '../types.js';
import { createLogger } from '../../engine/logger.js';

// Production logging goes through the project logger (never console.*).
const moduleLog = createLogger('iam.oidc');

const router = Router({ mergeParams: true });

/**
 * §10.3::1 — the client secret is stored encrypted at rest as an AES-256-GCM
 * "encrypted:iv" blob bound to the tenant (see updateSso). Resolve the runtime
 * plaintext here by decrypting the blob when present; otherwise fall back to a
 * legacy plaintext `clientSecret` (documents seeded before at-rest encryption,
 * or builds without the native crypto binding) so OIDC stays operational.
 */
export async function resolveOidcClientSecret(
  oidcConfig: OidcConfig,
  tenantId: string,
  sourceField: 'sso.oidc' | 'settings.oidc',
): Promise<string> {
  if (oidcConfig.clientSecretEncrypted) {
    // splitEncryptedIv (crypto.ts) uses the LAST ':' as the separator, not
    // the first — `clientSecretEncrypted` is `${encrypted}:${iv}` and a
    // CH-10 v2-format `encrypted` value itself carries an internal "v2:"
    // colon, so `indexOf(':')`/`.split(':')` split at the WRONG colon and
    // silently produce a garbage iv for every v2 record. See crypto.ts.
    const parts = splitEncryptedIv(oidcConfig.clientSecretEncrypted);
    if (!parts) {
      throw new Error('OIDC clientSecretEncrypted is malformed');
    }
    // CH-10 (§12.2) AAD binding — must match the fixed record identifier
    // updateSso/encryptOidcSecretAtRest (tenant.ts) encrypted this under.
    const result = await decryptFields(parts.encrypted, parts.iv, tenantId, 'oidc-client-secret');
    // CH-10 upgrade-on-decrypt (§12.2, rulings item 59, "the caller MUST
    // persist {encrypted, iv} back to the SAME record, in the SAME
    // operation"). CAS on the legacy combined blob we just read: a
    // concurrent upgrader that already rewrote this field makes the CAS
    // match zero documents — an idempotent no-op, never a clobber. A
    // genuine write error is NOT swallowed — it fails this login attempt.
    if (result.upgraded) {
      try {
        const col = await getCollection(IAM_TENANTS_COLLECTION);
        const writeRes = await col.updateOne(
          { tenantId, [`${sourceField}.clientSecretEncrypted`]: oidcConfig.clientSecretEncrypted },
          { $set: { [`${sourceField}.clientSecretEncrypted`]: `${result.upgraded.encrypted}:${result.upgraded.iv}` } },
        );
        void writeRes;
      } catch (writeBackErr) {
        moduleLog.error('OIDC client-secret upgrade-on-decrypt write-back failed', {
          tenantId,
          error: writeBackErr instanceof Error ? writeBackErr.message : String(writeBackErr),
        });
        throw new VaultUpgradePersistFailedError('oidc', `${tenantId}:oidc-client-secret`, writeBackErr);
      }
    }
    return result.fields.value;
  }
  // §10.3::1 — new writes are encrypted at rest via updateSso. A config that
  // still carries only a legacy plaintext `clientSecret` — seeded before at-rest
  // encryption, or in a build WITHOUT the native crypto binding required to
  // decrypt `clientSecretEncrypted` — is tolerated on read so OIDC stays
  // operational. The write path (updateSso) always encrypts going forward.
  if (oidcConfig.clientSecret) {
    return oidcConfig.clientSecret;
  }
  throw new Error('OIDC clientSecret not configured');
}

/**
 * GET /oidc/authorize
 *
 * Initiates the OIDC Authorization Code + PKCE flow.
 * Generates code_verifier/code_challenge, sets an encrypted state cookie,
 * and redirects the user to the tenant's IdP authorization endpoint.
 */
router.get('/oidc/authorize', async (req: Request, res: Response): Promise<void> => {
  try {
    // §10.8::5 — tenant comes only from the URL (validated upstream by
    // requireUrlTenantIsolation); never from a query param or header.
    const tenantId = req.params.tenantId as string;

    if (!tenantId) {
      res.status(400).json({ error: 'Tenant not resolved' });
      return;
    }

    const tenant = await getByTenantId(tenantId);

    if (!tenant) {
      res.status(404).json({ error: 'Tenant not found' });
      return;
    }

    // OIDC config may be at tenant.sso.oidc or tenant.settings.oidc
    const oidcConfig = tenant.sso?.oidc || tenant.settings?.oidc;
    const oidcConfigField: 'sso.oidc' | 'settings.oidc' = tenant.sso?.oidc ? 'sso.oidc' : 'settings.oidc';

    if (!oidcConfig) {
      res.status(404).json({ error: 'OIDC not configured for this tenant' });
      return;
    }

    // Discover the OIDC provider configuration
    const config = await client.discovery(
      new URL(oidcConfig.issuer),
      oidcConfig.clientId,
      await resolveOidcClientSecret(oidcConfig, tenantId, oidcConfigField),
    );

    // Generate PKCE code verifier and challenge
    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);

    // Generate state for CSRF protection
    const state = crypto.randomBytes(32).toString('hex');

 // Generate cryptographically random nonce. The nonce is bound
    // to the issued ID token via the `nonce` claim and is the spec-mandated
    // defense against authorization-code replay: a captured code, replayed
    // within its TTL, will mint an ID token whose `nonce` claim mismatches
    // any subsequent `expectedNonce` we pass to authorizationCodeGrant.
    // openid-client's `randomNonce()` is the documented helper for this.
    const nonce = client.randomNonce();

    // Store verifier, state and nonce in a secure cookie for the callback.
    // Without binding the nonce to the same opaque cookie that holds the
    // PKCE verifier, an attacker who captured a code could replay against a
    // freshly-initiated /authorize round-trip whose cookie lacks a nonce
    // expectation, defeating the protection.
    const oauthState = JSON.stringify({ state, codeVerifier, tenantId, nonce });
    res.cookie('oidc_state', oauthState, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 600_000, // 10 minutes
    });

    // Build authorization URL.
    //
    // `oidcConfig.scopes` is the declared field; tolerate a legacy `scope`
    // field (singular, string OR array) that may exist on older tenant
    // documents without widening the type to `any`.
    const legacyScope = oidcConfig.scope;
    const rawScopes: string[] | undefined = oidcConfig.scopes
      ?? (Array.isArray(legacyScope) ? legacyScope : legacyScope ? [legacyScope] : undefined);
    // §10.3::1: default scopes are ['openid','profile','email','groups'] —
    // 'groups' is required so the IdP returns group claims for RBAC mapping.
    const scopes: string[] = rawScopes ?? ['openid', 'profile', 'email', 'groups'];

    const parameters: Record<string, string> = {
      redirect_uri: oidcConfig.redirectUri,
      scope: scopes.join(' '),
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
 // The IdP echoes this back as the `nonce` claim of the issued
      // ID token. The callback enforces it via `expectedNonce`.
      nonce,
      response_type: 'code',
    };

    const redirectTo = client.buildAuthorizationUrl(config, parameters);

    res.redirect(redirectTo.href);
  } catch (err) {
     
    moduleLog.error('[iam/oidc] authorize initiation failed', { error: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: 'Failed to initiate OIDC authorization' });
  }
});

/**
 * GET /oidc/callback
 *
 * Handles the redirect back from the IdP after user authentication.
 * Validates the state parameter, exchanges the authorization code for tokens,
 * extracts user claims, JIT-provisions if needed, and issues a session cookie.
 */
router.get('/oidc/callback', async (req: Request, res: Response): Promise<void> => {
  let parsedStateTenant = '';

  // SOC 2: Record a failed auth attempt against the rate limiter. Resolves
  // the tenant from (in order) the parsed state cookie, the `tenant` query
  // parameter, then the `x-tenant-id` header. No-ops when no tenant can be
  // resolved at all. Never throws — rate-limit-store failures are logged.
  const recordAuthFailureSafe = async (): Promise<void> => {
    const failIp = clientIpHelper(req);
    // §10.8::5 — cookie-bound tenant (signed state) is primary; else the URL
    // tenant. Never a query param or header.
    const failTenant = parsedStateTenant
      || (typeof req.params.tenantId === 'string' ? req.params.tenantId : '');
    // CHARIOT::§16.1 IAM (CHARIOT-SPEC.md:1346, rulings item 91/105) —
    // recordAuthFailureSafe() is called from every failure branch in this
    // handler, so this is the single natural site for auth.failure.
    // Emitted even when failTenant is empty (an unresolvable tenant on a
    // failed OIDC callback is itself a failure worth recording); the
    // early-return below only skips the rate-limit bookkeeping, which
    // genuinely needs a concrete tenant to key against.
    chariotEmitter.send('auth.failure', {
      severity: 'warning',
      data: { tenantId: failTenant || null, method: 'oidc', ip: failIp },
    });
    if (!failTenant) return;
    try {
      await recordAuthFailure(failIp, failTenant);
    } catch (rateLimitErr) {
       
      moduleLog.error('[iam/oidc] recordAuthFailure failed', { error: rateLimitErr instanceof Error ? rateLimitErr.message : String(rateLimitErr) });
    }
  };

  try {
    // Retrieve stored state from cookie. `req.cookies` is typed as `any`
    // by cookie-parser; cast to a narrowed record locally.
    const cookies = req.cookies as Record<string, string | undefined> | undefined;
    const stateCookie = cookies?.oidc_state;

    // Early-parse the cookie (if any) to extract a tenantId for rate
    // limiting. Missing or malformed cookies leave `parsedStateTenant`
    // empty and the fallback chain below resolves the gate key from
    // query/header instead — the same fallback the recorder uses.
    if (stateCookie) {
      try {
        const earlyParsed = JSON.parse(stateCookie) as { tenantId?: string };
        parsedStateTenant = earlyParsed.tenantId ?? '';
      } catch {
        // Malformed cookie — tolerated; fallback chain handles it.
      }
    }

    // SOC 2: Rate-limit gate must run BEFORE any error branch below so
    // that every failure path (missing cookie, malformed cookie, CSRF
    // mismatch, downstream IdP failure) is subject to 429. Uses the SAME
    // fallback chain as `recordAuthFailureSafe` so the gate and the
    // recorder key against the same (ip, tenant) tuple on every branch —
    // if they diverge, failures accumulate under one key while the gate
    // reads another and 429 never fires. `recordAuthFailureSafe` is the
    // single source of truth for failure keying; this gate mirrors it.
    // Trusted-proxy-aware IP (utils/url.clientIp), NOT req.ip — behind the
    // reverse proxy req.ip is the nginx hop and collapses all clients into
    // one bucket, enabling a tenant-wide SSO login DoS.
    const clientIp = clientIpHelper(req);
    const gateTenantId = parsedStateTenant
      || (typeof req.params.tenantId === 'string' ? req.params.tenantId : '');
    if (gateTenantId && await isAuthRateLimited(clientIp, gateTenantId)) {
      res.status(429).json({ error: 'Too many failed login attempts. Try again in 15 minutes.' });
      return;
    }

    if (!stateCookie) {
      // SOC 2: a callback without any state cookie is an auth-failure event.
      // Legitimate clients always round-trip through /oidc/authorize, which
      // sets the cookie. Record so absent-cookie spam from the same IP
      // accumulates against the rate limiter — the gate above will block
      // future requests from the same (ip, gateTenantId) once the threshold
      // is reached.
      await recordAuthFailureSafe();
      res.status(400).json({ error: 'Missing OIDC state cookie' });
      return;
    }

    let storedState: { state: string; codeVerifier: string; tenantId: string; nonce?: string };

    try {
      storedState = JSON.parse(stateCookie) as { state: string; codeVerifier: string; tenantId: string; nonce?: string };
    } catch {
      // SOC 2: tampered/malformed state cookie is an auth failure event.
      // Record BEFORE returning so the rate limiter counts it.
      await recordAuthFailureSafe();
      res.status(400).json({ error: 'Malformed OIDC state cookie' });
      return;
    }

    const { state: expectedState, codeVerifier, tenantId, nonce: expectedNonce } = storedState;

    // §10.8::5 — the URL tenant must equal the tenant bound into the signed
    // state cookie at /authorize time. A mismatch is a cross-tenant callback
    // attempt; fail closed and count it against the rate limiter.
    if (tenantId !== req.params.tenantId) {
      await recordAuthFailureSafe();
      res.status(403).json({ error: 'Tenant mismatch' });
      return;
    }

 // A state cookie produced by /oidc/authorize after this fix is
    // shipped will always carry `nonce`. A cookie missing `nonce` is either
    // tampered or pre-fix (an attacker could intentionally forge a nonce-less
    // cookie to bypass the replay check). Fail closed.
    if (!expectedNonce || typeof expectedNonce !== 'string') {
      await recordAuthFailureSafe();
      res.status(400).json({ error: 'Malformed OIDC state cookie -- missing nonce' });
      return;
    }

    // Clear the state cookie immediately
    res.clearCookie('oidc_state');

    // Validate the state parameter
    const returnedState = req.query.state as string | undefined;

    if (!returnedState || returnedState !== expectedState) {
      // SOC 2: CSRF state mismatch is an auth failure event.
      await recordAuthFailureSafe();
      res.status(400).json({ error: 'Invalid state parameter -- possible CSRF' });
      return;
    }

    const tenant = await getByTenantId(tenantId);
    const oidcConfig = tenant?.sso?.oidc || tenant?.settings?.oidc;
    const oidcConfigField: 'sso.oidc' | 'settings.oidc' = tenant?.sso?.oidc ? 'sso.oidc' : 'settings.oidc';

    if (!oidcConfig) {
      res.status(400).json({ error: 'OIDC not configured for this tenant' });
      return;
    }

    // Re-discover provider configuration
    const config = await client.discovery(
      new URL(oidcConfig.issuer),
      oidcConfig.clientId,
      await resolveOidcClientSecret(oidcConfig, tenantId, oidcConfigField),
    );

    // Exchange the authorization code for tokens
    // Use the configured redirect_uri (not reconstructed from req) because
    // behind reverse proxies/tunnels, req.protocol and req.host are wrong.
    const callbackUrl = new URL(oidcConfig.redirectUri);
    callbackUrl.search = new URL(req.originalUrl, 'http://localhost').search;

    const tokens = await client.authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: codeVerifier,
      expectedState: expectedState,
 // Pass expectedNonce so openid-client validates the ID token's
      // `nonce` claim matches the value we sent on /authorize. Replay of a
      // captured authorization code against a fresh /authorize round-trip
      // produces an id_token bound to the original nonce — mismatch trips
      // an exception here, which falls to the catch block and 401s.
      expectedNonce,
    });

    // Extract claims from the id_token
    const claims = tokens.claims();

    if (!claims) {
      res.status(401).json({ error: 'No claims in token response' });
      return;
    }

    const email = claims.email as string | undefined;
    const sub = claims.sub;
    const name = claims.name as string | undefined;
    const groups = (claims.groups as string[] | undefined) ?? [];
    const emailVerified = claims.email_verified as boolean | undefined;

    if (!email) {
      res.status(401).json({ error: 'Email claim missing from ID token' });
      return;
    }

    // Account-binding defense: email is the JIT-provisioning / identity key
    // below, so an id_token asserting email=victim@tenant with
    // email_verified=false must NOT be allowed to adopt or create that
    // identity. Reject an EXPLICIT false. (Undefined is tolerated — Entra ID
    // and some enterprise IdPs omit the claim; requiring true unconditionally
    // would break conformant IdPs.)
    if (emailVerified === false) {
      await recordAuthFailureSafe();
      res.status(401).json({ error: 'Email not verified by identity provider' });
      return;
    }

    // JIT provision: upsert user
    const usersCol = await getCollection<EnterpriseUserDocument>('iam_users');
    const now = new Date();

    const upsertResult = await usersCol.findOneAndUpdate(
      { tenantId, email },
      {
        $set: {
          displayName: name ?? email,
          groups,
          active: true,
          updatedAt: now,
        },
        $setOnInsert: {
          tenantId,
          externalId: sub,
          userName: email,
          email,
          metadata: {
            givenName: (claims.given_name as string) ?? '',
            familyName: (claims.family_name as string) ?? '',
          },
          createdAt: now,
        },
      },
      { upsert: true, returnDocument: 'after' },
    );

    if (!upsertResult) {
       
      moduleLog.error(
        `[iam/oidc] JIT provisioning returned null for tenant=${tenantId} email=${email}`,
      );
      res.status(500).json({ error: 'Failed to provision user' });
      return;
    }
    const user = upsertResult;

    // SOC 2: Clear failure counter on successful primary auth
    await clearAuthFailures(clientIp, tenantId);

    // Delegate to the IdP. Inspect the OIDC `amr` claim (RFC 8176)
    // before falling through to Chariot-side TOTP. If the IdP
    // already performed MFA, forcing a second factor here is double MFA
    // for Okta/Entra/Ping customers whose IdPs enforce step-up at sign-in.
    const idpMfa = oidcAssertedMfa((claims as Record<string, unknown>).amr);

    // MFA gate: if tenant requires TOTP AND the IdP did NOT already perform
    // MFA, redirect to the Chariot TOTP flow.
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

    // Issue session. Stamp `mfaVerified: true` when either the tenant
    // doesn't require MFA or the IdP asserted MFA via the amr claim.
    const mfaVerified = !tenant.settings?.mfaRequired || idpMfa.asserted;

    // CHARIOT::§16.1 IAM (CHARIOT-SPEC.md:1346, rulings item 91/105) —
    // `mfa.skipped_via_idp`: fires ONLY when the tenant requires MFA and
    // the IdP already asserted it via the amr claim, skipping Chariot's
    // own TOTP challenge. A tenant with mfaRequired=false has nothing to
    // skip and must not emit this event.
    if (tenant.settings?.mfaRequired && idpMfa.asserted) {
      chariotEmitter.send('mfa.skipped_via_idp', {
        data: { tenantId, userId: user._id.toString(), method: 'oidc', amr: idpMfa.amr },
      });
    }

    const token = await issueToken(user, tenant, { mfaVerified });
    const jti = (JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString(),
    ) as { jti: string }).jti;
    const refreshToken = await issueRefreshToken(jti, user._id.toString(), tenantId, mfaVerified);

    // P6 — persist the inbound OIDC ID token as subject_token for the
    // Chariot-as-Client ID-JAG fan-out path (§4.3). When the MCP-
    // dispatch layer needs a per-audience ID-JAG, it reads this record
    // and presents it at the IdP's token-exchange endpoint. Encrypted
    // at rest by setIdJagSubjectToken. Issuer is the OIDC discovery
    // `iss` (claims.iss). Skip silently when the IdP did not return
    // an exp / iss (defence — every conformant OIDC IdP includes both).
    if (
      typeof tokens.id_token === 'string'
      && typeof claims.iss === 'string'
      && typeof claims.exp === 'number'
    ) {
      try {
        await setIdJagSubjectToken(tenantId, jti, {
          token: tokens.id_token,
          type: 'id_token',
          exp: claims.exp,
          issuer: claims.iss,
        });
      } catch (e) {
        // Non-fatal — the session itself is valid. Log and continue;
        // MCP-dispatch will fall through to static credentials for
        // adapters that allow that fallback.
        moduleLog.warn('[iam/oidc] setIdJagSubjectToken failed (non-fatal)', { error: e instanceof Error ? e.message : String(e) });
      }
    }

    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);
    const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    // Audit log
    await audit.log(tenantId, 'login', {
      actorId: user._id.toString(),
      actorEmail: email,
      targetType: 'user',
      targetId: user._id.toString(),
      detail: {
        method: 'oidc',
        sub,
        idpAssertedMfa: idpMfa.asserted,
        amr: idpMfa.amr,
        mfaRequired: Boolean(tenant.settings?.mfaRequired),
      },
      ip: clientIpHelper(req),
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    // CHARIOT::§16.1 IAM (CHARIOT-SPEC.md:1346, rulings item 91/105) — this
    // point is only reached for a COMPLETED login: the MFA-required branch
    // above returns early before here, so this never double-fires
    // alongside mfa.ts's own auth.success on MFA completion.
    chariotEmitter.send('auth.success', {
      data: { tenantId, userId: user._id.toString(), method: 'oidc' },
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

    res.redirect('/');
  } catch (err: unknown) {
    // SOC 2: Record failed auth attempt via the shared helper so every
    // failure path in this handler uses identical tenant-resolution logic.
    await recordAuthFailureSafe();
    // Log the full error server-side for operators. Return a generic
    // message to the client — the underlying `err.message` can contain
    // IdP URLs, token response fragments, library stack hints, or other
    // sensitive material that must not reach the client.
     
    moduleLog.error('[iam/oidc] callback auth failed', { error: err instanceof Error ? err.message : String(err) });
    res.status(401).json({ error: 'OIDC authentication failed' });
  }
});

export default router;
