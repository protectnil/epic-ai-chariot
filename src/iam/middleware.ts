/**
 * Enterprise IAM Middleware
 *
 * Factory functions for Express 4 middleware that handle authentication,
 * authorization, adapter filtering, tenant resolution, and license gating
 * for the Chariot enterprise IAM subsystem.
 *
 * @module iam/middleware
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { EnterpriseSessionPayload } from './types.js';
import type { VerifiedCatalog } from '../catalog/VerifiedCatalog.js';
import { canonicalName } from '../catalog/VerifiedCatalog.js';
import type { TenantDemotionOverrideStore } from '../catalog/TenantDemotionOverrides.js';
import { verifyToken } from './services/session.js';
import { verifyScimToken, getByTenantId } from './services/tenant.js';
import { isAuthRateLimited, recordAuthFailure, clearAuthFailures } from './services/auth-rate-limit.js';
import { verifyDpopProofForResource } from './services/dpop.js';
import { jtiReplayCache } from './services/jti-replay-cache.js';
import { log as auditLog } from './services/audit.js';
import { clientIp as extractClientIp, escapeDpopHeaderValue, requestHtu, userAgent } from './utils/url.js';
import { validateLicense, checkSeatLimit } from '../license/loader.js';
import { PromptCache } from '../engine/resilience/PromptCache.js';
import { createLogger } from '../engine/logger.js';
import { filterAdapterIdsForPrincipal } from './services/principal-partition.js';
import type { LoadMappingsFn, NativeRbacResolver } from './services/principal-partition.js';

const scimLog = createLogger('iam.scim');
const principalPartitionLog = createLogger('iam.principal-partition');
const moduleLog = createLogger('iam.middleware');

// In-memory cache of tenant.settings.mfaRequired keyed by tenantId.
// Avoids a DB lookup on every authenticated request when the token's
// mfaVerified claim is anything other than `true`. TTL is 60s — short
// enough that an admin toggling mfaRequired is enforced within a minute.
// Admin code (PUT /tenant) calls invalidateMfaRequiredCache() on toggle so
// enforcement is immediate, not eventually-consistent.
//
// PromptCache<boolean> replaces the previous bespoke Map<string, { value,
// expiresAt }> (REUSE #4). It provides LRU eviction with a 10 000-entry cap
// and per-entry 60s TTL via set(key, value, ttlMs). Operations used:
//   get(key) → boolean | null, set(key, value, ttlMs), invalidate(key).
// All are present on PromptCache<T>.
const MFA_REQUIRED_CACHE_TTL_MS = 60_000;
const MFA_REQUIRED_CACHE_MAX_ENTRIES = 10_000;
const _mfaRequiredCache = new PromptCache<boolean>({
  maxEntries: MFA_REQUIRED_CACHE_MAX_ENTRIES,
  defaultTTLMs: MFA_REQUIRED_CACHE_TTL_MS,
});

async function isMfaRequiredForTenant(tenantId: string): Promise<boolean> {
  const cached = _mfaRequiredCache.get(tenantId);
  if (cached !== null) return cached;

  const tenant = await getByTenantId(tenantId);
  const value = tenant?.settings?.mfaRequired === true;
  _mfaRequiredCache.set(tenantId, value, MFA_REQUIRED_CACHE_TTL_MS);
  return value;
}

/**
 * Invalidate the in-memory mfaRequired cache for a tenant. Call this when
 * tenant settings are updated so policy changes take effect on the next request.
 */
export function invalidateMfaRequiredCache(tenantId: string): void {
  _mfaRequiredCache.invalidate(tenantId);
}

/** Maximum token size in bytes (8 KB). */
const MAX_TOKEN_BYTES = 8192;

// ---------------------------------------------------------------------------
// Express type augmentation
// ---------------------------------------------------------------------------

declare global {
  namespace Express {
    interface Request {
      enterpriseUser?: EnterpriseSessionPayload & {
        sub: string;
        isAdmin: boolean;
        adapterIds: string[];
        jti: string;
      };
      tenantId?: string;
      allowedAdapterIds?: string[];
    }
  }
}

// ---------------------------------------------------------------------------
// License gate
// ---------------------------------------------------------------------------

/**
 * Gate middleware that checks the Chariot license before allowing
 * multi-user IAM operations.
 *
 * Spec Chapter 5 — Four license states:
 * - UNLICENSED → 402, multi-user routes blocked
 * - LICENSED → proceed
 * - GRACE → proceed (full access continues during grace period)
 * - DEGRADED → 402, multi-user routes blocked
 */
export function licenseGateMiddleware(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const license = validateLicense();

    if (license.mode === 'unlicensed') {
      res.status(402).json({
        error: 'License required',
        detail:
          'Multi-user IAM features require a valid Chariot license. ' +
          'Visit https://epic-ai.io to purchase seats.',
        mode: 'unlicensed',
      });
      return;
    }

    if (license.mode === 'degraded') {
      res.status(402).json({
        error: 'License lapsed',
        detail:
          'Your Chariot team license has lapsed. Single-user mode is active with full features. ' +
          'Multi-user access, SSO, shared credentials, and RBAC are paused. ' +
          'This will resolve automatically when your payment processes. ' +
          'If you need help: support@epic-ai.io',
        mode: 'degraded',
        companyName: license.companyName,
        expiresAt: license.expiresAt,
      });
      return;
    }

    // LICENSED and GRACE both proceed — full access
    next();
  };
}

/**
 * Middleware that enforces seat limits on new session creation.
 * Should be placed before token issuance endpoints (SAML callback, OIDC callback).
 *
 * `getActiveUserCount` is injected by the caller to avoid coupling to a
 * specific session counting implementation.
 */
/**
 * Atomic reservation slot store closes the read-then-check race in
 * seatLimitMiddleware. Implementations MUST guarantee:
 *   - reserve(nonce, ttlSec) is atomic. Concurrent callers with the
 *     same nonce produce exactly one `true` result.
 *   - The reservation expires within ttlSec without explicit release.
 *   - count() returns the current outstanding reservation count.
 */
export interface SeatReservationStore {
  reserve(nonce: string, ttlSec: number): Promise<boolean>;
  count(): Promise<number>;
}

const RESERVATION_TTL_SEC = 5;

export function seatLimitMiddleware(
  getActiveUserCount: () => Promise<number>,
  reservations?: SeatReservationStore,
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const activeUsers = await getActiveUserCount();
      const outstanding = reservations ? await reservations.count() : 0;
      const seatCheck = checkSeatLimit(activeUsers + outstanding);

      if (!seatCheck.allowed) {
        res.status(402).json({
          error: 'Seat limit reached',
          detail:
            `Your license allows ${seatCheck.totalSeats} seats. ` +
            `${seatCheck.activeUsers} are currently active. ` +
            'Purchase additional seats at https://epic-ai.io.',
          totalSeats: seatCheck.totalSeats,
          activeUsers: seatCheck.activeUsers,
        });
        return;
      }

      // atomically claim a reservation slot BEFORE next() so a
      // concurrent signup against the same residual capacity cannot also
      // pass the gate. The session-creation handler downstream persists
      // the real session; the reservation auto-expires within 5s.
      if (reservations) {
        const { randomBytes } = await import('node:crypto');
        const nonce = randomBytes(16).toString('hex');
        const claimed = await reservations.reserve(nonce, RESERVATION_TTL_SEC);
        if (!claimed) {
          // 128-bit collision is astronomically unlikely; treat as
          // transient capacity pressure so the client retries.
          res.status(409).json({ error: 'Seat reservation race; retry.' });
          return;
        }
      }

      next();
    } catch {
      res.status(500).json({ error: 'Failed to check seat limit' });
    }
  };
}

// ---------------------------------------------------------------------------
// Authentication middleware
// ---------------------------------------------------------------------------

/**
 * Authenticate enterprise users via session cookie or Authorization
 * Bearer/DPoP header. RFC 9449 DPoP enforcement: when a token carries a
 * `cnf.jkt` claim (ID-JAG-bound or future DPoP-bound issuance path), the
 * request MUST use `Authorization: DPoP <token>` (not Bearer) AND carry
 * a fresh proof in the `DPoP` header whose JWK SHA-256 thumbprint
 * matches `cnf.jkt` and whose `ath` claim equals base64url(SHA-256(token)).
 */
export function enterpriseAuthMiddleware(): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const cookies = req.cookies as Record<string, string | undefined> | undefined;
      const authzHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined;
      const dpopScheme = authzHeader !== undefined && /^DPoP\s+/i.test(authzHeader);
      const bearerToken = extractBearerToken(authzHeader);
      const dpopHeaderToken = dpopScheme ? authzHeader!.replace(/^DPoP\s+/i, '').trim() : undefined;
      const token = cookies?.enterprise_token ?? bearerToken ?? dpopHeaderToken;

      if (!token) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      if (Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) {
        res.status(401).json({ error: 'Token exceeds maximum size' });
        return;
      }

      const payload = await verifyToken(token);

      if (!payload) {
        res.status(401).json({ error: 'Invalid or expired token' });
        return;
      }

      // RFC 9449 DPoP enforcement — fail-closed on cnf.jkt mismatch or
      // missing/invalid proof. A bearer presentation of a sender-
      // constrained token is rejected with WWW-Authenticate: DPoP per
      // §7.1 so the client knows to retry with the DPoP scheme.
      //
      // Every DPoP failure path here records a per-IP+tenant rate-limit
      // failure AND audits an id_jag_assertion_rejected event with
      // code=dpop_resource_failed so the resource surface is throttled
      // and audited the same way the token endpoint is.
      const cnfJkt = typeof payload.cnf?.jkt === 'string' ? payload.cnf.jkt : undefined;
      if (cnfJkt !== undefined) {
        const clientAddr = extractClientIp(req);
        const auditDpopFailure = async (reason: string): Promise<void> => {
          await recordAuthFailure(clientAddr, payload.tenantId);
          await auditLog(payload.tenantId, 'id_jag_assertion_rejected', {
            actorId: payload.userId,
            actorEmail: payload.email ?? '',
            targetType: 'user',
            targetId: payload.userId,
            detail: { code: 'dpop_resource_failed', reason, ip: clientAddr, path: req.originalUrl.split('?')[0] },
            ip: clientAddr,
            userAgent: userAgent(req),
          });
        };
        if (!dpopScheme) {
          await auditDpopFailure('token is sender-constrained; use Authorization: DPoP scheme');
          res
            .status(401)
            .set('WWW-Authenticate', 'DPoP error="invalid_token", error_description="token is sender-constrained; use Authorization: DPoP scheme"')
            .json({ error: 'invalid_token', error_description: 'token is sender-constrained; use Authorization: DPoP scheme' });
          return;
        }
        const dpopProof = typeof req.headers.dpop === 'string' ? req.headers.dpop : undefined;
        if (!dpopProof) {
          await auditDpopFailure('DPoP header missing');
          res
            .status(401)
            .set('WWW-Authenticate', 'DPoP error="invalid_token", error_description="DPoP header missing"')
            .json({ error: 'invalid_token', error_description: 'DPoP header missing' });
          return;
        }
        const htu = requestHtu(req);
        const dpopResult = await verifyDpopProofForResource({
          proof: dpopProof,
          htm: req.method.toUpperCase(),
          htu,
          accessToken: token,
          expectedJkt: cnfJkt,
          jtiCache: jtiReplayCache,
        });
        if (!dpopResult.ok) {
          await auditDpopFailure(dpopResult.reason);
          // Phase 0.1 R4: shared sanitiser with oauth.ts /token + /revoke
          // so all three DPoP-failure paths cannot drift on header/JSON
          // escaping. RFC 9449 §7.1 applies at the resource boundary —
          // this surface keeps 401 + `invalid_token` per that section.
          const safeReason = escapeDpopHeaderValue(dpopResult.reason);
          res
            .status(401)
            .set('WWW-Authenticate', `DPoP error="invalid_token", error_description="${safeReason}"`)
            .json({ error: 'invalid_token', error_description: safeReason });
          return;
        }
      }

      // MFA enforcement (fail-closed):
      // - mfaVerified === true: short-circuit, no DB lookup
      // - mfaVerified === false: token was issued for a tenant that requires MFA
      //   but TOTP was not completed → 401
      // - undefined (legacy tokens issued before this rollout): consult tenant
      //   policy. If tenant requires MFA, reject — otherwise the legacy session
      //   would silently bypass MFA until expiry.
      if (payload.mfaVerified !== true) {
        if (payload.mfaVerified === false || (await isMfaRequiredForTenant(payload.tenantId))) {
          res.status(401).json({ error: 'MFA verification required', code: 'MFA_REQUIRED' });
          return;
        }
      }

      req.enterpriseUser = payload;
      req.tenantId = payload.tenantId;

      // §10.8::5 / §3.5::23 — reject a URL tenantId that does not match the
      // token's tid claim. The URL is the authoritative tenant selector; a
      // token for another tenant must never operate under this tenant's path.
      if (
        typeof req.params.tenantId === 'string' &&
        req.params.tenantId !== payload.tenantId
      ) {
        res.status(403).json({ error: 'Tenant mismatch' });
        return;
      }

      next();
    } catch {
      res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
}

/**
 * Authenticate SCIM provisioning requests.
 */
export function scimAuthMiddleware(): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = extractBearerToken(req.headers.authorization);

      if (!token) {
        res.status(401).json({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
          detail: 'Authorization header with Bearer token is required',
          status: '401',
        });
        return;
      }

      const tenantId = req.params.tenantId as string
        || req.tenantId
        || (req.headers['x-tenant-id'] as string)
        || process.env.SCIM_DEFAULT_TENANT
        || '';

      if (!tenantId) {
        res.status(400).json({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
          detail: 'Tenant ID is required',
          status: '400',
        });
        return;
      }

      // Use the shared clientIp helper (imported above as
      // extractClientIp) so the SCIM rate-limit key is consistent with
      // /token + /revoke + MFA + admin. Without this, an attacker
      // hitting SCIM is keyed under `req.ip` while the same attacker
      // hitting MFA is keyed under the trusted-proxy-aware helper —
      // failures don't accumulate on the same bucket.
      const clientAddr = extractClientIp(req);
      // Rate-limit store failures must NOT break authentication — fail
      // open on availability (treat as not-limited) and log via the
      // structured logger. Matches the OIDC `recordAuthFailureSafe`
      // pattern (oidc.ts:142-154).
      let rateLimited = false;
      try {
        rateLimited = await isAuthRateLimited(clientAddr, tenantId);
      } catch (rateLimitErr) {
        scimLog.error('isAuthRateLimited failed', { tenantId, error: String(rateLimitErr) });
      }
      if (rateLimited) {
        res.status(429).json({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
          detail: 'Too many failed authentication attempts. Try again in 15 minutes.',
          status: '429',
        });
        return;
      }

      const valid = await verifyScimToken(tenantId, token);

      if (!valid) {
        try {
          await recordAuthFailure(clientAddr, tenantId);
        } catch (rateLimitErr) {
          scimLog.error('recordAuthFailure failed', { tenantId, error: String(rateLimitErr) });
        }
        res.status(401).json({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
          detail: 'Invalid SCIM bearer token',
          status: '401',
        });
        return;
      }

      // Clear failure counter on successful authentication. Matches the
      // SAML (saml.ts:179) and OIDC (oidc.ts:330) success-path patterns.
      // Without this, a tenant with routine token rotation accumulates
      // failures and eventually trips its own 15-minute lockout.
      try {
        await clearAuthFailures(clientAddr, tenantId);
      } catch (rateLimitErr) {
        scimLog.error('clearAuthFailures failed', { tenantId, error: String(rateLimitErr) });
      }

      req.tenantId = tenantId;

      next();
    } catch {
      res.status(500).json({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'Internal server error during SCIM authentication',
        status: '500',
      });
    }
  };
}

/**
 * Guard that requires the authenticated user to be a tenant admin.
 */
export function enterpriseAdminGuard(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.enterpriseUser?.isAdmin) {
      res.status(403).json({ error: 'Admin access required' });
      return;
    }

    next();
  };
}

/**
 * Attach the user's allowed adapter IDs from their session to the request.
 *
 * Resolution order (fail-closed on anything unexpected):
 *
 * 1. If `adapterIds` (the RBAC-resolved list populated at session-issue
 *    time by `issueToken()`) is non-empty, use it. This is the normal
 *    group-mapped path.
 *
 * 2. If the user has NO groups at all (`groups` is undefined, empty, or
 *    missing), fall back to the tenant-wide `allowedAdapterIds`. This
 *    preserves "allowlist-only" tenant mode — tenants who have not
 *    configured group→adapter mappings at all, and grant access purely
 *    via the tenant ceiling. Users without any IdP groups inherit the
 *    tenant ceiling in this mode only.
 *
 * 3. If the user has groups but `adapterIds` is empty, DENY. This is
 *    the case where an IdP populated groups but none of them mapped to
 *    any adapter — the user should NOT inherit the tenant ceiling, which
 *    would broaden privileges beyond what the admin intended. An empty
 *    group-mapped adapter list is treated as an explicit deny rather than
 *    a fallback to the tenant ceiling; this branch enforces that boundary.
 *
 * 4. If both paths yield nothing, 403 with an explicit message.
 *
 * ## Principal-kind partition (gap #3 — Wiz 2 human/agent/service)
 *
 * This middleware is ALSO the live enforcement point for the principal
 * partition. When the authenticated session is a NON-HUMAN principal
 * (`enterpriseUser.principalType === 'agent' | 'service'` — stamped at
 * issuance, e.g. by the ID-JAG token exchange), the Path-1 RBAC adapter
 * list is re-filtered through `filterAdapterIdsForPrincipal`
 * (services/principal-partition.ts): any adapter the session can only
 * justify via a mapping whose `principalScope` excludes the caller's
 * kind (e.g. `principalScope: ['human']`) is stripped before
 * `req.allowedAdapterIds` is populated. If nothing survives, the
 * request gets the same 403 as a user with no grants.
 *
 * Safe default — NO change to existing traffic: sessions with
 * `principalType` absent, `'human'`, or any unrecognized value take the
 * exact pre-partition code path (no mapping-store read, no native
 * call). Mappings without `principalScope` apply to every principal
 * kind, so agent/service sessions only lose grants an operator
 * EXPLICITLY scoped away from them. The Path-2 tenant ceiling carries
 * no per-grant principal scope and is intentionally not filtered.
 *
 * Fail-closed: if principal-scope re-resolution itself fails (mapping
 * store unreachable), the non-human request is rejected with 503 rather
 * than falling back to the unfiltered session list.
 */
export interface AdapterFilterOptions {
  /**
   * Test seam: overrides how tenant mapping documents are loaded inside
   * `filterAdapterIdsForPrincipal`. Production callers omit it (Mongo-
   * backed `mapping.list`). Only ever invoked for agent/service
   * sessions — never on the human/absent default path.
   */
  loadMappings?: LoadMappingsFn;
  /**
   * Test seam: overrides how the native RBAC decision surface is resolved
   * inside `filterAdapterIdsForPrincipal` (CHARIOT::§2.1::2 — the decision
   * is always the native `resolveUserAdaptersForPrincipal` export in
   * production; there is no TS fallback to test around). Production
   * callers omit it (real `resolveNativeFromBinding`). Lets unit tests
   * exercise both the native-decision path and the fail-closed refusal
   * path deterministically, independent of whether a platform binary
   * happens to be present on the host running the test.
   */
  resolveNative?: NativeRbacResolver;
}

export function adapterFilterMiddleware(options: AdapterFilterOptions = {}): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const enterpriseUser = req.enterpriseUser;
    const rbacAdapters = enterpriseUser?.adapterIds;
    const tenantCeiling = enterpriseUser?.allowedAdapterIds;
    const userGroups = enterpriseUser?.groups;

    let adapterIds: string[] | undefined;
    if (rbacAdapters && rbacAdapters.length > 0) {
      // Path 1: normal RBAC path.
      adapterIds = rbacAdapters;

      // Principal partition (gap #3): agent/service sessions must not
      // inherit grants an operator scoped to other principal kinds.
      // STRICT membership check — absent/'human'/unknown values all fall
      // through to the unchanged legacy behavior (safe default).
      const principalType = enterpriseUser?.principalType;
      if ((principalType === 'agent' || principalType === 'service')
        && enterpriseUser?.tenantId) {
        try {
          adapterIds = await filterAdapterIdsForPrincipal(
            enterpriseUser.tenantId,
            principalType,
            userGroups ?? [],
            adapterIds,
            options.loadMappings ?? undefined,
            options.resolveNative,
          );
        } catch (err) {
          // Fail closed for the stricter (non-human) path only: never
          // hand an agent the unfiltered human grant list because the
          // mapping store was unreachable.
          principalPartitionLog.error('principal-scope re-resolution failed', {
            tenantId: enterpriseUser.tenantId,
            principalType,
            error: String(err),
          });
          res.status(503).json({
            error: 'Authorization temporarily unavailable',
            detail:
              'Principal-scoped adapter authorization could not be resolved. Retry shortly.',
          });
          return;
        }
      }
    } else if (!userGroups || userGroups.length === 0) {
      // Path 2: allowlist-only tenant — user has no IdP groups, so
      // fall back to the tenant ceiling.
      adapterIds = tenantCeiling;
    } else {
      // Path 3: user has groups but none resolved to adapter mappings.
      // Deny — do NOT inherit the tenant ceiling.
      adapterIds = [];
    }

    if (!adapterIds || adapterIds.length === 0) {
      res.status(403).json({
        error: 'No adapters configured',
        detail:
          'No adapters are configured for your account. Contact your administrator.',
      });
      return;
    }

    req.allowedAdapterIds = adapterIds;

    next();
  };
}

// ---------------------------------------------------------------------------
// Verified-catalog enforcement (C2)
// ---------------------------------------------------------------------------

/**
 * Remove adapters that have not (yet) passed verification from
 * the request's `allowedAdapterIds`. MUST run AFTER
 * `adapterFilterMiddleware()` — reads what the session said
 * the user could access, then strips any adapter whose
 * `VerifiedCatalog` record is NOT `status: 'verified'` — i.e.
 * `'failed'` (demoted), `'pending'` (never reviewed) or
 * `'stale'` (review expired). Only `'verified'` adapters are
 * reachable via REST/HTTP.
 *
 * This is the C2 enforcement surface for the Chariot
 * middleware. Upstream catalog demotion events eventually
 * become `catalog.markFailed(adapterName, reason)` calls on
 * the Chariot process, and brand-new adapters simply have no
 * verification record yet (`getVerification()` synthesizes a
 * `'pending'` record for any adapter the catalog has never
 * seen `markVerified`/`markFailed` called for). This
 * middleware ensures that neither demoted NOR not-yet-reviewed
 * adapters can be invoked via any authenticated request, even
 * if the session token still lists them (feed #7 — the REST
 * half of the same gate FederationManager already enforces on
 * the dispatch side via `verifiedCatalog`/`AdapterVerificationLookup`,
 * see FederationManager.ts's `verifiedCatalog` option doc).
 *
 * ## Fail-closed semantics
 *
 * If `req.allowedAdapterIds` is unset (undefined) rather
 * than an empty array, the wiring is broken — either
 * `adapterFilterMiddleware()` wasn't mounted first, or a
 * caller bypassed it. This middleware fails closed with
 * `500 Middleware misconfigured` rather than silently
 * passing the request through, because this is a trust-
 * boundary check and silent bypass is the worst outcome.
 * Empty array (the legitimate "no adapters configured"
 * shape) is still a no-op — the earlier 403 from
 * `adapterFilterMiddleware()` handles it.
 *
 * Adapter IDs on both sides (the session's list and the
 * catalog's verification records) are normalized via
 * `canonicalName()` before comparison. The catalog
 * canonicalizes storage keys internally but preserves the
 * raw `adapterName` on its records, so without explicit
 * normalization a case/format mismatch would let unverified
 * adapters through.
 *
 * If every adapter in the user's session has been demoted or
 * is not yet verified, the request fails with `403 All
 * adapters unavailable`.
 *
 * When the provided catalog is undefined (tests or local
 * dev that doesn't wire one up), the middleware is a
 * no-op — production wiring MUST supply a catalog.
 */
export interface VerifiedCatalogEnforcementOptions {
  /**
   * Optional per-tenant override store (C3). When present,
   * any adapter that would normally be blocked by the C2
   * not-verified filter (failed, pending, OR stale) is
   * EXEMPTED for tenants that have an active override for
   * that adapter. Requires `tenantResolutionMiddleware()` to
   * have run first so `req.tenantId` is populated. When
   * `req.tenantId` is unset (non-multi-tenant deployments),
   * overrides are not consulted and enforcement behaves as
   * plain C2.
   */
  overrides?: TenantDemotionOverrideStore;
  /** Injected clock for deterministic tests. */
  now?: () => Date;
}

export function verifiedCatalogEnforcementMiddleware(
  catalog: VerifiedCatalog | undefined,
  options: VerifiedCatalogEnforcementOptions = {},
): RequestHandler {
  const nowFn = options.now ?? (() => new Date());
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!catalog) {
      next();
      return;
    }
    const allowed = req.allowedAdapterIds;
    if (allowed === undefined) {
      // Fail-closed: the trust-boundary middleware ran
      // without the prerequisite `adapterFilterMiddleware()`
      // having populated req.allowedAdapterIds. Refuse the
      // request rather than letting it through unchecked.
      res.status(500).json({
        error: 'Middleware misconfigured',
        detail:
          'verifiedCatalogEnforcementMiddleware must run AFTER adapterFilterMiddleware. req.allowedAdapterIds is unset.',
      });
      return;
    }
    if (allowed.length === 0) {
      // Legitimate empty case — handled upstream. No-op.
      next();
      return;
    }

    // feed #7: block anything that is NOT 'verified' — 'failed' (demoted),
    // 'pending' (no verification record at all yet — brand-new/never
    // reviewed), and 'stale' (review expired) all resolve here, mirroring
    // the FederationManager dispatch-side gate's status set but stricter
    // (REST denies pending/stale outright rather than routing them to an
    // approval queue, since there is no approval surface at this layer).
    // getVerification() synthesizes a 'pending' record for any adapter id
    // the catalog has never seen, so this also catches adapters with zero
    // verification history — not just ones explicitly marked failed.
    const notVerifiedSet = new Set<string>();
    for (const id of allowed) {
      const canonical = canonicalName(id);
      if (catalog.getVerification(id).status !== 'verified') {
        notVerifiedSet.add(canonical);
      }
    }
    if (notVerifiedSet.size === 0) {
      next();
      return;
    }

    // C3: consult the per-tenant override store. An adapter
    // that has an active override for this tenant is
    // removed from the not-verified set for this request only.
    // The override is a deliberate business-continuity
    // decision by the tenant admin and does not affect
    // other tenants.
    if (options.overrides && req.tenantId) {
      const now = nowFn();
      const tenantId = req.tenantId;
      const exempt = new Set<string>();
      for (const canonical of notVerifiedSet) {
        if (options.overrides.isExempted(tenantId, canonical, now)) {
          exempt.add(canonical);
        }
      }
      for (const c of exempt) notVerifiedSet.delete(c);
    }

    const filtered = allowed.filter(
      (id) => !notVerifiedSet.has(canonicalName(id)),
    );
    if (filtered.length === 0) {
      res.status(403).json({
        error: 'All adapters unavailable',
        detail:
          'Every adapter in your access list has been demoted by the verified-catalog trust layer. Contact your administrator or wait for the catalog publisher to re-verify.',
      });
      return;
    }
    req.allowedAdapterIds = filtered;
    next();
  };
}

/**
 * Resolve the tenant from the `X-Tenant-Id` header or the request subdomain.
 */
export function tenantResolutionMiddleware(): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const headerTenantId = req.headers['x-tenant-id'] as string | undefined;
      const subdomain = req.hostname?.split('.')[0];

      const identifier = headerTenantId || subdomain;

      if (!identifier) {
        res.status(400).json({ error: 'Unable to resolve tenant' });
        return;
      }

      const tenant = await getByTenantId(identifier);

      if (!tenant) {
        res.status(404).json({ error: 'Tenant not found' });
        return;
      }

      if (!tenant.active) {
        res.status(403).json({ error: 'Tenant is suspended' });
        return;
      }

      req.tenantId = tenant.tenantId;

      next();
    } catch {
      res.status(500).json({ error: 'Failed to resolve tenant' });
    }
  };
}

// ---------------------------------------------------------------------------
// TLS enforcement (SOC 2)
// ---------------------------------------------------------------------------

/**
 * Reject non-HTTPS requests in production.
 * Checks X-Forwarded-Proto (for reverse proxies like nginx) and req.secure.
 */
export function requireTlsMiddleware(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (process.env.NODE_ENV !== 'production') {
      next();
      return;
    }
    const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
    if (proto !== 'https') {
      res.status(403).json({
        error: 'HTTPS required',
        detail: 'Enterprise IAM routes require TLS in production.',
      });
      return;
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractBearerToken(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const match = header.match(/^Bearer\s+(\S+)$/i);
  if (match) return match[1];
  const trimmed = header.trim();
  if (trimmed.length > 0 && !trimmed.includes(' ')) return trimmed;
  return undefined;
}

/**
 * Type-safe auth context for a route handler.
 *
 * Routes that run behind `enterpriseAuthMiddleware()` can assume `req.tenantId`
 * and `req.enterpriseUser` are present — but TypeScript's type system cannot
 * prove that because the fields are declared optional on the Express Request
 * augmentation. Prior code used non-null assertions (`req.tenantId!`,
 * `req.enterpriseUser!.email`) to work around this, which is both a type-
 * safety violation (eslint `no-non-null-assertion`) and a runtime footgun:
 * if a route is ever mounted without the auth middleware in front of it, the
 * assertion silently hides the mistake and the handler crashes at runtime
 * with an opaque `Cannot read properties of undefined` error.
 *
 * This helper replaces those assertions. Call at the top of every
 * authenticated route handler:
 *
 * ```ts
 * const auth = requireEnterpriseAuth(req, res);
 * if (!auth) return;
 * const { tenantId, user } = auth;
 * ```
 *
 * On missing auth it writes a 401 response and returns `null`; the caller
 * MUST return immediately. On success it returns a narrowed tuple with
 * `tenantId: string` and `user` typed as the non-optional enterprise user.
 *
 * Using this helper makes the failure mode explicit (401) rather than
 * relying on middleware ordering correctness as a type invariant.
 */
export interface EnterpriseAuthContext {
  tenantId: string;
  user: NonNullable<Request['enterpriseUser']>;
}

// Per-(adapterId, operation) RBAC enforcement helper lives in
// `./types.js` so the chariot_call dispatcher (`engine/server/toolHandlers`)
// can import the deny-by-default check without pulling in license / catalog /
// redis side-effects from this middleware module. Re-exported here so the
// existing IAM middleware surface is unchanged.
export { isOperationAllowed } from './types.js';

export function requireEnterpriseAuth(
  req: Request,
  res: Response,
): EnterpriseAuthContext | null {
  const tenantId = req.tenantId;
  const user = req.enterpriseUser;
  if (!tenantId || !user) {
     
    moduleLog.error(
      '[iam/middleware] requireEnterpriseAuth invoked without prior auth — ' +
        'route is missing enterpriseAuthMiddleware()',
    );
    res.status(401).json({ error: 'Authentication required' });
    return null;
  }
  return { tenantId, user };
}
