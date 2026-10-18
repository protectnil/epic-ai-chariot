/**
 * Enterprise IAM Route Index
 *
 * Mounts all sub-routers and exports `createEnterpriseRoutes()`.
 *
 * §10.8::5 / §3.5::23 (CH-17): EVERY tenant-specific route mounts under
 * /enterprise/{tenantId}/. The URL is the only tenant selector; tenantId in a
 * header/body/query is rejected, and the URL tenant must match the session
 * token's tid claim (403 on mismatch).
 *
 * Full URL paths (when mounted at /enterprise):
 *
 *   Authentication:
 *     GET  /enterprise/:tenantId/auth/saml/login
 *     POST /enterprise/:tenantId/auth/saml/callback
 *     GET  /enterprise/:tenantId/auth/oidc/authorize
 *     GET  /enterprise/:tenantId/auth/oidc/callback
 *     GET  /enterprise/:tenantId/auth/session
 *     POST /enterprise/:tenantId/auth/logout
 *
 *   OAuth (ID-JAG, RFC 8414 discovery):
 *     POST /enterprise/:tenantId/oauth/token
 *     POST /enterprise/:tenantId/oauth/revoke
 *     GET  /enterprise/:tenantId/oauth/.well-known/oauth-authorization-server
 *
 *   SCIM 2.0 Provisioning:
 *     GET|POST        /enterprise/:tenantId/scim/v2/Users
 *     GET|PUT|PATCH|DELETE /enterprise/:tenantId/scim/v2/Users/:id
 *     GET|POST        /enterprise/:tenantId/scim/v2/Groups
 *     GET|PUT|PATCH|DELETE /enterprise/:tenantId/scim/v2/Groups/:id
 *     GET             /enterprise/:tenantId/scim/v2/ServiceProviderConfig
 *     GET             /enterprise/:tenantId/scim/v2/Schemas
 *     (CHARIOT §10.4::2 root-level fallback for path-stripping IdPs — same
 *      routes, same tenant prefix, /scim/v2 segment omitted:)
 *     GET|POST        /enterprise/:tenantId/Users
 *     GET|PUT|PATCH|DELETE /enterprise/:tenantId/Users/:id
 *     GET|POST        /enterprise/:tenantId/Groups
 *     GET|PUT|PATCH|DELETE /enterprise/:tenantId/Groups/:id
 *     GET             /enterprise/:tenantId/ServiceProviderConfig
 *     GET             /enterprise/:tenantId/Schemas
 *
 *   Admin API:
 *     GET    /enterprise/:tenantId/admin/group-mappings
 *     POST   /enterprise/:tenantId/admin/group-mappings
 *     PUT    /enterprise/:tenantId/admin/group-mappings/:id
 *     DELETE /enterprise/:tenantId/admin/group-mappings/:id
 *     GET    /enterprise/:tenantId/admin/users
 *     GET    /enterprise/:tenantId/admin/users/:id
 *     POST   /enterprise/:tenantId/admin/users/:id/force-logout
 *     GET    /enterprise/:tenantId/admin/groups
 *     GET    /enterprise/:tenantId/admin/audit-logs
 *     GET    /enterprise/:tenantId/admin/tenant
 *     PUT    /enterprise/:tenantId/admin/tenant
 *
 *   Adapter Connections:
 *     GET    /enterprise/:tenantId/adapters/available
 *     GET    /enterprise/:tenantId/adapters/connected
 *     POST   /enterprise/:tenantId/adapters/:id/connect
 *     DELETE /enterprise/:tenantId/adapters/:id/disconnect
 *     POST   /enterprise/:tenantId/adapters/admin/:id/connect-shared
 *     DELETE /enterprise/:tenantId/adapters/admin/:id/disconnect-shared
 *
 * @module iam/routes/index
 */

import { Router, type RequestHandler } from 'express';
import samlRouter from './saml.js';
import oidcRouter from './oidc.js';
import sessionRouter from './session.js';
import mfaRouter from './mfa.js';
import scimRouter from './scim.js';
import adminRouter from './admin.js';
import adminTrustRouter from './admin-trust.js';
import adaptersRouter from './adapters.js';
import oauthRouter from './oauth.js';
import { licenseGateMiddleware, seatLimitMiddleware, requireTlsMiddleware } from '../middleware.js';
import { redisSeatReservationStore } from '../seat-reservation.js';
import type { SeatReservationStore } from '../middleware.js';

export function isValidTenantId(tenantId: string | undefined): tenantId is string {
  return typeof tenantId === 'string' && /^[a-z0-9][a-z0-9-]{1,63}$/.test(tenantId);
}

/**
 * Create and return the top-level enterprise IAM router.
 *
 * License gating is applied internally and mandatorily — the host app
 * cannot mount enterprise routes without license enforcement.
 * Seat limit middleware is applied to auth callback paths (SAML + OIDC)
 * to block token issuance before it happens, not after.
 *
 * Mount this on your Express app, e.g.:
 *   `app.use('/enterprise', createEnterpriseRoutes({ getActiveUserCount }));`
 */
export function createEnterpriseRoutes(options: {
  getActiveUserCount: () => Promise<number>;
  /**
   * Optional override for the seat-reservation store. Defaults to the
   * Redis-backed implementation in seat-reservation.ts which uses the
   * same Redis client bootstrap installs for sessions. Tests inject an
   * in-memory store; single-replica installs that have not yet brought
   * up Redis can pass `null` to fall back to the legacy
   * read-then-check behavior (still strictly better than nothing on
   * one process where the race window is sub-millisecond).
   */
  seatReservationStore?: SeatReservationStore | null;
}): Router {
  const router = Router();

  // ── SOC 2: TLS enforcement in production ───────────────────────────────
  router.use(requireTlsMiddleware());

  // ── Seat limit enforcement on session-issuing paths ────────────────────
  // The seat limit is the single enforcement point for licensing. It checks
  // the license state and active user count together:
  //   - Unlicensed/degraded: allows 1 seat (free tier guarantee)
  //   - Licensed/grace: allows up to totalSeats
  // This replaces the blanket licenseGateMiddleware which incorrectly
  // blocked the single free user from all enterprise routes.
  //
  // The reservation store closes the read-then-check race: every
  // gate-pass atomically claims a 5-second TTL Redis slot that counts
  // toward subsequent activeUsers+reservations comparisons.
  const reservationStore = options.seatReservationStore === undefined
    ? redisSeatReservationStore
    : options.seatReservationStore;
  const seatGate = seatLimitMiddleware(
    options.getActiveUserCount,
    reservationStore ?? undefined,
  );

  // §10.8::5 / §3.5::23 (CH-17) — every tenant-specific route mounts under
  // /enterprise/{tenantId}/. Tenant-isolation middleware: the URL is the ONLY
  // tenant selector; any tenantId supplied via header / body / query is
  // rejected. The token-tid vs URL-tid 403 is enforced inside
  // enterpriseAuthMiddleware (once the token is decoded); SCIM binds its
  // bearer token to the URL tenant via verifyScimToken(req.params.tenantId).
  const requireUrlTenantIsolation: RequestHandler = (req, res, next) => {
    const urlTenantId = Array.isArray(req.params.tenantId) ? undefined : req.params.tenantId;
    if (!isValidTenantId(urlTenantId)) {
      res.status(400).json({ error: 'Invalid tenant ID' });
      return;
    }
    if (
      Object.prototype.hasOwnProperty.call(req.query, 'tenantId') ||
      Object.prototype.hasOwnProperty.call(req.body ?? {}, 'tenantId') ||
      req.headers['x-tenant-id'] !== undefined
    ) {
      res.status(403).json({ error: 'Tenant must be specified by URL' });
      return;
    }
    next();
  };

  const multiUserGate = licenseGateMiddleware();

  // seatGate applies ONLY to POST /token (the issuance path); /revoke and
  // discovery stay reachable under seat pressure.
  const seatGateOnTokenOnly: RequestHandler = (req, res, next) => {
    if (req.method === 'POST' && (req.path === '/token' || req.path === '/token/')) {
      return seatGate(req, res, next);
    }
    next();
  };

  // /:tenantId/auth — SAML + OIDC + session + MFA. Pre-session auth is
  // tenant-scoped by URL; the callback binds the URL tenant to the signed
  // state cookie. Seat limit on the session-issuing callbacks.
  router.use('/:tenantId/auth', requireUrlTenantIsolation, seatGate, samlRouter);
  router.use('/:tenantId/auth', requireUrlTenantIsolation, seatGate, oidcRouter);
  router.use('/:tenantId/auth', requireUrlTenantIsolation, sessionRouter);
  router.use('/:tenantId/auth', requireUrlTenantIsolation, mfaRouter);

  // /:tenantId/oauth — ID-JAG (IETF draft-04) endpoints.
  router.use('/:tenantId/oauth', requireUrlTenantIsolation, licenseGateMiddleware(), seatGateOnTokenOnly, oauthRouter);

  // ── Multi-user-only routes: SCIM, admin, adapters ─────────────────────
  // /:tenantId/scim/v2 — SCIM 2.0 provisioning (tenantId in URL for IdP config)
  router.use('/:tenantId/scim/v2', requireUrlTenantIsolation, multiUserGate, scimRouter);

  // /:tenantId/admin/trust — ID-JAG admin CRUD. Mounted BEFORE the generic
  // /:tenantId/admin so Express matches the more-specific subpath first.
  router.use('/:tenantId/admin/trust', requireUrlTenantIsolation, multiUserGate, adminTrustRouter);

  // /:tenantId/admin — tenant admin API (multi-user only)
  router.use('/:tenantId/admin', requireUrlTenantIsolation, multiUserGate, adminRouter);

  // /:tenantId/adapters — adapter credential management (multi-user only)
  router.use('/:tenantId/adapters', requireUrlTenantIsolation, multiUserGate, adaptersRouter);

  // /:tenantId — CHARIOT §10.4::2 root-level SCIM fallback for path-stripping
  // IdPs that POST directly to /Users instead of /scim/v2/Users. This is
  // "root-level" RELATIVE TO THE TENANT PREFIX (CH-17/§10.8 forbids a route
  // that omits the tenant segment entirely) — /enterprise/{tenantId}/Users,
  // never a bare /Users at the app root. Reuses the identical scimRouter
  // instance and gate chain as the /scim/v2 mount above (same auth, same
  // tenant isolation, same license gate) so both shapes behave identically.
  // Registered LAST: Express tries each router in registration order and
  // only falls through to the next when the current one has no matching
  // route, so every more-specific mount above (auth, oauth, scim/v2,
  // admin/trust, admin, adapters) is tried first and this bare mount only
  // ever serves paths none of them claim (/Users, /Groups,
  // /ServiceProviderConfig, /Schemas) — it cannot shadow any existing route.
  router.use('/:tenantId', requireUrlTenantIsolation, multiUserGate, scimRouter);

  return router;
}

export default createEnterpriseRoutes;
