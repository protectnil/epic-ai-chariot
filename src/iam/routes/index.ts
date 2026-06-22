/**
 * Enterprise IAM Route Index
 *
 * Mounts all sub-routers and exports `createEnterpriseRoutes()`.
 *
 * Full URL paths (when mounted at /enterprise):
 *
 *   Authentication:
 *     GET  /enterprise/auth/saml/login
 *     POST /enterprise/auth/saml/callback
 *     GET  /enterprise/auth/oidc/authorize
 *     GET  /enterprise/auth/oidc/callback
 *     GET  /enterprise/auth/session
 *     POST /enterprise/auth/logout
 *
 *   SCIM 2.0 Provisioning:
 *     GET|POST        /enterprise/:tenantId/scim/v2/Users
 *     GET|PUT|PATCH|DELETE /enterprise/:tenantId/scim/v2/Users/:id
 *     GET|POST        /enterprise/:tenantId/scim/v2/Groups
 *     GET|PUT|PATCH|DELETE /enterprise/:tenantId/scim/v2/Groups/:id
 *     GET             /enterprise/:tenantId/scim/v2/ServiceProviderConfig
 *     GET             /enterprise/:tenantId/scim/v2/Schemas
 *
 *   Admin API:
 *     GET    /enterprise/admin/group-mappings
 *     POST   /enterprise/admin/group-mappings
 *     PUT    /enterprise/admin/group-mappings/:id
 *     DELETE /enterprise/admin/group-mappings/:id
 *     GET    /enterprise/admin/users
 *     GET    /enterprise/admin/users/:id
 *     POST   /enterprise/admin/users/:id/force-logout
 *     GET    /enterprise/admin/groups
 *     GET    /enterprise/admin/audit-logs
 *     GET    /enterprise/admin/tenant
 *     PUT    /enterprise/admin/tenant
 *
 *   Adapter Connections:
 *     GET    /enterprise/adapters/available
 *     GET    /enterprise/adapters/connected
 *     POST   /enterprise/adapters/:id/connect
 *     DELETE /enterprise/adapters/:id/disconnect
 *     POST   /enterprise/adapters/admin/:id/connect-shared
 *     DELETE /enterprise/adapters/admin/:id/disconnect-shared
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

  // /auth — SAML + OIDC + session management
  // Seat limit on auth callbacks prevents creating sessions beyond the limit.
  // Session introspection and logout do not create new sessions — no gate needed.
  router.use('/auth', seatGate, samlRouter);
  router.use('/auth', seatGate, oidcRouter);
  router.use('/auth', sessionRouter);
  router.use('/auth', mfaRouter);

  // /oauth — ID-JAG (IETF draft-04) endpoints. seatGate applies ONLY to
  // POST /token (the issuance path). /revoke and
  // /.well-known/oauth-authorization-server must stay reachable under
  // seat pressure so customers can shed sessions and clients can discover
  // metadata even when the tenant is at capacity. licenseGateMiddleware
  // wraps the whole subtree (a customer whose license lapsed loses
  // exchange + revoke + metadata together).
  const seatGateOnTokenOnly: RequestHandler = (req, res, next) => {
    if (req.method === 'POST' && (req.path === '/token' || req.path === '/token/')) {
      return seatGate(req, res, next);
    }
    next();
  };
  router.use('/oauth', licenseGateMiddleware(), seatGateOnTokenOnly, oauthRouter);

  // ── Multi-user-only routes: SCIM, admin, adapters ─────────────────────
  // These routes manage multiple users/groups/credentials. They are gated
  // by licenseGateMiddleware because they only make sense with a team license.
  // The single free user does not need SCIM provisioning or RBAC admin.

  const multiUserGate = licenseGateMiddleware();
  const tenantIdGate: RequestHandler = (req, res, next) => {
    const tenantId = Array.isArray(req.params.tenantId) ? undefined : req.params.tenantId;
    if (!isValidTenantId(tenantId)) {
      res.status(400).json({ error: 'Invalid tenant ID' });
      return;
    }
    next();
  };

  // /:tenantId/scim/v2 — SCIM 2.0 provisioning (tenantId in URL for IdP config)
  router.use('/:tenantId/scim/v2', tenantIdGate, multiUserGate, scimRouter);

  // Root-level SCIM fallback — Okta's SCIM client strips the path from
  // the Base URL and calls /Users, /Groups directly at the origin root.
  const scimTenantInjector: RequestHandler = (req, _res, next) => {
    if (!req.params.tenantId) {
      req.params.tenantId =
        (req.headers['x-tenant-id'] as string) ||
        process.env.SCIM_DEFAULT_TENANT ||
        '';
    }
    next();
  };
  router.use('/scim/v2', scimTenantInjector, multiUserGate, scimRouter);

  // /admin/trust — ID-JAG admin CRUD (trusted IdPs, scope mappings,
  // OAuth clients). Mounted BEFORE the generic /admin so Express
  // matches the more-specific subpath first. multiUserGate applies
  // — ID-JAG is an enterprise feature.
  router.use('/admin/trust', multiUserGate, adminTrustRouter);

  // /admin — tenant admin API (multi-user only)
  router.use('/admin', multiUserGate, adminRouter);

  // /adapters — adapter credential management (multi-user only)
  router.use('/adapters', multiUserGate, adaptersRouter);

  // Root-level SCIM fallback — MUST be last.
  const scimRootFallback: RequestHandler = (req, res, next) => {
    const scimPaths = ['/Users', '/Groups', '/ServiceProviderConfig', '/Schemas'];
    if (scimPaths.some(p => req.path.startsWith(p))) {
      scimTenantInjector(req, res, () => scimRouter(req, res, next));
    } else {
      next();
    }
  };
  router.use(scimRootFallback);

  return router;
}

export default createEnterpriseRoutes;
