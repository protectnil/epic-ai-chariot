/**
 * IAM — ID-JAG OAuth 2.0 endpoints (Resource Authorization Server).
 *
 * Implements the Resource-AS side of IETF
 * draft-ietf-oauth-identity-assertion-authz-grant-04 §4.4. The wire-level
 * grant at this token endpoint is RFC 7523 JWT Bearer:
 *
 *   POST /token
 *     grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
 *     assertion=<ID-JAG JWT>
 *
 * (NOT RFC 8693 token-exchange — that's the §4.3 IdP-side grant at a
 * different endpoint owned by the IdP Authorization Server. The Resource
 * AS response is the standard RFC 6749 §5.1 token response, not the
 * RFC 8693 §2.2.1 token-exchange response.)
 *
 * Three endpoints under /enterprise/oauth/*:
 *   POST   /token                                  RFC 7523 JWT-Bearer (draft-04 §4.4)
 *   POST   /revoke                                 RFC 7009 token revocation
 *   GET    /.well-known/oauth-authorization-server RFC 8414 AS metadata + §7.2
 *
 * Pipeline (POST /token):
 *   0.  grant-type allowlist  (jwt-bearer canonical; jwt-dpop alias per §9.8.1.2.1)
 *   1.  client authentication  (basic | post | private_key_jwt)
 *   1a. per-IP, per-tenant, per-client_id rate limit
 *   2-11. delegated to id-jag-validator (§4.4.1 processing rules)
 *   13-21. delegated to id-jag-issuer
 *   22. emit `id_jag_token_issued` audit event with auditDetail from issuer
 *
 * There is no `subject_token_type` parameter under §4.4; RFC 7523 does
 * not define one. The assertion arrives in the `assertion` form param.
 *
 * DPoP-bound issuance: if the request carries a `DPoP` proof header AND
 * it verifies per RFC 9449 §4.3, the issued access token is bound to the
 * proof's JWK (cnf.jkt). Resource-server enforcement lives in
 * middleware.ts:enterpriseAuthMiddleware.
 */

import { Router, type Request, type Response } from 'express';
import { importJWK, jwtVerify } from 'jose';

import { log as auditLog } from '../services/audit.js';
import { getByTenantId } from '../services/tenant.js';
import {
  isAuthRateLimited,
  recordAuthFailure,
  isClientRateLimited,
  recordAuthFailureForClient,
  clearClientFailures,
  isIpProbeRateLimited,
  recordIpProbeFailure,
  clearIpProbeFailures,
} from '../services/auth-rate-limit.js';
import {
  validateIdJagAssertion,
  type ClientAuthMethod,
} from '../services/id-jag-validator.js';
import { trustRegistry, jwksPort, listTrustedIssuers } from '../services/idp-trust-registry.js';
import {
  clientRegistry,
  findClient,
  findCandidateTenantIdsForClient,
  verifyClientSecret,
  getClientJwksUri,
  clientViewFromDoc,
} from '../services/oauth-client-registry.js';
import { verifyToken as verifyHashedToken } from '../crypto.js';
import type { OAuthClientView } from '../services/id-jag-validator.js';
import { jtiReplayCache } from '../services/jti-replay-cache.js';
import { issueIdJagToken } from '../services/id-jag-issuer.js';
import {
  verifyDpopProofForTokenEndpoint,
  verifyDpopProofForResource,
} from '../services/dpop.js';
import { verifyToken, revokeAllUserSessions } from '../services/session.js';
import { clientIp, escapeDpopHeaderValue, requestHtu, userAgent } from '../utils/url.js';
import { isValidTenantId } from './index.js';

const router = Router();
export default router;

// CORS for the whole /enterprise/oauth subtree. xaa.dev's Resource AS
// playground UI is browser-driven and fires fetch() at /token from the
// xaa.dev origin; without Access-Control-Allow-* the browser blocks the
// response. Token endpoints are not normally browser-callable in a
// production OAuth flow, but the XAA playground IS a browser-driven test
// harness. client_id+client_secret in the form body remain the real auth
// gate — CORS just lets the browser deliver the request.
router.use((_req: Request, res: Response, next): void => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  // X-Tenant-Id is allowed for the DISCOVERY metadata endpoints, which
  // still resolve tenant from that header (tenantIdFromRequest). /token and
  // /revoke ignore it — they resolve tenant from the authenticated client
  // (resolveClientTenant) — but the header is harmless on those requests and
  // a single subtree-wide allow-list keeps preflight from diverging per path.
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, DPoP, X-Tenant-Id');
  res.setHeader('Access-Control-Expose-Headers', 'WWW-Authenticate');
  res.setHeader('Access-Control-Max-Age', '600');
  next();
});

router.options(/.*/, (_req: Request, res: Response): void => {
  res.status(204).end();
});

// ── Exported helpers (test seams) ────────────────────────────────────────────

/**
 * RFC 8414 §3 discovery-metadata CORS headers — single source of truth.
 * The discovery endpoint is the only AS surface browser-origin clients
 * fetch cross-origin; Allow-Headers MUST include X-Tenant-Id so per-tenant
 * discovery preflight is not rejected (tenantIdFromRequest reads that
 * header). Shared by the in-router OPTIONS preflight, the metadata GET
 * handler, and the canonical root-path mount in setup.ts so the
 * preflight and the actual response can never advertise a divergent
 * allowed-header set.
 */
export function setDiscoveryCors(res: Response): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Tenant-Id');
  res.setHeader('Access-Control-Max-Age', '600');
}

/**
 * RFC 7523 §3 client-assertion claim-binding. The assertion's `iss` AND
 * `sub` MUST equal the authenticated client_id; `jti` is REQUIRED for
 * replay protection. jose validates signature + audience + exp/nbf;
 * this helper covers the remaining spec-mandated claims.
 *
 * Exported so the test suite can verify the claim-binding logic without
 * needing a registered private_key_jwt client + live JWKS endpoint.
 */
export function validateClientAssertionClaims(
  payload: { iss?: unknown; sub?: unknown; jti?: unknown },
  expectedClientId: string,
): { ok: true } | { ok: false; reason: string } {
  if (payload.iss !== expectedClientId) {
    return { ok: false, reason: `client_assertion iss "${String(payload.iss)}" does not match client_id` };
  }
  if (payload.sub !== expectedClientId) {
    return { ok: false, reason: `client_assertion sub "${String(payload.sub)}" does not match client_id` };
  }
  if (typeof payload.jti !== 'string' || payload.jti.length === 0) {
    return { ok: false, reason: 'client_assertion missing required jti claim' };
  }
  return { ok: true };
}

// ── Constants ────────────────────────────────────────────────────────────────

const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
/**
 * draft-04 §9.8.1.2.1 worked example (lines 2426-2432) uses
 * `urn:ietf:params:oauth:grant-type:jwt-dpop` on the cnf-bound + DPoP
 * path. The footnote `[I-D.parecki-oauth-jwt-dpop-grant]` is a
 * referenced draft, not normative — but the worked example is in the
 * draft-04 body and the §9.8.1.2 family of MUSTs is gated on it.
 *
 * Best-of-breed conformance: accept BOTH URNs at /token and advertise
 * both in `grant_types_supported`. Semantics are identical (validator
 * path unchanged); the cnf+DPoP MUSTs at §9.8.1.2.{1,2,3,4} are
 * enforced post-validator regardless of which URN the client used.
 * Accepting the alias does not relax any MUST; rejecting it would
 * break interop with conformant clients that follow the §9.8.1.2.1
 * wire example verbatim.
 */
const GRANT_TYPE_DPOP_ALIAS = 'urn:ietf:params:oauth:grant-type:jwt-dpop';
const ACCEPTED_GRANT_TYPES: readonly string[] = [GRANT_TYPE, GRANT_TYPE_DPOP_ALIAS];
const CLIENT_ASSERTION_TYPE_JWT = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const SUPPORTED_RAR_TYPE = 'chariot.adapter_scope.v1';

// No-existence-oracle invariant: a single constant for every client-credential
// failure (unknown client_id, wrong method, wrong secret, bad assertion) and a
// single constant for every rate-limit 429, so the error_description can never
// distinguish "client unregistered" from "registered, wrong credential", nor
// reveal which rate-limit bucket fired.
const CLIENT_AUTH_FAILED = 'client authentication failed';
// Distinct from CLIENT_AUTH_FAILED: emitted ONLY when no client-auth mechanism
// was presented at all (presented === 0). Returned identically whether the
// (body-supplied) client_id is known or unknown, so it is NOT an existence
// oracle — it reflects the request shape (no credential), which the caller
// already knows. RFC 6749 §5.2 / RFC 7009 §2.1: client auth required → 401.
const CLIENT_AUTH_REQUIRED = 'client authentication required';
// RFC 6749 §5.2: a request that includes two client authentication mechanisms
// simultaneously is malformed (not an authentication failure). Always 400
// invalid_request regardless of credential correctness — the request shape
// itself is invalid before credentials are evaluated. Returned identically
// for known and unknown clients so it is NOT an existence oracle.
const CLIENT_AUTH_MULTI_MECHANISM = 'only one client authentication mechanism may be used per request';

const RATE_LIMITED = 'too many failed attempts';

// RFC 7523 private_key_jwt: pin verification to asymmetric signature
// algorithms. Excludes all HS* (symmetric) algs so a client_assertion header
// cannot force an HMAC verification against asymmetric key material
// (alg-confusion). Defense-in-depth: the jwks-fetched key's kty already
// constrains the usable alg, but the allowlist makes the constraint explicit.
const ASYMMETRIC_CLIENT_ASSERTION_ALGS: readonly string[] = [
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
];

// ── Helpers ──────────────────────────────────────────────────────────────────

function oauthError(
  res: Response,
  status: number,
  error: string,
  description: string,
): void {
  // Observability: every OAuth rejection emits one structured stderr line
  // so nohup-captured logs name which validator gate failed without having
  // to read the HTTP response body. Loki shipping happens via the host
  // forwarder; for now this is the only visible reject trace.
  try {
    const req = (res as unknown as { req?: { ip?: string; method?: string; originalUrl?: string; headers?: Record<string, string | string[] | undefined> } }).req;
    // Only log x-tenant-id when it passes tenant-id validation. JSON.stringify
    // already escapes control chars, but validating bounds the charset/length
    // so an attacker-supplied header cannot bloat or pollute the log value.
    const rawTenant = req?.headers?.['x-tenant-id'];
    const safeTenant = typeof rawTenant === 'string' && isValidTenantId(rawTenant) ? rawTenant : undefined;
    process.stderr.write(JSON.stringify({
      ts: new Date().toISOString(),
      level: 'warn',
      source: 'iam/oauth',
      event: 'oauth_reject',
      status,
      error,
      description,
      ip: req?.ip,
      method: req?.method,
      url: req?.originalUrl,
      tenantId: safeTenant,
    }) + '\n');
  } catch { /* never let logging crash the response */ }
  res.status(status).json({ error, error_description: description });
}

/**
 * Run a rate-limit / tenant infra read. On a backing-store (Mongo) error,
 * respond with an explicit 503 (fail-closed) instead of letting the async
 * throw surface as an opaque 500. Returns null when it handled the error (the
 * caller MUST return) or `{ value }` on success.
 */
async function infraRead<T>(res: Response, fn: () => Promise<T>): Promise<{ value: T } | null> {
  try {
    return { value: await fn() };
  } catch {
    oauthError(res, 503, 'temporarily_unavailable', 'service temporarily unavailable');
    return null;
  }
}

function extractBasicAuth(req: Request): { clientId: string; clientSecret: string } | null {
  const h = req.headers.authorization;
  if (typeof h !== 'string' || !/^Basic\s+/i.test(h)) return null;
  const b64 = h.replace(/^Basic\s+/i, '').trim();
  let decoded: string;
  try {
    decoded = Buffer.from(b64, 'base64').toString('utf-8');
  } catch {
    return null;
  }
  const idx = decoded.indexOf(':');
  if (idx === -1) return null;
  return { clientId: decoded.slice(0, idx), clientSecret: decoded.slice(idx + 1) };
}

interface ClientAuthSuccess {
  clientId: string;
  authMethod: ClientAuthMethod;
  /** OAuthClientView projection threaded to the validator as prefetchedClient. */
  view: OAuthClientView;
}

/**
 * Verify a private_key_jwt client_assertion (RFC 7523) against a specific
 * registration's jwks_uri. Pure boolean — no response/audit/rate-limit side
 * effects — so it serves BOTH the authoritative client-auth path
 * (authenticateClient) AND the silent multi-tenant disambiguation in
 * resolveClientTenant. `htu` is the request's HTTP target URI, used as the
 * required audience of the assertion.
 */
async function verifyClientAssertionJwt(
  jwksUri: string,
  assertion: string,
  clientId: string,
  htu: string,
): Promise<{ jti: string; exp?: number } | null> {
  try {
    const { payload } = await jwtVerify(
      assertion,
      async (protectedHeader) => {
        const alg = typeof protectedHeader.alg === 'string' ? protectedHeader.alg : 'RS256';
        const key = await jwksPort.fetchKey(jwksUri, protectedHeader.kid, alg);
        return 'kty' in (key as object) ? await importJWK(key as never, alg) : (key as never);
      },
      { audience: htu, currentDate: new Date(), algorithms: [...ASYMMETRIC_CLIENT_ASSERTION_ALGS] },
    );
    if (!validateClientAssertionClaims(payload, clientId).ok) return null;
    // jti is validated as a non-empty string by validateClientAssertionClaims.
    // Return it (with exp) so the authoritative caller can enforce single-use
    // replay protection. This helper itself performs NO replay reservation —
    // it is also called in resolveClientTenant's silent disambiguation, where
    // consuming the jti would falsely burn it before authenticateClient runs.
    return { jti: payload.jti as string, exp: typeof payload.exp === 'number' ? payload.exp : undefined };
  } catch {
    return null;
  }
}

/**
 * Authenticate the calling OAuth client. ONE Mongo read fetches the
 * full client document; auth-method-specific verification then runs
 * against the in-memory doc. The projected view is returned so the
 * caller can pass it as prefetchedClient to the validator, avoiding a
 * second findOne on the same row.
 *
 * Supports three RFC 6749 §2.3 methods:
 *   - client_secret_basic  (HTTP Basic Authorization header)
 *   - client_secret_post   (client_id + client_secret in form body)
 *   - private_key_jwt      (client_assertion JWT signed by the client's JWKS key)
 */
async function authenticateClient(
  tenantId: string,
  body: Record<string, unknown>,
  req: Request,
  res: Response,
  ip: string,
): Promise<ClientAuthSuccess | null> {
  const basic = extractBasicAuth(req);
  const post = typeof body.client_id === 'string' && typeof body.client_secret === 'string'
    ? { clientId: body.client_id, clientSecret: body.client_secret }
    : null;
  const jwtBody = typeof body.client_assertion === 'string'
    && body.client_assertion_type === CLIENT_ASSERTION_TYPE_JWT
    && typeof body.client_id === 'string'
    ? { clientId: body.client_id, assertion: body.client_assertion }
    : null;

  // Resolve clientId for the per-client rate-limit CHECK below. Note: the
  // per-client bucket is only CHARGED on a genuine credential-guess
  // (presented === 1 with a wrong secret/assertion). A request that presents
  // zero or multiple credentials does NOT charge it (see the presented!==1
  // branch) — otherwise an attacker spamming `client_id=victim` with no
  // credential could exhaust the victim's lockout bucket (DoS). Those shapes
  // are throttled by the per-IP / IP-probe buckets instead.
  const bodyClientId = typeof body.client_id === 'string' ? body.client_id : '';
  const clientId = basic?.clientId ?? post?.clientId ?? jwtBody?.clientId ?? bodyClientId;

  // Helper closure: record the per-IP+tenant AND per-client failure
  // buckets on every auth-failure path, then write the OAuth error and
  // return null. Both buckets increment so a brute-force attacker
  // rotating either axis is rate-limited by the other.
  const fail = async (
    status: number,
    error: string,
    description: string,
    basicWwwAuth = false,
    chargeClientBucket = true,
  ): Promise<null> => {
    await recordAuthFailure(ip, tenantId);
    if (chargeClientBucket && clientId) await recordAuthFailureForClient(tenantId, clientId);
    if (basicWwwAuth) res.set('WWW-Authenticate', 'Basic realm="chariot-id-jag"');
    oauthError(res, status, error, description);
    return null;
  };

  // No-existence-oracle: any non-singular credential count (zero, or multiple
  // mechanisms) returns the SAME tuple as the unknown-client path — Basic →
  // 401 + WWW-Authenticate, else 400, always CLIENT_AUTH_FAILED. A known
  // client_id reaches authenticateClient (resolved by resolveClientTenant)
  // while an unknown one is rejected before it; if these branches returned a
  // distinct status/description, a no-credential or multi-mechanism probe
  // would distinguish registered from unregistered client_ids.
  const usedBasic = basic !== null;
  const presented = [basic, post, jwtBody].filter(Boolean).length;
  if (presented === 0) {
    // No client authentication attempted at all (RFC 6749 §5.2 / RFC 7009
    // §2.1). 401 client-authentication-required — IDENTICAL to
    // resolveClientTenant's no-credential rejection (rejectUnresolvedClient),
    // so a known vs unknown client_id presenting no credential are
    // indistinguishable (no existence oracle). No bucket charge: a
    // no-credential request is not a guess against any client_id.
    return fail(401, 'invalid_client', CLIENT_AUTH_REQUIRED, false, false);
  }
  if (presented > 1) {
    // Multiple mechanisms — RFC 6749 §5.2: the request is malformed
    // (invalid_request, not invalid_client). Always 400; the caller's request
    // shape itself is invalid before credentials are evaluated, so this is not
    // an authentication failure and not an existence oracle. chargeClientBucket=false:
    // not a credential guess against one client_id, so it MUST NOT charge a
    // victim's per-client lockout bucket (DoS prevention). Per-IP buckets apply.
    return fail(400, 'invalid_request', CLIENT_AUTH_MULTI_MECHANISM, false, false);
  }

  // Per-client rate-limit check — ONLY on the single-credential auth path
  // (presented === 1). A rotating-IP brute-force attacker targeting
  // `client_secret_*` / `private_key_jwt` hits this bucket regardless of
  // source IP. It MUST run AFTER the presented-count branches above: a tripped
  // bucket returns 429, which exists ONLY for a registered client_id, so
  // running it on the presented===0 / multi-mechanism shapes would return 429
  // for a known client while an unknown one (rejected at resolveClientTenant)
  // returns the uniform invalid_client — an existence oracle. The single-
  // credential path is a genuine credential guess where the 429 lockout is the
  // intended behaviour. The bucket is incremented on every failure path below.
  if (clientId) {
    const cl = await infraRead(res, () => isClientRateLimited(tenantId, clientId));
    if (!cl) return null;
    if (cl.value) {
      oauthError(res, 429, 'slow_down', RATE_LIMITED);
      return null;
    }
  }

  // No-existence-oracle invariant: EVERY client-credential failure below —
  // unknown client_id, wrong auth method, wrong secret, bad assertion —
  // returns a byte-identical response per presented method (Basic → 401 +
  // WWW-Authenticate + CLIENT_AUTH_FAILED; post/JWT → 400 + CLIENT_AUTH_FAILED).
  // RFC 6749 §5.2: 401 + WWW-Authenticate only when the caller used Basic.
  const doc = await findClient(tenantId, clientId);
  if (!doc) {
    return basic
      ? fail(401, 'invalid_client', CLIENT_AUTH_FAILED, true)
      : fail(400, 'invalid_client', CLIENT_AUTH_FAILED);
  }

  if (basic) {
    if (doc.authMethod !== 'client_secret_basic' && doc.authMethod !== 'client_secret_post') {
      return fail(401, 'invalid_client', CLIENT_AUTH_FAILED, true);
    }
    if (!doc.clientSecretHash || !verifyHashedToken(basic.clientSecret, doc.clientSecretHash)) {
      return fail(401, 'invalid_client', CLIENT_AUTH_FAILED, true);
    }
    return { clientId, authMethod: 'basic', view: clientViewFromDoc(doc) };
  }
  if (post) {
    if (doc.authMethod !== 'client_secret_basic' && doc.authMethod !== 'client_secret_post') {
      return fail(400, 'invalid_client', CLIENT_AUTH_FAILED);
    }
    if (!doc.clientSecretHash || !verifyHashedToken(post.clientSecret, doc.clientSecretHash)) {
      return fail(400, 'invalid_client', CLIENT_AUTH_FAILED);
    }
    return { clientId, authMethod: 'post', view: clientViewFromDoc(doc) };
  }
  // private_key_jwt — RFC 7523. JWKS fetched via cached jwksPort.
  if (jwtBody) {
    if (doc.authMethod !== 'private_key_jwt' || !doc.jwksUri) {
      return fail(400, 'invalid_client', CLIENT_AUTH_FAILED);
    }
    const verified = await verifyClientAssertionJwt(doc.jwksUri, jwtBody.assertion, clientId, requestHtu(req));
    if (!verified) {
      return fail(400, 'invalid_client', CLIENT_AUTH_FAILED);
    }
    // RFC 7523 §3 + §4(10): the client_assertion jti MUST be single-use, or a
    // captured assertion is replayable until its exp. Reserve it (keyed by
    // client_id, since iss==sub==client_id) for the assertion's remaining
    // lifetime; a repeat presentation fails the uniform client-auth check.
    // This is the ONLY reservation site — resolveClientTenant must not burn it.
    const nowSec = Math.floor(Date.now() / 1000);
    const ttl = verified.exp !== undefined
      ? Math.max(1, Math.min(600, verified.exp - nowSec))
      : 300;
    const reserved = await jtiReplayCache.reserve(clientId, verified.jti, ttl);
    if (!reserved) {
      return fail(400, 'invalid_client', CLIENT_AUTH_FAILED);
    }
    return { clientId, authMethod: 'private_key_jwt', view: clientViewFromDoc(doc) };
  }
  oauthError(res, 400, 'invalid_request', 'unknown client authentication state');
  return null;
}

function tenantIdFromRequest(req: Request): string | null {
  // Resolution order:
  //   1. X-Tenant-Id header (set by the host's tenant-resolution layer)
  //   2. SCIM_DEFAULT_TENANT env var (single-tenant deployments)
  // The token endpoint itself does NOT carry tenantId in the path so the
  // hosting environment must provide it the same way SCIM does.
  const h = req.headers['x-tenant-id'];
  if (typeof h === 'string' && h.length > 0 && isValidTenantId(h)) return h;
  const env = process.env.SCIM_DEFAULT_TENANT;
  if (env && env.length > 0 && isValidTenantId(env)) return env;
  return null;
}

/**
 * Outcome of resolving the Resource-AS tenant from a presented client
 * credential. Three states are distinguished so the caller can react
 * correctly to each — collapsing them into a bare `string | null` is what let
 * the multi-tenant wrong-credential brute-force path (below) escape the
 * per-client lockout bucket:
 *   - resolved          → the tenant whose registration the credential matches.
 *   - unknown           → no usable signal to charge a victim bucket: an
 *                         unknown client_id, OR a multi-tenant client_id with
 *                         NO credential presented (charging here would let a
 *                         no-credential prober exhaust a victim's bucket — the
 *                         same DoS guard as the presented!==1 path).
 *   - wrong-credential  → a multi-tenant client_id WAS presented a credential
 *                         that matched no candidate registration. This is a
 *                         genuine credential guess and MUST charge the
 *                         per-client bucket for every candidate tenant, or a
 *                         rotating-IP attacker brute-forces a shared client_id
 *                         throttled only by the (defeatable) per-IP bucket.
 */
type TenantResolution =
  | { kind: 'resolved'; tenantId: string }
  | { kind: 'unknown' }
  | { kind: 'wrong-credential'; clientId: string; candidates: string[] };

/**
 * Resolve the Resource-AS tenant for a /token, /revoke, or
 * /discovery/issuer-acceptance request from the PRESENTED client credential —
 * never from a request header (a header is attacker-controllable; draft-04
 * §6.2 makes the authenticated client's registration authoritative).
 *
 * draft-04 §6.2 permits the same client_id to be registered in more than one
 * tenant (exercised by eval case 10 cross_tenant_isolation). When it is, the
 * tenant cannot be chosen by client_id alone — it is the tenant whose
 * registration the presented credential authenticates against. The
 * single-candidate path returns `resolved` and lets authenticateClient perform
 * the authoritative verification + per-client bucket charge; only the
 * multi-candidate path verifies here, by a SILENT per-candidate check (no jti
 * reservation, see verifyClientAssertionJwt).
 *
 * Does NOT itself touch any failure bucket — the caller drives bucket charges
 * off the returned `kind` via rejectUnresolvedClient, so the no-existence-
 * oracle response stays uniform across all three states.
 */
async function resolveClientTenant(
  body: Record<string, unknown>,
  req: Request,
): Promise<TenantResolution> {
  const basic = extractBasicAuth(req);
  const clientId = basic?.clientId
    ?? (typeof body.client_id === 'string' ? body.client_id : '');
  if (!clientId) return { kind: 'unknown' };

  const candidates = await findCandidateTenantIdsForClient(clientId);
  if (candidates.length === 0) return { kind: 'unknown' };
  if (candidates.length === 1) return { kind: 'resolved', tenantId: candidates[0] };

  // Multi-tenant client_id — pick the registration the credential matches.
  const presentedSecret = basic?.clientSecret
    ?? (typeof body.client_secret === 'string' ? body.client_secret : undefined);
  const jwtAssertion = typeof body.client_assertion === 'string'
    && body.client_assertion_type === CLIENT_ASSERTION_TYPE_JWT
    ? body.client_assertion
    : undefined;

  for (const tenantId of candidates) {
    if (presentedSecret !== undefined) {
      if (await verifyClientSecret(tenantId, clientId, presentedSecret)) {
        return { kind: 'resolved', tenantId };
      }
    } else if (jwtAssertion !== undefined) {
      const jwksUri = await getClientJwksUri(tenantId, clientId);
      // Signature/claims check only — NO jti reservation here (this is the
      // silent disambiguation pass; authenticateClient does the authoritative
      // reservation so the jti is consumed exactly once).
      if (jwksUri && (await verifyClientAssertionJwt(jwksUri, jwtAssertion, clientId, requestHtu(req))) !== null) {
        return { kind: 'resolved', tenantId };
      }
    }
  }

  // A credential was presented against a known (multi-tenant) client_id but
  // matched no registration → genuine credential guess; charge each candidate.
  // No credential presented → no victim bucket to charge (DoS guard).
  if (presentedSecret !== undefined || jwtAssertion !== undefined) {
    return { kind: 'wrong-credential', clientId, candidates };
  }
  return { kind: 'unknown' };
}

/**
 * Surface a uniform invalid_client for a /token, /revoke, or discovery request
 * whose client could not be resolved to a tenant, and charge the appropriate
 * failure buckets. The HTTP response is byte-identical across both non-resolved
 * states (no existence oracle); only the side-effect bucket charges differ:
 *   - always: per-IP probe bucket (enumeration throttle).
 *   - wrong-credential only: per-client bucket for each candidate tenant
 *     (multi-tenant brute-force throttle — review #3).
 * RFC 6749 §5.2: 401 + WWW-Authenticate only when the caller used Basic.
 */
async function rejectUnresolvedClient(
  req: Request,
  res: Response,
  ip: string,
  resolution: { kind: 'unknown' } | { kind: 'wrong-credential'; clientId: string; candidates: string[] },
): Promise<void> {
  const basic = extractBasicAuth(req);
  // Mirror authenticateClient's credential-count semantics so the known-client
  // (resolved → authenticateClient) and unknown-client (here) rejections are
  // byte-identical for every request shape — no existence oracle.
  const body = (req.body ?? {}) as Record<string, unknown>;
  const post = typeof body.client_id === 'string' && typeof body.client_secret === 'string';
  const jwt = typeof body.client_assertion === 'string'
    && body.client_assertion_type === CLIENT_ASSERTION_TYPE_JWT
    && typeof body.client_id === 'string';
  const presented = [basic !== null, post, jwt].filter(Boolean).length;

  // Compute credential count BEFORE bucket charges: malformed requests
  // (presented===0 or presented>1) must not charge per-client buckets
  // or DoS the candidates' lockout counters. Only the IP-probe bucket
  // is charged for multi-mechanism requests (DoS-resistant per-IP
  // throttle that does not reveal client registration state).
  if (presented === 0) {
    // No client authentication attempted. Charge the IP probe bucket (enumerate
    // throttle for unauthenticated probes) but NOT the per-client bucket —
    // no credential was supplied so there is no victim client to protect.
    await recordIpProbeFailure(ip);
    oauthError(res, 401, 'invalid_client', CLIENT_AUTH_REQUIRED);
    return;
  }
  if (presented > 1) {
    // RFC 6749 §5.2: multiple mechanisms = malformed request → 400 invalid_request.
    // Charge only the per-IP bucket (not per-client), so a rotating-credential
    // attacker cannot DoS a victim tenant's lockout counter via malformed requests.
    await recordIpProbeFailure(ip);
    oauthError(res, 400, 'invalid_request', CLIENT_AUTH_MULTI_MECHANISM);
    return;
  }

  // Single-mechanism request: charge both IP-probe and per-client buckets.
  // Per-client charge: mirrors authenticateClient's single-credential failure
  // side effects so brute-force via unknown-client resolves as wrong-credential.
  await recordIpProbeFailure(ip);
  if (resolution.kind === 'wrong-credential') {
    for (const tenantId of resolution.candidates) {
      await recordAuthFailureForClient(tenantId, resolution.clientId);
    }
  }
  if (basic) res.set('WWW-Authenticate', 'Basic realm="chariot-id-jag"');
  oauthError(res, basic ? 401 : 400, 'invalid_client', CLIENT_AUTH_FAILED);
}

// ── POST /token ──────────────────────────────────────────────────────────────

router.post('/token', async (req: Request, res: Response): Promise<void> => {
  const ip = clientIp(req);
  const ua = userAgent(req);
  const body = (req.body ?? {}) as Record<string, unknown>;
  // Per-IP enumeration throttle BEFORE client resolution: no tenant bucket
  // exists yet, so this is the only thing that rate-limits an attacker
  // probing for valid client_ids.
  const probe = await infraRead(res, () => isIpProbeRateLimited(ip));
  if (!probe) return;
  if (probe.value) {
    oauthError(res, 429, 'slow_down', RATE_LIMITED);
    return;
  }
  // draft-04 §6.2: the authoritative Resource-AS tenant is the tenant whose
  // client registration the presented credential authenticates against —
  // NOT a caller-supplied X-Tenant-Id header (attacker-controllable).
  // resolveClientTenant disambiguates a client_id shared across tenants.
  // resolveClientTenant performs Mongo reads (candidate lookup + per-candidate
  // credential verification); wrap in infraRead so a backing-store blip during
  // disambiguation fails closed as 503, not an opaque 500 (review #1).
  const rt = await infraRead(res, () => resolveClientTenant(body, req));
  if (!rt) return;
  const resolution = rt.value;
  if (resolution.kind !== 'resolved') {
    await rejectUnresolvedClient(req, res, ip, resolution);
    return;
  }
  const tenantId = resolution.tenantId;
  // E2 — tenant fetch + rate-limit check are independent Mongo reads.
  const tl = await infraRead(res, () => Promise.all([
    getByTenantId(tenantId),
    isAuthRateLimited(ip, tenantId),
  ]));
  if (!tl) return;
  const [tenant, limited] = tl.value;
  if (!tenant) {
    oauthError(res, 400, 'invalid_request', 'unknown tenant');
    return;
  }
  if (limited) {
    oauthError(res, 429, 'slow_down', RATE_LIMITED);
    return;
  }

  // Step 0 — grant_type allowlist (draft-04 §4.4 + RFC 7523).
  // Accepts the canonical `jwt-bearer` URN and the §9.8.1.2.1 worked-
  // example alias `jwt-dpop`. See ACCEPTED_GRANT_TYPES comment for
  // why both must be accepted.
  if (typeof body.grant_type !== 'string' || !ACCEPTED_GRANT_TYPES.includes(body.grant_type)) {
    oauthError(
      res,
      400,
      'unsupported_grant_type',
      `grant_type must be one of: ${ACCEPTED_GRANT_TYPES.join(', ')}`,
    );
    return;
  }
  if (typeof body.assertion !== 'string' || body.assertion.length === 0) {
    oauthError(res, 400, 'invalid_request', 'assertion required');
    return;
  }

  // Step 1 — client authentication. authenticateClient handles the
  // per-client rate-limit check itself (before any auth-method work) and
  // increments the counter on every failure path, so an attacker brute-
  // forcing client_secret_* / private_key_jwt cannot bypass the bucket
  // by churning IPs.
  const clientAuth = await authenticateClient(tenantId, body, req, res, ip);
  if (!clientAuth) return;
  // A real client authenticated from this IP — it is not a prober. Clear the
  // per-IP probe bucket so a shared-NAT IP is not left blocked by earlier
  // unknown-client probes once a legitimate client succeeds.
  await clearIpProbeFailures(ip);

  // Optional DPoP proof on issuance (RFC 9449 §5).
  let dpopJkt: string | undefined;
  const dpopHeader = typeof req.headers.dpop === 'string' ? req.headers.dpop : undefined;
  if (dpopHeader) {
    const proof = await verifyDpopProofForTokenEndpoint({
      proof: dpopHeader,
      htm: 'POST',
      htu: requestHtu(req),
      jtiCache: jtiReplayCache,
    });
    if (!proof.ok) {
      // Per-client + per-IP buckets count DPoP-proof failures too —
      // a malformed proof from a valid client is still a credential-
      // misuse signal worth rate-limiting.
      await recordAuthFailure(ip, tenantId);
      await recordAuthFailureForClient(tenantId, clientAuth.clientId);
      await auditLog(tenantId, 'id_jag_assertion_rejected', {
        actorId: clientAuth.clientId,
        actorEmail: '',
        targetType: 'user',
        targetId: clientAuth.clientId,
        detail: { code: 'invalid_dpop_proof', reason: proof.reason, ip, spec_section: 'draft-04 §9.8.1.2 / RFC 9449' },
        ip,
        userAgent: ua,
      });
      // draft-04 §9.8.1.2.2 worked example (lines 2469-2476): the
      // Resource AS token-endpoint DPoP-proof failure response is
      // HTTP 400 + Cache-Control: no-store + JSON body
      // {error:'invalid_grant', error_description:...}. NO
      // WWW-Authenticate header — that header's DPoP scheme is
      // RFC 9449 §7.1 territory which scopes to RESOURCE SERVER 401
      // responses, not AS token-endpoint 400 responses. The body's
      // error_description uses the sanitised reason so an attacker-
      // controlled segment of `proof.reason` cannot inject
      // CR/LF/quote/backslash. Cache-Control: no-store prevents
      // negative-response caching of the 400 by upstream proxies.
      const safeReason = escapeDpopHeaderValue(proof.reason);
      res
        .status(400)
        .set('Cache-Control', 'no-store')
        .json({ error: 'invalid_grant', error_description: safeReason });
      return;
    }
    dpopJkt = proof.jkt;
  }

  // Steps 2-11 — validator. prefetchedClient (loaded by authenticateClient)
  // skips the validator's clientRegistry.getClient round-trip per E4.
  const validated = await validateIdJagAssertion({
    assertion: body.assertion,
    authenticatedClientId: clientAuth.clientId,
    authMethod: clientAuth.authMethod,
    tenantId,
    trustRegistry,
    clientRegistry,
    jtiCache: jtiReplayCache,
    jwks: jwksPort,
    prefetchedClient: clientAuth.view,
  });

  if (!validated.ok) {
    await recordAuthFailure(ip, tenantId);
    await recordAuthFailureForClient(tenantId, clientAuth.clientId);
    await auditLog(tenantId, 'id_jag_assertion_rejected', {
      actorId: clientAuth.clientId,
      actorEmail: '',
      targetType: 'user',
      targetId: clientAuth.clientId,
      detail: {
        code: validated.code,
        step: validated.step,
        reason: validated.reason,
        ip,
        ...(validated.specSection !== undefined ? { spec_section: validated.specSection } : {}),
      },
      ip,
      userAgent: ua,
    });
    oauthError(res, validated.status, validated.code, validated.reason);
    return;
  }

  // NOTE: draft-04 §6.4 ("Tenant Context in Token Exchange") binds the
  // tenant identifier in the ID-JAG at *issuance* time, and is enforced
  // by the IdP Authorization Server — NOT by the Resource Authorization
  // Server at the §4.4 access-token-request endpoint this route serves.
  // §4.4.1 lists the RAS's processing rules (typ, aud==RAS-issuer,
  // client_id continuity, sub_id format, resource) and imposes no
  // aud_tenant==client-tenant check. aud_tenant is a subject-keying
  // dimension per §3.1 (combination aud+aud_tenant+aud_sub MUST be unique
  // within the RAS) and is handled in id-jag-validator/id-jag-issuer.
  // A §6.4 gate belongs in a future IdP token-exchange endpoint, if added.

  // draft-04 §9.8.1.2 proof-of-possession enforcement at the AS token
  // endpoint. The validator surfaces the assertion's `cnf` claim; the
  // route enforces the four cases:
  //   §9.8.1.2.1: cnf present + DPoP proof present → MUST compare the
  //               proof's JWK SHA-256 thumbprint to cnf.jkt. Mismatch
  //               → invalid_grant.
  //   §9.8.1.2.2: cnf present + DPoP proof absent → MUST reject with
  //               invalid_grant "Proof of possession required for this
  //               authorization grant".
  //   §9.8.1.2.3: cnf absent + DPoP proof present → continue; issuer
  //               binds the access token to the proof's key.
  //   §9.8.1.2.4: cnf absent + DPoP proof absent → continue; Bearer.
  const assertionCnfJkt = typeof validated.cnf?.jkt === 'string' ? validated.cnf.jkt : undefined;
  if (assertionCnfJkt !== undefined) {
    const rejectCnf = async (reason: string): Promise<void> => {
      await recordAuthFailure(ip, tenantId);
      await recordAuthFailureForClient(tenantId, clientAuth.clientId);
      await auditLog(tenantId, 'id_jag_assertion_rejected', {
        actorId: clientAuth.clientId,
        actorEmail: '',
        targetType: 'user',
        targetId: validated.sub,
        detail: { code: 'invalid_grant', step: 12, reason, ip, spec_section: '§9.8.1.2' },
        ip,
        userAgent: ua,
      });
      res
        .status(400)
        .set('Cache-Control', 'no-store')
        .json({ error: 'invalid_grant', error_description: reason });
    };
    if (dpopJkt === undefined) {
      // §9.8.1.2.2 — spec example wording.
      await rejectCnf('Proof of possession required for this authorization grant');
      return;
    }
    if (dpopJkt !== assertionCnfJkt) {
      // §9.8.1.2.1 step 4: "Compare the two thumbprints. They MUST match exactly."
      await rejectCnf('DPoP proof thumbprint does not match assertion cnf.jkt');
      return;
    }
  }

  // draft-04 §9.8.1.2.4: cnf absent + DPoP proof absent. Default is MAY
  // issue a Bearer token. When the Resource AS tenant is configured to
  // require sender-constrained tokens, an unconstrained grant MUST be
  // rejected invalid_grant. dpopJkt is set only when a valid DPoP proof
  // was presented; assertionCnfJkt only when the assertion carried cnf —
  // both undefined is the unconstrained case this gate governs.
  if (
    assertionCnfJkt === undefined
    && dpopJkt === undefined
    && tenant.settings?.requireSenderConstrainedTokens === true
  ) {
    await recordAuthFailure(ip, tenantId);
    await recordAuthFailureForClient(tenantId, clientAuth.clientId);
    await auditLog(tenantId, 'id_jag_assertion_rejected', {
      actorId: clientAuth.clientId,
      actorEmail: '',
      targetType: 'user',
      targetId: validated.sub,
      detail: {
        code: 'invalid_grant',
        reason: 'sender-constrained (DPoP) token required by Resource AS policy',
        ip,
        spec_section: 'draft-04 §9.8.1.2.4',
      },
      ip,
      userAgent: ua,
    });
    oauthError(
      res,
      400,
      'invalid_grant',
      'this Resource Authorization Server requires a sender-constrained (DPoP) token; present a DPoP proof (draft-04 §9.8.1.2.4)',
    );
    return;
  }

  // Audit `assertion_received` AFTER validation passes so we don't write
  // for malformed / replayed assertions that don't decode cleanly.
  await auditLog(tenantId, 'id_jag_assertion_received', {
    actorId: clientAuth.clientId,
    actorEmail: '',
    targetType: 'user',
    targetId: validated.sub,
    detail: {
      iss: validated.iss,
      jti: validated.jti,
      sub: validated.sub,
      sub_id: validated.subId,
      client_id: clientAuth.clientId,
      ip,
    },
    ip,
    userAgent: ua,
  });

  // Steps 13-21 — issuer.
  // RFC 8707 §2: `resource` MAY be a single string OR an array of
  // strings (Express qs delivers repeated form-body `resource=` keys
  // as an array; application/json bodies preserve native arrays).
  // Both shapes MUST be honoured; a scalar-only check silently
  // dropped the array form and let the JWT-asserted wider resource
  // claim win even when the client's form body intended narrower.
  let requestedResource: string | string[] | undefined;
  if (typeof body.resource === 'string') {
    requestedResource = body.resource;
  } else if (Array.isArray(body.resource) && body.resource.every((v) => typeof v === 'string')) {
    requestedResource = body.resource as string[];
  } else if (body.resource !== undefined) {
    oauthError(res, 400, 'invalid_target', 'resource must be a URI string or array of URI strings (RFC 8707 §2)');
    return;
  }
  // RFC 9396 authorization_details may arrive as a JSON string (form
  // body) or as a pre-parsed array (application/json body, Express
  // body-parser delivers the typed value). Both must be accepted; a
  // string-only check silently drops the JSON-array form and would
  // downgrade the issued scope.
  let requestedAuthorizationDetails: unknown[] | undefined;
  if (typeof body.authorization_details === 'string') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.authorization_details);
    } catch {
      oauthError(res, 400, 'invalid_authorization_details', 'authorization_details is not valid JSON');
      return;
    }
    if (!Array.isArray(parsed)) {
      oauthError(res, 400, 'invalid_authorization_details', 'authorization_details must be a JSON array');
      return;
    }
    requestedAuthorizationDetails = parsed;
  } else if (Array.isArray(body.authorization_details)) {
    requestedAuthorizationDetails = body.authorization_details;
  } else if (body.authorization_details !== undefined) {
    oauthError(res, 400, 'invalid_authorization_details', 'authorization_details must be a JSON array or its JSON-string encoding');
    return;
  }
  const issued = await issueIdJagToken({
    validated,
    tenant,
    requestedResource,
    requestedAuthorizationDetails,
    dpopJkt,
  });
  if (!issued.ok) {
    await recordAuthFailure(ip, tenantId);
    await recordAuthFailureForClient(tenantId, clientAuth.clientId);
    await auditLog(tenantId, 'id_jag_assertion_rejected', {
      actorId: clientAuth.clientId,
      actorEmail: '',
      targetType: 'user',
      targetId: validated.sub,
      detail: {
        code: issued.code,
        reason: issued.reason,
        ip,
        ...(issued.specSection !== undefined ? { spec_section: issued.specSection } : {}),
      },
      ip,
      userAgent: ua,
    });
    oauthError(res, issued.status, issued.code, issued.reason);
    return;
  }

  // H2 — successful issuance clears the per-client rate-limit counter so a
  // legitimate client that accrued failures during a bad deployment is not
  // locked out for the full TTL window once it starts succeeding.
  await clearClientFailures(tenantId, clientAuth.clientId);

  // Step 22 — audit successful issuance.
  await auditLog(tenantId, 'id_jag_token_issued', {
    actorId: clientAuth.clientId,
    actorEmail: issued.user.email,
    targetType: 'user',
    targetId: String(issued.user._id),
    detail: issued.auditDetail,
    ip,
    userAgent: ua,
  });

  // draft-04 §4.4.2: the Resource AS responds with a standard RFC 6749
  // §5.1 OAuth 2.0 Token Response — token_type / access_token /
  // expires_in / scope. No `issued_token_type` (that field is
  // RFC 8693 §2.2.1, which is the IdP-side token-exchange response).
  const response: Record<string, unknown> = {
    access_token: issued.access_token,
    token_type: issued.token_type,
    expires_in: issued.expires_in,
  };
  if (issued.scope !== undefined) response.scope = issued.scope;
  if (issued.resource !== undefined) response.resource = issued.resource;
  if (issued.authorization_details !== undefined) response.authorization_details = issued.authorization_details;

  // RFC 6749 §5.1 + draft-04 §4.4.2: token response MUST set both
  // Cache-Control: no-store AND Pragma: no-cache. The Pragma header
  // defends against HTTP/1.0 intermediaries that ignore Cache-Control
  // and would otherwise cache an access_token for cross-client reuse.
  res
    .status(200)
    .set('Cache-Control', 'no-store')
    .set('Pragma', 'no-cache')
    .json(response);
});

// ── POST /revoke ─────────────────────────────────────────────────────────────

router.post('/revoke', async (req: Request, res: Response): Promise<void> => {
  const ip = clientIp(req);
  const ua = userAgent(req);
  const body = (req.body ?? {}) as Record<string, unknown>;

  // Tenant resolved from the authenticated client (draft-04 §6.2), never a
  // request header — consistent with /token. Per-IP probe throttle first.
  const probe = await infraRead(res, () => isIpProbeRateLimited(ip));
  if (!probe) return;
  if (probe.value) {
    oauthError(res, 429, 'slow_down', RATE_LIMITED);
    return;
  }
  // Fail closed (503) on a Mongo blip during disambiguation — see /token (review #1).
  const rt = await infraRead(res, () => resolveClientTenant(body, req));
  if (!rt) return;
  const resolution = rt.value;
  if (resolution.kind !== 'resolved') {
    await rejectUnresolvedClient(req, res, ip, resolution);
    return;
  }
  const tenantId = resolution.tenantId;

  // Client authentication is required (RFC 7009 §2.1).
  const clientAuth = await authenticateClient(tenantId, body, req, res, ip);
  if (!clientAuth) return;
  // Real client authenticated from this IP — clear the per-IP probe bucket
  // (shared-NAT recovery), symmetric with /token.
  await clearIpProbeFailures(ip);

  const token = typeof body.token === 'string' ? body.token : '';
  if (!token) {
    // RFC 7009 §2.2: respond 200 even if token is missing/unknown to avoid
    // an existence oracle.
    res.status(200).end();
    return;
  }

  const payload = await verifyToken(token);
  if (!payload) {
    res.status(200).end();
    return;
  }

  // M2 — cross-tenant revocation guard. A client authenticated for tenant-A
  // presenting a token issued to tenant-B must not be able to revoke that
  // token. Respond 200 per RFC 7009 §2.2 to avoid an existence oracle, but
  // audit the attempt against the request tenant for forensic visibility.
  if (payload.tenantId !== tenantId) {
    await auditLog(tenantId, 'id_jag_assertion_rejected', {
      actorId: clientAuth.clientId,
      actorEmail: '',
      targetType: 'user',
      targetId: payload.userId,
      detail: {
        code: 'cross_tenant_revoke_blocked',
        token_tenant: payload.tenantId,
        request_tenant: tenantId,
        ip,
      },
      ip,
      userAgent: ua,
    });
    res.status(200).end();
    return;
  }

  // DPoP-bound revocation: when the token has cnf.jkt, the revoke
  // request MUST carry a fresh DPoP proof in the `DPoP` header bound to
  // the same key with `ath` matching the token. The client authenticates
  // via the registered method (Basic / post / private_key_jwt) in the
  // Authorization header / body — so the Authorization header is for
  // CLIENT auth, NOT a DPoP scheme tag. RFC 9449 carries the proof in
  // the DPoP header regardless of the client-auth method.
  if (payload.cnf?.jkt !== undefined) {
    const auditRevokeDpopFailure = async (reason: string): Promise<void> => {
      await recordAuthFailure(ip, tenantId);
      await recordAuthFailureForClient(tenantId, clientAuth.clientId);
      await auditLog(tenantId, 'id_jag_assertion_rejected', {
        actorId: clientAuth.clientId,
        actorEmail: '',
        targetType: 'user',
        targetId: payload.userId,
        detail: { code: 'dpop_revoke_failed', reason, ip },
        ip,
        userAgent: ua,
      });
    };
    const dpopProof = typeof req.headers.dpop === 'string' ? req.headers.dpop : '';
    if (!dpopProof) {
      await auditRevokeDpopFailure('DPoP-bound token requires DPoP header on revoke');
      res
        .status(401)
        .set('WWW-Authenticate', 'DPoP error="invalid_token", error_description="DPoP-bound token requires DPoP header on revoke"')
        .json({ error: 'invalid_token', error_description: 'DPoP-bound token requires DPoP header on revoke' });
      return;
    }
    const proof = await verifyDpopProofForResource({
      proof: dpopProof,
      htm: 'POST',
      htu: requestHtu(req),
      accessToken: token,
      expectedJkt: payload.cnf.jkt,
      jtiCache: jtiReplayCache,
    });
    if (!proof.ok) {
      await auditRevokeDpopFailure(proof.reason);
      // Phase 0.1 R4: share `escapeDpopHeaderValue` with /token and
      // middleware.ts so all three DPoP-failure surfaces sanitise
      // identically. /revoke retains 401 + `invalid_token` because
      // RFC 7009 §2.2 governs revoke responses for sender-constrained
      // tokens at this surface (distinct from /token, which is the
      // ID-JAG redemption per draft-04 §9.8.1.2).
      const safeReason = escapeDpopHeaderValue(proof.reason);
      res
        .status(401)
        .set('WWW-Authenticate', `DPoP error="invalid_token", error_description="${safeReason}"`)
        .json({ error: 'invalid_token', error_description: safeReason });
      return;
    }
  }

  // Revoke by bumping the user's revocation counter (existing pattern
  // used by force-logout). This invalidates every session for that user
  // including the one being revoked.
  await revokeAllUserSessions(payload.tenantId, payload.userId);

  await auditLog(tenantId, 'id_jag_token_revoked', {
    actorId: clientAuth.clientId,
    actorEmail: '',
    targetType: 'user',
    targetId: payload.userId,
    detail: { jti: payload.jti, dpop_bound: payload.cnf !== undefined },
    ip,
    userAgent: ua,
  });

  res.status(200).end();
});

// ── POST /discovery/issuer-acceptance ───────────────────────────────────────
//
// draft-04 §9.4 ¶3: "Resource Authorization Servers MAY provide a
// protected discovery mechanism by which an authenticated client can
// determine whether an Identity Assertion JWT Authorization Grant from
// a particular issuer would be accepted for that client. If such a
// mechanism is provided, the Resource Authorization Server MUST require
// client authentication before disclosing issuer-specific acceptance
// information. The response MUST be specific to the authenticated
// client and MAY also be scoped by tenant, resource, or other local
// policy context."
//
// Client auth uses the same authenticateClient() helper as /token.
// Method is POST (carries form-body / client_assertion); response is
// JSON with the client-specific accepted-issuer list intersected with
// the client's registered allowedIssuers.
router.post('/discovery/issuer-acceptance', async (req: Request, res: Response): Promise<void> => {
  const ip = clientIp(req);
  const body = (req.body ?? {}) as Record<string, unknown>;
  // Tenant resolved from the authenticated client (draft-04 §6.2), never a
  // request header — consistent with /token & /revoke. Resolving from an
  // attacker-controlled X-Tenant-Id here would be a tenant-existence oracle
  // and a cross-tenant rate-limit-poisoning surface. Per-IP probe throttle
  // first (symmetric with /token's enumeration gate).
  const probe = await infraRead(res, () => isIpProbeRateLimited(ip));
  if (!probe) return;
  if (probe.value) {
    oauthError(res, 429, 'slow_down', RATE_LIMITED);
    return;
  }
  // Fail closed (503) on a Mongo blip during disambiguation — see /token (review #1).
  const rt = await infraRead(res, () => resolveClientTenant(body, req));
  if (!rt) return;
  const resolution = rt.value;
  if (resolution.kind !== 'resolved') {
    await rejectUnresolvedClient(req, res, ip, resolution);
    return;
  }
  const tenantId = resolution.tenantId;
  const tl = await infraRead(res, () => Promise.all([
    getByTenantId(tenantId),
    isAuthRateLimited(ip, tenantId),
  ]));
  if (!tl) return;
  const [tenant, limited] = tl.value;
  if (!tenant) {
    oauthError(res, 400, 'invalid_request', 'unknown tenant');
    return;
  }
  if (limited) {
    oauthError(res, 429, 'slow_down', RATE_LIMITED);
    return;
  }
  const clientAuth = await authenticateClient(tenantId, body, req, res, ip);
  if (!clientAuth) return;
  await clearIpProbeFailures(ip);
  const allTrusted = await listTrustedIssuers(tenantId);
  const clientAllowedIssuers = new Set(clientAuth.view.allowedIssuers);
  const acceptedIssuers = allTrusted
    .filter((t) => clientAllowedIssuers.has(t.issuer))
    .map((t) => ({
      issuer: t.issuer,
      audience: t.audience,
      id_jag_signing_alg_values_supported: t.allowedAlgorithms,
      ...(t.requireSamlNameIdSubId ? { saml_nameid_required: true } : {}),
      ...(t.requiresTenantContext ? { tenant_required: true } : {}),
    }));
  // Response is client-specific (filtered by allowedIssuers) and the
  // metadata does not enumerate cross-client trust topology — closes
  // §9.4 ¶1's disclosure prohibition.
  res.set('Cache-Control', 'no-store').json({
    client_id: clientAuth.clientId,
    tenant_id: tenantId,
    grant_profile: 'urn:ietf:params:oauth:grant-profile:id-jag',
    accepted_issuers: acceptedIssuers,
  });
});

// ── GET /.well-known/oauth-authorization-server ──────────────────────────────
//
// CORS: RFC 8414 metadata is a public discovery document by design. Partner
// UIs (xaa.dev's Register Resource form, Okta's playground, any other
// browser-based OAuth client) fetch it cross-origin; same-origin policy
// blocks the response without Access-Control-Allow-*. The payload exposes
// no secrets — it advertises endpoint URLs, grant types, and algorithm
// allowlists that the same browser would learn from any successful token
// exchange. `*` origin is the standard treatment for RFC 8414 metadata.
// Only the discovery endpoint gets CORS; /token + /revoke remain
// non-CORS-permitted (server-to-server only).

router.options('/.well-known/oauth-authorization-server', (_req: Request, res: Response): void => {
  setDiscoveryCors(res);
  res.status(204).end();
});

/**
 * RFC 8414 §3 OAuth 2.0 Authorization Server Metadata handler.
 *
 * Exported so setup.ts can mount it at the canonical root path
 * `/.well-known/oauth-authorization-server` AND inside the
 * `/enterprise/oauth` router. RFC 8414 §3 requires the metadata to be
 * reachable at `https://<issuer>/.well-known/oauth-authorization-server`
 * (no sub-path); without the root mount, partner conformance tooling
 * that follows the spec literally gets 404 unless an external rewrite
 * (nginx, ingress) translates the path.
 */
export const oauthAuthorizationServerMetadataHandler = (req: Request, res: Response): void => {
  setDiscoveryCors(res);
  // RFC 8414 §3 requires the metadata `issuer` value to match the AS's
  // server-configured identifier, NOT a client-supplied header. Pinning
  // to req.headers.host enables host-header injection: an attacker GET
  // with `Host: evil.example.com` causes the response to advertise
  // token_endpoint / revocation_endpoint / issuer on evil.example.com.
  // Resolution order:
  //   1. CHARIOT_PUBLIC_BASE_URL env var (e.g. https://chariot.example.com)
  //      — the configured public origin; used in all production deploys.
  //   2. NODE_ENV !== 'production' fallback to req.protocol+host so the
  //      eval framework and dev workflows that bind to dynamic loopback
  //      ports keep working without per-test env-var plumbing.
  //   3. Refuse to emit metadata in production when neither is set, so
  //      a deploy that forgets the env var fails closed rather than
  //      leaking attacker-controlled URLs.
  const configured = process.env.CHARIOT_PUBLIC_BASE_URL;
  let base: string;
  if (configured && /^https?:\/\/.+/.test(configured)) {
    base = configured.replace(/\/+$/, '');
  } else if (process.env.NODE_ENV !== 'production') {
    const proto = (req.headers['x-forwarded-proto'] as string) ?? req.protocol;
    const host = req.headers.host ?? '';
    base = `${proto}://${host}`;
  } else {
    res.status(500).json({
      error: 'metadata_unconfigured',
      error_description: 'CHARIOT_PUBLIC_BASE_URL must be set in production',
    });
    return;
  }
  // RFC 8414 §3 mandates the discovery `issuer` value EXACTLY identify
  // the AS that issues tokens with matching `iss` claims. We MUST NOT
  // emit a phantom 'default' tenant when none is resolvable from the
  // request — a partner that follows the issuer URL for further
  // verification would fail iss-claim comparison against any real
  // tenant's tokens. Refuse the request instead and tell the client to
  // supply x-tenant-id (or set SCIM_DEFAULT_TENANT in single-tenant
  // deployments).
  const tenantId = tenantIdFromRequest(req);
  if (tenantId === null) {
    res.status(400).json({
      error: 'tenant_unspecified',
      error_description: 'discovery requires x-tenant-id header (or SCIM_DEFAULT_TENANT env in single-tenant mode)',
    });
    return;
  }
  // CHARIOT_PUBLIC_OAUTH_BASE is the public-facing path prefix for OAuth
  // endpoints (e.g. "/oauth" or "https://auth.example.com/oauth"). nginx
  // maps public /oauth/* → backend /enterprise/oauth/* so RFC 8414 clients
  // that follow the discovered endpoints hit routes that actually exist.
  // Default "/oauth" matches the standard nginx reverse-proxy setup.
  // NEVER emit /enterprise/oauth/* here — that is an internal backend path
  // not reachable by external RFC 8414 clients.
  // Blank/empty CHARIOT_PUBLIC_OAUTH_BASE must NOT silently fall back to the
  // bare origin — that would emit /token as the token_endpoint, which is
  // wrong. Coerce blank back to the /oauth default.
  const rawOauthBase = (process.env.CHARIOT_PUBLIC_OAUTH_BASE ?? '').trim() || '/oauth';
  // If it's an absolute URL (starts with http:// or https://), use it as-is.
  // If it's a path (starts with /), prepend the base origin.
  const oauthBase = /^https?:\/\//.test(rawOauthBase)
    ? rawOauthBase.replace(/\/+$/, '')
    : `${base}${rawOauthBase.replace(/\/+$/, '')}`;
  const issuer = `${oauthBase}/${tenantId}`;

  res.set('Cache-Control', 'public, max-age=3600').json({
    issuer,
    token_endpoint: `${oauthBase}/token`,
    revocation_endpoint: `${oauthBase}/revoke`,
    grant_types_supported: [...ACCEPTED_GRANT_TYPES],
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'private_key_jwt',
    ],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256'],
    // RFC 7009 §2.1: the revocation endpoint requires client
    // authentication. Advertise the same methods the token endpoint
    // supports so clients discover them via standard metadata.
    revocation_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'private_key_jwt',
    ],
    revocation_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256'],
    // draft-04 §7.2: a Resource AS that processes the ID-JAG profile
    // SHOULD advertise it via authorization_grant_profiles_supported
    // and MUST include jwt-bearer in grant_types_supported (which we
    // do via GRANT_TYPE above).
    authorization_grant_profiles_supported: ['urn:ietf:params:oauth:grant-profile:id-jag'],
    id_jag_signing_alg_values_supported: ['RS256', 'ES256'],
    authorization_details_types_supported: [SUPPORTED_RAR_TYPE],
    resource_indicators_supported: true,
    // L1 — sync with dpop.ts SUPPORTED_ALGS: clients reading discovery
    // must see the same algorithm set the verifier accepts.
    dpop_signing_alg_values_supported: ['RS256', 'ES256', 'EdDSA', 'PS256'],
  });
};
router.get('/.well-known/oauth-authorization-server', oauthAuthorizationServerMetadataHandler);
