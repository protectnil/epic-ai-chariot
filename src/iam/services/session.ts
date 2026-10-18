/**
 * IAM — Session Service
 *
 * Enterprise JWT sessions with Redis-backed per-session and per-tenant
 * revocation via epoch checking.
 *
 * ENTERPRISE_JWT_SECRET is required. No fallback. No default.
 * Redis must be reachable before any token operation.
 */

import { randomUUID, randomBytes, createHash } from 'node:crypto';
import jwt from 'jsonwebtoken';
import type { RedisClientType } from 'redis';
import { resolveAdapterIds, resolveAllowedOperations } from './mapping.js';
import { getCollection } from '../db.js';
import { createLogger } from '../../engine/logger.js';
import type {
  EnterpriseUserDocument,
  TenantDocument,
  EnterpriseSessionPayload,
} from '../types.js';

// Exported (rulings item 91/105) so §16.2 alert-channel admin-contact
// resolution (src/observability/alertDispatchWiring.ts) uses the SAME
// admin-group default this module's own isAdmin derivation uses, rather
// than a second hardcoded copy that could silently drift from this one.
export const DEFAULT_ADMIN_GROUP_NAME = 'EpicAI-Admins';
const moduleLog = createLogger('iam.session');

// Single source of truth for token lifetime. Exported so external token-
// envelope builders (e.g. id-jag-issuer's RFC 8693 expires_in) reference
// the same value rather than duplicating the 8h constant.
export const TOKEN_EXPIRY_SECONDS = 8 * 3600;
/**
 * TTL of the `ent:session:revoked:{jti}` revocation marker (§3.4::2 = 24h).
 * Distinct from the `ent:user-sessions` set TTL (§3.4::3 = 30h): the marker
 * only needs to outlive the 8h access token it rejects, so a revoked jti stays
 * blocked until the token would have expired anyway.
 */
export const SESSION_REVOKED_TTL_SECONDS = 24 * 3600;
const TOKEN_EXPIRY = `${TOKEN_EXPIRY_SECONDS}s`;

// SOC 2: Idle session timeout (30 minutes). Configurable via ENTERPRISE_IDLE_TIMEOUT_MINUTES.
const IDLE_TIMEOUT_SECONDS = parseInt(process.env.ENTERPRISE_IDLE_TIMEOUT_MINUTES || '30', 10) * 60;

// Redis key prefixes
const KEY_TENANT_EPOCH = 'ent:tenant-epoch:';
const KEY_USER_EPOCH = 'ent:user-epoch:';
// Monotonic per-user revocation version. Incremented (INCR) on every
// revokeAllUserSessions / revokeAllUserRefreshTokens call. Each token
// captures the current value at issuance via getUserRevocationVersion();
// at verification, token.userVer < currentVer → reject. Using a counter
// rather than a timestamp eliminates the same-millisecond race that
// wall-clock comparisons cannot resolve.
const KEY_USER_REV_VERSION = 'ent:user-rev:';
/**
 * §3.4::1 — `ent:session:{jti}` maps session ID → user ID for the session
 * lifetime. Held at the token's own lifetime (TOKEN_EXPIRY_SECONDS) so the
 * mapping cannot outlive the session it describes. Distinct from
 * `ent:session:active:` (idle-timeout timestamp, 30h) and
 * `ent:session:revoked:` (revocation marker, 24h).
 */
const KEY_SESSION = 'ent:session:';
const KEY_SESSION_REVOKED = 'ent:session:revoked:';
const KEY_USER_SESSIONS = 'ent:user-sessions:';
const KEY_SESSION_ACTIVITY = 'ent:session:active:';
/**
 * Per-session subject_token cache for the Chariot-as-Client ID-JAG path
 * (P6). Holds the user's inbound SSO assertion so MCP-dispatch (P4) can
 * present it to the enterprise IdP's §4.3 token-exchange endpoint when
 * requesting a per-audience ID-JAG. Encrypted at the credential-loader
 * layer; the Redis value is the encrypted blob. TTL = exp(assertion) -
 * 60s OR 8h, whichever is shorter.
 */
const KEY_SESSION_IDJAG_SUBJECT = 'ent:session:idjag-subject:';

/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10). Rulings item 59: the
 * upgrade-on-decrypt write-back "MUST persist {encrypted, iv} back to the
 * SAME record, in the SAME operation" — for a Redis-backed record, that
 * means the SET is a compare-and-set against the exact bytes just read,
 * atomically, via a single EVAL (Lua runs to completion under Redis's
 * single-threaded execution model — no separate WATCH/MULTI round trip
 * needed, and none of the TOCTOU window that would create). A concurrent
 * upgrader that already rewrote the key makes GET != ARGV[1], so this is
 * a no-op (return 0) — never a clobber of a v2 value another upgrader
 * already wrote, and never a resurrection of a key that expired/was
 * cleared between the read and this write (GET on a missing key is Lua
 * `false`, which also never equals the expected string).
 */
const CAS_SET_WITH_TTL_SCRIPT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
  return 1
else
  return 0
end
`;

/**
 * Compare-and-set a Redis string value with a TTL, atomically. Returns
 * `true` when the CAS succeeded (the key held exactly `expectedRaw`),
 * `false` on a benign CAS mismatch (concurrent write, deletion, or
 * expiry — never treated as a failure by callers). Shared by
 * `getIdJagSubjectToken`'s upgrade-on-decrypt write-back and
 * `walkLegacyIdJagSubjectTokens` (the CH-10 migration walker below), so
 * both use the identical atomic primitive.
 */
export async function casSetWithTtl(
  redis: RedisClientType,
  key: string,
  expectedRaw: string,
  newValue: string,
  ttlSeconds: number,
): Promise<boolean> {
  const result = await redis.eval(CAS_SET_WITH_TTL_SCRIPT, {
    keys: [key],
    arguments: [expectedRaw, newValue, String(ttlSeconds)],
  });
  return result === 1;
}

const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600; // 30 days

// ── Secret resolution ──────────────────────────────────────────────────────

/**
 * Validate ENTERPRISE_JWT_SECRET at startup. Throws the same Error shape
 * getJwtSecret() throws — missing / insecure-default / <32 chars — so
 * bind-time can surface secret-misconfiguration as a fail-fast startup
 * error rather than every /mcp request silently 401'ing at runtime.
 */
export function validateEnterpriseJwtSecret(): void {
  getJwtSecret();
}

/**
 * Returns the JWT secret, throwing immediately if not set.
 * Called on every sign/verify to ensure the secret cannot be swapped at runtime.
 */
function getJwtSecret(): string {
  const secret = process.env.ENTERPRISE_JWT_SECRET;
  if (!secret || secret === 'change-me' || secret === 'changeme' || secret === 'secret') {
    throw new Error(
      'ENTERPRISE_JWT_SECRET is not set or is an insecure default. ' +
      'Enterprise session management requires a real secret. ' +
      'Generate with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'base64\'))"'
    );
  }
  if (secret.length < 32) {
    throw new Error(
      `ENTERPRISE_JWT_SECRET is too short (${secret.length} chars, minimum 32). ` +
      'Use a cryptographically random value of at least 256 bits. ' +
      'Generate with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'base64\'))"'
    );
  }
  return secret;
}

// ── Redis injection ────────────────────────────────────────────────────────

let _redis: RedisClientType | null = null;

/**
 * Inject the Redis client from bootstrap. Must be called before any session
 * operation. This replaces the lazy-connect pattern so Redis availability
 * is verified at startup, not on first request.
 */
export function setRedisClient(client: RedisClientType): void {
  _redis = client;
}

// ── Redis-degraded mode (CHARIOT::§18.3) ────────────────────────────────────

let _redisDegraded = false;

/**
 * CHARIOT::§18.3 — "Redis unreachable | ControlPlane degrades to
 * in-process; ApprovalQueue degrades to in-memory; sessions fall back to
 * JWT-signature-only revocation (8h max stale window)." (CHARIOT-SPEC.md:1480)
 *
 * Called by bootstrap (src/iam/bootstrap.ts, src/engine/bin/setup.ts) with
 * resolveEnterpriseRedisClient()'s `degraded` result: true ONLY when a
 * CONFIGURED REDIS_URL was unreachable at boot/restart and the in-process
 * shim was substituted for it (the shim then starts EMPTY, so every token
 * issued before the outage has no activity/revocation record in it) —
 * NOT when REDIS_URL was simply never configured (that shim is used
 * consistently from process start with no prior state to have lost).
 * verifyToken() below consults isSessionRedisDegraded() to decide whether
 * a missing activity key is fail-closed (normal mode) or ignorable
 * (degraded mode — signature + exp become the only checks).
 *
 * Logs exactly ONE warning on each true transition INTO the degraded
 * state (not per verifyToken() call) so operators see it once at the
 * point of failure rather than flooding logs on every request; a
 * transition back to `degraded: false` (e.g. after a restart with Redis
 * reachable again) is silent here — the normal boot-success log line
 * covers that.
 */
export function setSessionRedisDegraded(degraded: boolean, reason?: string): void {
  if (degraded && !_redisDegraded) {
    moduleLog.warn(
      '[iam/session] Redis degraded — session revocation falls back to ' +
      'JWT-signature-only (missing activity/revocation state is no longer ' +
      'fail-closed) until a real Redis is reachable again; bounded by the ' +
      `${TOKEN_EXPIRY_SECONDS / 3600}h token TTL`,
      reason ? { reason } : undefined,
    );
  }
  _redisDegraded = degraded;
}

/** Exported for session.*.test.ts and for verifyToken() below. */
export function isSessionRedisDegraded(): boolean {
  return _redisDegraded;
}

function getRedis(): RedisClientType {
  if (!_redis) {
    throw new Error(
      'Session service: Redis client not initialized. ' +
      'Call setRedisClient() during enterprise bootstrap before issuing tokens.'
    );
  }
  return _redis;
}

/**
 * CHARIOT::§8.2::3 — thin, additive export so `src/iam/services/mfa.ts` can
 * reuse the SAME session-revocation Redis client (and therefore the same
 * KEY_TENANT_EPOCH/KEY_USER_EPOCH get/set epoch-bump pattern this file
 * already implements) for a new, narrower "MFA assertion" epoch namespace,
 * rather than re-deriving a second Redis connection. Does not change
 * `getRedis()`'s behavior or any of its ~15 existing internal call sites —
 * this only exposes the same private client through a new name.
 */
export function getSessionRedisClient(): RedisClientType {
  return getRedis();
}

// ── Issue ───────────────────────────────────────────────────────────────────

/**
 * Issue a JWT for an authenticated IAM user.
 *
 * Populates the JWT payload with:
 *   - `adapterIds` — resolved from `iam_group_adapter_mappings` by calling
 *     `resolveAdapterIds(tenantId, user.groups)`. This is the authoritative
 *     RBAC surface read by `adapterFilterMiddleware`. NEVER hardcode this
 *     to an empty array — doing so causes `adapterFilterMiddleware` to 403
 *     every authenticated request, which is the bug that was previously
 *     shipped. If a user has no mapped adapters, the payload carries an
 *     empty array and the middleware correctly denies access for that user.
 *   - `isAdmin` — derived from whether the user's `groups` contain the
 *     tenant's `adminGroupName` (defaults to "EpicAI-Admins"). Read by
 *     `enterpriseAdminGuard()` for admin-only routes.
 *
 * Group membership comes from the IdP (SAML attributes or OIDC claims) and
 * maps 1:1 to the `groupId` field in `iam_group_adapter_mappings`, which is
 * stored as the raw display name rather than an ObjectId. `resolveAdapterIds`
 * performs the join on exact string match.
 */
/**
 * Type alias for the resolver functions issueToken uses to look up
 * group-adapter mappings and operation grants. The named optional fields on
 * IssueTokenOptions accept these so tests can inject deterministic stubs
 * without trying to mutate ESM namespace bindings (which are non-configurable
 * by spec, so Object.defineProperty on the module namespace cannot work).
 */
export type ResolveAdapterIdsFn = typeof resolveAdapterIds;
export type ResolveAllowedOperationsFn = typeof resolveAllowedOperations;

export interface IssueTokenOptions {
  mfaVerified?: boolean;
  /**
   * Optional resolver injection point for adapter-id lookups. Production
   * callers omit this; the default resolveAdapterIds() runs. Tests pass a
   * stub to return deterministic adapter ids without touching Mongo.
   */
  resolveAdapterIds?: ResolveAdapterIdsFn;
  /**
   * Optional resolver injection point for per-adapter operation grants.
   * Same posture as resolveAdapterIds — production callers omit, tests stub.
   */
  resolveAllowedOperations?: ResolveAllowedOperationsFn;
  /**
   * The audit-only entry path that produced this token. Surfaces in the
   * audit detail (callers write the audit row); does NOT change JWT shape.
   * Defaults to 'login' when omitted.
   */
  provisioningSource?: 'login' | 'id_jag';
  /**
   * RFC 9449 DPoP: when present, the JWT receives a `cnf: { jkt }` claim
   * binding the token to the JWK SHA-256 thumbprint (base64url) of the
   * client's proof key. Resource-server middleware (extended in commit 4)
   * MUST require Authorization: DPoP + a fresh proof matching this `jkt`
   * on every protected-resource call. When omitted, the issued token is
   * a bearer token (no cnf claim).
   */
  cnfJkt?: string;
  /**
   * Principal kind of the token holder (gap #3 — Wiz 2 human/agent/
   * service partition). Only non-human kinds are ever stamped: a human
   * session is expressed by OMITTING the claim entirely, so every
   * interactive-SSO call site (SAML/OIDC callbacks, session refresh)
   * stays byte-identical to pre-partition tokens. The ID-JAG issuer
   * passes 'agent' — its tokens are minted for client workloads
   * presenting identity assertions, not for a person at a keyboard.
   * Consumed by adapterFilterMiddleware, which strips grants whose
   * mapping `principalScope` excludes the stamped kind.
   */
  principalType?: 'agent' | 'service';
}

export async function issueToken(
  user: EnterpriseUserDocument,
  tenant: TenantDocument,
  opts?: IssueTokenOptions,
): Promise<string> {
  const jti = randomUUID();
  const secret = getJwtSecret();

  const userGroups = user.groups ?? [];
  const resolveAdapterIdsFn = opts?.resolveAdapterIds ?? resolveAdapterIds;
  const resolveAllowedOperationsFn = opts?.resolveAllowedOperations ?? resolveAllowedOperations;
  const resolvedAdapterIds = await resolveAdapterIdsFn(tenant.tenantId, userGroups);
 // Per-(adapterId, operation) grants stamped into the JWT and
  // enforced by the chariot_call dispatcher. Deny-by-default downstream:
  // an empty Record (no groups, no mappings) means every call is denied.
  const resolvedAllowedOperations = await resolveAllowedOperationsFn(tenant.tenantId, userGroups);
  const adminGroupName = tenant.settings.adminGroupName ?? DEFAULT_ADMIN_GROUP_NAME;
  const isAdmin = userGroups.includes(adminGroupName);

  // MongoDB stores _id as ObjectId; the declared type is `string` but the
  // runtime value may be an ObjectId instance from the driver. Explicit
  // String() ensures the JWT payload is always a string regardless of
  // which path produced the user document.
  const userIdString = String(user._id);

  // mfaVerified: true when MFA is not required for the tenant (no step-up needed),
  // or when the caller explicitly confirms TOTP was completed.
  // Default to true when mfaRequired is false so existing code paths are unchanged.
  const mfaVerified = opts?.mfaVerified ?? !tenant.settings?.mfaRequired;

  // Capture the user's monotonic revocation version at issuance. The token
  // is invalidated by verifyToken if this stamped version is less than the
  // current version (which only ever increases).
  const userVer = await getUserRevocationVersion(tenant.tenantId, userIdString);

  const nowMs = Date.now();
  const iat = Math.floor(nowMs / 1000);
  // Inline payload shape — keeps `cnf` an optional, typed field so a
  // future reader who needs to read `payload.cnf` gets type narrowing
  // rather than `unknown`. Adding fields here is the only place to add
  // new JWT claims; downstream consumers re-derive the shape via
  // EnterpriseSessionPayload in types.ts.
  interface IssueTokenPayload {
    sub: string;
    tenantId: string;
    userId: string;
    email: string;
    displayName: string;
    groups: string[];
    allowedAdapterIds: string[];
    adapterIds: string[];
    allowedOperations: Record<string, string[]>;
    isAdmin: boolean;
    mfaVerified: boolean;
    jti: string;
    iat: number;
    iatMs: number;
    userVer: number;
    cnf?: { jkt: string };
    principalType?: 'agent' | 'service';
  }
  const payload: IssueTokenPayload = {
    sub: userIdString,
    tenantId: tenant.tenantId,
    userId: userIdString,
    email: user.email,
    displayName: user.displayName,
    groups: userGroups,
    allowedAdapterIds: tenant.settings.allowedAdapterIds ?? [],
    adapterIds: resolvedAdapterIds,
    allowedOperations: resolvedAllowedOperations,
    isAdmin,
    mfaVerified,
    jti,
    iat,
    // Custom millisecond-precision issuance timestamp. Used by verifyToken
    // for tenant-epoch comparisons (which are also in milliseconds) so a
    // token issued microseconds after revocation is not falsely rejected by
    // the seconds-resolution iat claim.
    iatMs: nowMs,
    // Per-user monotonic revocation version. verifyToken rejects when
    // userVer < current. This eliminates same-ms races that timestamp
    // comparisons cannot resolve.
    userVer,
  };
  // RFC 9449 DPoP: bind this access token to the client's proof key. The
  // resource-server middleware that enforces Authorization: DPoP + a fresh
  // `ath`-bearing proof on every protected-resource call lives in commit 4
  // of the ID-JAG implementation series.
  if (opts?.cnfJkt) {
    payload.cnf = { jkt: opts.cnfJkt };
  }
  // Gap #3 (Wiz 2 principal partition): stamp the principal kind ONLY
  // when the caller declares a non-human holder (ID-JAG workload path).
  // Interactive sessions omit the claim → downstream consumers default
  // to 'human' → pre-partition behavior unchanged.
  if (opts?.principalType) {
    payload.principalType = opts.principalType;
  }

  // expiresIn sets exp automatically — do NOT put exp in the payload or jwt.sign throws
  // §10.6::1 — state HS256 explicitly rather than relying on jsonwebtoken's
  // string-secret default, so the signing and verifying sides are pinned to the
  // same algorithm and cannot drift apart in a future library upgrade.
  const token = jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn: TOKEN_EXPIRY });

  // Track session for per-user revocation
  const redis = getRedis();

  // §3.4::1 — session → user mapping, held for the session's own lifetime.
  await redis.set(`${KEY_SESSION}${jti}`, userIdString, { EX: TOKEN_EXPIRY_SECONDS });

  const userKey = `${KEY_USER_SESSIONS}${tenant.tenantId}:${user._id}`;
  await redis.sAdd(userKey, jti);
  // Expire the set after slightly longer than token lifetime
  await redis.expire(userKey, 30 * 3600); // 30 hours

  // SOC 2: Record initial activity timestamp for idle timeout
  await redis.set(`${KEY_SESSION_ACTIVITY}${jti}`, String(Date.now()), { EX: 30 * 3600 });

  return token;
}

// ── Verify ──────────────────────────────────────────────────────────────────

/**
 * Verify a JWT: signature, tenant epoch, per-session revocation.
 * Returns the decoded payload or null if invalid/revoked.
 */
export async function verifyToken(
  token: string,
  expectedTenantId?: string,
): Promise<(EnterpriseSessionPayload & { jti: string }) | null> {
  const secret = getJwtSecret();
  let decoded: EnterpriseSessionPayload & { jti: string };

  try {
    // §10.6::1 — pin the accepted algorithm. Without `algorithms`, jsonwebtoken
    // honours the `alg` declared in the ATTACKER-SUPPLIED token header, which is
    // the classic algorithm-confusion foothold (CWE-347). Sessions are signed
    // HS256 with a symmetric secret, so exactly one algorithm is ever legitimate.
    // Every other jwt.verify in this codebase already pins (dpop.ts,
    // id-jag-validator.ts, oauth.ts); this — the primary session credential —
    // was the only unpinned verifier.
    decoded = jwt.verify(token, secret, {
      algorithms: ['HS256'],
    }) as EnterpriseSessionPayload & { jti: string };
  } catch {
    return null;
  }

  // Tenant filter
  if (expectedTenantId && decoded.tenantId !== expectedTenantId) {
    return null;
  }

  const redis = getRedis();

  // Compute the token's effective issuance timestamp in milliseconds.
  // Prefer iatMs (custom claim added 2026); fall back to iat*1000 (standard
  // JWT seconds claim) for tokens issued before iatMs existed; then 0 for
  // fully legacy tokens — both fall-back cases fail-closed under any
  // active tenant or user epoch.
  const decodedIatMs = (decoded as { iatMs?: number }).iatMs;
  const iatMs = typeof decodedIatMs === 'number'
    ? decodedIatMs
    : (typeof decoded.iat === 'number' ? decoded.iat * 1000 : 0);

  // CHARIOT::§18.3 — "Redis unreachable | ... sessions fall back to
  // JWT-signature-only revocation (8h max stale window)." (CHARIOT-SPEC.md:1480)
  // WHILE DEGRADED (isSessionRedisDegraded()), every Redis-backed
  // revocation/epoch check below (tenant epoch, user epoch, user monotonic
  // revocation version, per-session revocation marker) is SKIPPED — not
  // "consult whatever the local in-process shim happens to hold", but
  // unconditionally signature+exp only, exactly as the clause states. Two
  // reasons that reading, not the "consult what's there" alternative, is
  // correct: (1) a real deployment degrades per-process (each `chariot
  // serve --http` instance falls back to its OWN empty shim independently
  // — CHARIOT-SPEC.md:1480's "ControlPlane degrades to in-process" is a
  // per-process posture), so an admin's revoke-while-degraded write would
  // land in only ONE instance's shim behind a load balancer, silently
  // leaving every other instance still honoring the revoked token — an
  // inconsistent, instance-dependent revocation guarantee that is worse
  // than the clause's plain, uniform "signature-only" reading; (2) the
  // clause's own phrase is "JWT-signature-only revocation", not
  // "best-effort local revocation" — jwt.verify() above (signature + exp,
  // unconditional, before any Redis access) is the ENTIRE enforcement
  // surface while degraded, bounded by TOKEN_EXPIRY_SECONDS (8h) since a
  // token can never outlive its own `exp` regardless of revocation state.
  // WHILE NOT DEGRADED, every check below is byte-identical to before this
  // guard was added.
  if (!isSessionRedisDegraded()) {
    // Tenant epoch check — invalidates ALL tenant sessions (used by
    // revokeAllTenantSessions / mfaRequired toggle).
    const tenantEpochStr = await redis.get(`${KEY_TENANT_EPOCH}${decoded.tenantId}`);
    if (tenantEpochStr) {
      const tenantEpochMs = parseInt(tenantEpochStr, 10);
      if (Number.isFinite(tenantEpochMs) && iatMs < tenantEpochMs) return null;
    }

    // User epoch check (timestamp-based defense in depth).
    const userEpochStr = await redis.get(
      `${KEY_USER_EPOCH}${decoded.tenantId}:${decoded.userId}`,
    );
    if (userEpochStr) {
      const userEpochMs = parseInt(userEpochStr, 10);
      if (Number.isFinite(userEpochMs) && iatMs < userEpochMs) return null;
    }

    // User monotonic revocation version check — the AUTHORITATIVE check.
    // Atomic INCR on the revoke side and integer comparison here mean there
    // is no clock-resolution race: a token stamped with version N is
    // permanently invalidated the instant the counter moves to N+1.
    const userVerStr = await redis.get(
      `${KEY_USER_REV_VERSION}${decoded.tenantId}:${decoded.userId}`,
    );
    if (userVerStr) {
      const currentVer = parseInt(userVerStr, 10);
      if (Number.isFinite(currentVer)) {
        const tokenVer = (decoded as { userVer?: number }).userVer;
        const stamped = typeof tokenVer === 'number' ? tokenVer : 0;
        if (stamped < currentVer) return null;
      }
    }

    // Check per-session revocation
    const revoked = await redis.get(`${KEY_SESSION_REVOKED}${decoded.jti}`);
    if (revoked) {
      return null;
    }
  }

  // SOC 2: Idle session timeout — reject tokens not used within the idle window.
  // missing activity key MUST fail closed. A successful login
  // always writes the activity key (see issueSession); absent key means
  // the session was either evicted/expired by Redis or never tracked —
  // either way the token must be rejected, NOT silently treated as if
  // freshly active.
  //
  // CHARIOT::§18.3 — "Redis unreachable | ... sessions fall back to
  // JWT-signature-only revocation (8h max stale window)." (CHARIOT-SPEC.md:1480)
  // WHILE DEGRADED (isSessionRedisDegraded() — see that function's doc for
  // exactly which case this is: a CONFIGURED REDIS_URL unreachable at
  // boot/restart, not "REDIS_URL never configured"): the in-process shim
  // was substituted after every pre-outage token had already been issued,
  // so it starts EMPTY — applying the fail-closed rule above verbatim
  // would reject every one of those tokens, which is an outage for all
  // existing users, not "fall back to JWT-signature-only revocation" as
  // the clause requires. So while degraded, a missing activity key is NOT
  // fail-closed: jwt.verify() above has already unconditionally checked
  // signature + exp (this function returns null before reaching here on
  // either failure — see the try/catch at the top), and that IS the
  // "JWT-signature-only revocation" the clause names; TOKEN_EXPIRY_SECONDS
  // (8h) bounds how stale that can ever be, since a token can never
  // outlive its own `exp` regardless of activity/revocation state.
  // WHILE NOT DEGRADED, behavior is unchanged — the fail-closed rule above
  // still applies exactly as before.
  //
  // The WHOLE idle-timeout check — the missing-key fail-closed rule AND the
  // elapsed-time computation on a present marker — is Redis-backed session
  // state, so while degraded none of it is consulted: a stale-but-present
  // activity marker must not reject a degraded token either (2026-09-03 gate). The marker is refreshed so a later, still-degraded verify
  // of this SAME session does not start from a cold state, and so behavior is
  // uniform once Redis recovers and the marker becomes a real, persisted one.
  if (isSessionRedisDegraded()) {
    await redis.set(`${KEY_SESSION_ACTIVITY}${decoded.jti}`, String(Date.now()), { EX: 30 * 3600 });
    return decoded;
  }
  const lastActivity = await redis.get(`${KEY_SESSION_ACTIVITY}${decoded.jti}`);
  if (!lastActivity) {
    await redis.set(`${KEY_SESSION_REVOKED}${decoded.jti}`, '1', { EX: SESSION_REVOKED_TTL_SECONDS });
    // §3.4::1 — the session is dead; drop its session→user mapping.
    await redis.del(`${KEY_SESSION}${decoded.jti}`);
    return null;
  }
  const elapsed = (Date.now() - parseInt(lastActivity, 10)) / 1000;
  if (elapsed > IDLE_TIMEOUT_SECONDS) {
    // Session idle too long — revoke it
    await redis.set(`${KEY_SESSION_REVOKED}${decoded.jti}`, '1', { EX: SESSION_REVOKED_TTL_SECONDS });
    // §3.4::1 — the session is dead; drop its session→user mapping.
    await redis.del(`${KEY_SESSION}${decoded.jti}`);
    return null;
  }

  // Update last activity timestamp (session is active)
  await redis.set(`${KEY_SESSION_ACTIVITY}${decoded.jti}`, String(Date.now()), { EX: 30 * 3600 });

  return decoded;
}

// ── Revoke ──────────────────────────────────────────────────────────────────

/**
 * Revoke a single session by JTI.
 */
export async function revokeSession(jti: string): Promise<void> {
  const redis = getRedis();
  await redis.set(`${KEY_SESSION_REVOKED}${jti}`, '1', { EX: SESSION_REVOKED_TTL_SECONDS });
  // §3.4::1 — the session→user mapping must not outlive the session.
  await redis.del(`${KEY_SESSION}${jti}`);
  // P6 — clear any stored ID-JAG subject_token so a leaked Redis snapshot
  // cannot be used by a future actor against the same session jti.
  await redis.del(`${KEY_SESSION_IDJAG_SUBJECT}${jti}`);
}

/**
 * Revoke all sessions for a specific user. Bumps the per-user epoch so
 * tokens issued before the bump (including legacy tokens that were never
 * tracked in the per-user JTI set) fail verification on next use.
 * Also marks every tracked JTI as revoked for fast-path rejection.
 * Returns the JTIs of the sessions that were revoked (empty when the user had
 * no tracked sessions) so callers can emit a per-session audit event.
 */
export async function revokeAllUserSessions(
  tenantId: string,
  userId: string,
): Promise<string[]> {
  const redis = getRedis();
  const userKey = `${KEY_USER_SESSIONS}${tenantId}:${userId}`;

  // ALWAYS bump the user epoch (timestamp) AND increment the revocation
  // version (monotonic counter). The counter is the primary check —
  // immune to same-ms races. The timestamp is retained as a defense-in-depth
  // signal for audit / forensics.
  await redis.set(`${KEY_USER_EPOCH}${tenantId}:${userId}`, Date.now().toString());
  await bumpUserRevocationVersion(tenantId, userId);

  const jtis = await redis.sMembers(userKey);
  if (jtis.length === 0) return [];

  const pipeline = redis.multi();
  for (const jti of jtis) {
    pipeline.set(`${KEY_SESSION_REVOKED}${jti}`, '1', { EX: SESSION_REVOKED_TTL_SECONDS });
    // §3.4::1 — drop the session→user mapping for every revoked session.
    pipeline.del(`${KEY_SESSION}${jti}`);
    // Forced logout MUST also clear the ID-JAG subject_token blob for
    // every revoked session so a Redis snapshot inside the natural TTL
    // window cannot leak the user's still-valid OIDC ID token or SAML
    // assertion (mirrors revokeSession's per-jti cleanup).
    pipeline.del(`${KEY_SESSION_IDJAG_SUBJECT}${jti}`);
  }
  pipeline.del(userKey);
  await pipeline.exec();

  return jtis;
}

/**
 * Revoke ALL sessions for a tenant by setting the epoch to now (milliseconds).
 * Any access or refresh token whose iat (in ms) is strictly less than the
 * stored epoch will fail verification. Millisecond precision narrows the
 * revocation race window to 1 ms — a token issued in the exact millisecond
 * of revocation is accepted, so a freshly re-authenticated user is not
 * rejected by their own admin's policy change.
 */
export async function revokeAllTenantSessions(
  tenantId: string,
): Promise<void> {
  const redis = getRedis();
  const epochMs = Date.now();
  await redis.set(`${KEY_TENANT_EPOCH}${tenantId}`, epochMs.toString());
}

/**
 * Check whether a specific session JTI has been revoked.
 */
export async function isSessionRevoked(jti: string): Promise<boolean> {
  const redis = getRedis();
  const result = await redis.get(`${KEY_SESSION_REVOKED}${jti}`);
  return result !== null;
}

/**
 * Read the current per-user epoch (ms) or null if none set.
 * Retained for legacy compatibility with timestamp-based checks.
 */
export async function getUserEpochMs(
  tenantId: string,
  userId: string,
): Promise<number | null> {
  const redis = getRedis();
  const value = await redis.get(`${KEY_USER_EPOCH}${tenantId}:${userId}`);
  if (!value) return null;
  const ms = parseInt(value, 10);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Read the current per-user monotonic revocation version, or 0 if unset.
 * Used at token issuance time to stamp tokens with the version they were
 * minted under. Tokens with a stamped version less than the current
 * version are rejected by verifyToken / consumeRefreshToken.
 */
export async function getUserRevocationVersion(
  tenantId: string,
  userId: string,
): Promise<number> {
  const redis = getRedis();
  const value = await redis.get(`${KEY_USER_REV_VERSION}${tenantId}:${userId}`);
  if (!value) return 0;
  const ver = parseInt(value, 10);
  return Number.isFinite(ver) ? ver : 0;
}

/**
 * Atomically increment the per-user revocation version. Called from
 * revokeAllUserSessions and revokeAllUserRefreshTokens. Returns the new
 * version. INCR in Redis is atomic and monotonically non-decreasing —
 * this is the primitive that eliminates same-millisecond race conditions
 * inherent to wall-clock comparisons.
 */
async function bumpUserRevocationVersion(
  tenantId: string,
  userId: string,
): Promise<number> {
  const redis = getRedis();
  const newVer = await redis.incr(`${KEY_USER_REV_VERSION}${tenantId}:${userId}`);
  return typeof newVer === 'number' ? newVer : 0;
}

// ── Refresh Tokens ───────────────────────────────────────────────────────────

interface RefreshTokenPayload {
  jti: string;
  userId: string;
  tenantId: string;
  mfaVerified: boolean;
  /** Issued-at timestamp in MILLISECONDS. Used for tenant epoch checks. */
  iatMs: number;
  /**
   * Per-user monotonic revocation version captured at issuance.
   * consumeRefreshToken rejects when userVer < current. This is the
   * primitive that eliminates same-millisecond races inherent to
   * wall-clock comparisons — INCR is atomic and monotonic.
   */
  userVer: number;
}

/**
 * Server-side refresh-token record persisted in Mongo `iam_refresh_tokens`
 * (§10.6::6). `_id` is the SHA-256 hash of the opaque token, giving a unique
 * key and an atomic single-use consume via `findOneAndDelete`; a TTL index on
 * `expiresAt` reaps expired records (see `ensureEnterpriseIndexes`). The raw
 * token itself is never stored.
 */
interface RefreshTokenDocument extends RefreshTokenPayload {
  _id: string;
  expiresAt: Date;
}

function hashRefreshToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

/**
 * Issue a new opaque refresh token linked to a session JTI.
 * The raw token is returned once and stored only as its SHA-256 hash in Redis.
 * TTL: 30 days (sliding — reset on every rotation).
 *
 * `mfaVerified` records whether the session that produced this refresh token
 * had completed MFA. /refresh uses this to (a) preserve continuity for verified
 * sessions and (b) fail-closed against tenants that enable MFA after issuance.
 */
export async function issueRefreshToken(
  jti: string,
  userId: string,
  tenantId: string,
  mfaVerified: boolean,
): Promise<string> {
  const raw = randomBytes(32).toString('hex');
  const hash = hashRefreshToken(raw);
  const userVer = await getUserRevocationVersion(tenantId, userId);
  const payload: RefreshTokenPayload = {
    jti,
    userId,
    tenantId,
    mfaVerified,
    iatMs: Date.now(),
    userVer,
  };
  // §10.6::6: refresh tokens are server-side state in Mongo `iam_refresh_tokens`.
  // Only the hash is persisted (as `_id`); the TTL index on `expiresAt` reaps
  // the record after the 30-day window. revokeAllUserRefreshTokens deletes by
  // {tenantId,userId}, so no separate per-user index is needed.
  const col = await getCollection<RefreshTokenDocument>('iam_refresh_tokens');
  await col.insertOne({
    _id: hash,
    ...payload,
    expiresAt: new Date(payload.iatMs + REFRESH_TOKEN_TTL_SECONDS * 1000),
  });
  return raw;
}

/**
 * Consume a refresh token atomically via GETDEL: fetch and delete in one
 * round-trip, preventing concurrent requests from both reading the same token.
 * Returns null if the token is unknown, already used, expired, or was issued
 * before the tenant epoch (which is bumped by revokeAllTenantSessions).
 */
export interface ConsumeRefreshTokenResult {
  payload: RefreshTokenPayload;
  /**
   * The user revocation version observed by consume itself. Returned so
   * /refresh can use it as the TOCTOU snapshot — capturing it OUTSIDE
   * consume would create a race where a revoke between consume returning
   * and the snapshot read would silently slip through.
   */
  observedUserVer: number;
}

export async function consumeRefreshToken(
  raw: string,
): Promise<ConsumeRefreshTokenResult | null> {
  const hash = hashRefreshToken(raw);
  // §10.6::6 single-use consume: an atomic findOneAndDelete on the Mongo `_id`
  // (the token hash). Two concurrent /refresh calls cannot both win the delete.
  const col = await getCollection<RefreshTokenDocument>('iam_refresh_tokens');
  const doc = await col.findOneAndDelete({ _id: hash });
  if (!doc) return null;
  // Mongo's TTL reaper runs lazily (~60s), so an expired record may still be
  // present at read time; treat a past expiry as already gone.
  if (doc.expiresAt instanceof Date && doc.expiresAt.getTime() <= Date.now()) return null;
  const parsed: RefreshTokenPayload = {
    jti: doc.jti,
    userId: doc.userId,
    tenantId: doc.tenantId,
    mfaVerified: doc.mfaVerified,
    iatMs: doc.iatMs,
    userVer: doc.userVer,
  };
  const redis = getRedis();

  const iatMs = typeof parsed.iatMs === 'number' ? parsed.iatMs : 0;

  // Tenant epoch check — invalidates all tenant refresh tokens.
  const tenantEpochStr = await redis.get(`${KEY_TENANT_EPOCH}${parsed.tenantId}`);
  if (tenantEpochStr) {
    const tenantEpochMs = parseInt(tenantEpochStr, 10);
    if (Number.isFinite(tenantEpochMs) && iatMs < tenantEpochMs) return null;
  }

  // User epoch check (timestamp-based, defense in depth).
  const userEpochStr = await redis.get(
    `${KEY_USER_EPOCH}${parsed.tenantId}:${parsed.userId}`,
  );
  if (userEpochStr) {
    const userEpochMs = parseInt(userEpochStr, 10);
    if (Number.isFinite(userEpochMs) && iatMs < userEpochMs) return null;
  }

  // Monotonic revocation version — the AUTHORITATIVE check, race-free.
  // Capture the version we observe so /refresh can use it as the TOCTOU
  // snapshot. Reading it INSIDE consume eliminates the window between
  // consume returning and a separate post-consume snapshot read, where
  // a revoke could slip through unnoticed.
  const userVerStr = await redis.get(
    `${KEY_USER_REV_VERSION}${parsed.tenantId}:${parsed.userId}`,
  );
  let observedUserVer = 0;
  if (userVerStr) {
    const currentVer = parseInt(userVerStr, 10);
    if (Number.isFinite(currentVer)) {
      observedUserVer = currentVer;
      const stamped = typeof parsed.userVer === 'number' ? parsed.userVer : 0;
      if (stamped < currentVer) return null;
    }
  }

  return { payload: parsed, observedUserVer };
}

/**
 * Revoke ALL refresh tokens for a single user. Used by force-logout and
 * SCIM deprovisioning so a stolen or stale refresh cookie cannot be used
 * to mint a new session after the user has been forcibly signed out.
 */
export async function revokeAllUserRefreshTokens(
  tenantId: string,
  userId: string,
): Promise<number> {
  const redis = getRedis();

  // Bump epoch (timestamp) AND increment monotonic revocation version.
  // The version counter is the authoritative check — immune to same-ms
  // races. The timestamp is retained for forensics and as a backstop.
  await redis.set(`${KEY_USER_EPOCH}${tenantId}:${userId}`, Date.now().toString());
  await bumpUserRevocationVersion(tenantId, userId);

  // §10.6::6: refresh-token records live in Mongo — delete every one this user
  // holds so a stolen/stale refresh token cannot mint a new session.
  const col = await getCollection<RefreshTokenDocument>('iam_refresh_tokens');
  const res = await col.deleteMany({ tenantId, userId });
  return res.deletedCount;
}

/**
 * Revoke a refresh token without consuming it (e.g., on logout).
 * No-ops silently if the token is already gone. Also cleans the per-user
 * index entry — best-effort: index drift doesn't compromise security since
 * the per-token key is the authoritative lookup.
 */
export async function revokeRefreshToken(raw: string): Promise<void> {
  const hash = hashRefreshToken(raw);
  // §10.6::6: delete the Mongo record (no per-user Redis index to reconcile).
  const col = await getCollection<RefreshTokenDocument>('iam_refresh_tokens');
  await col.deleteOne({ _id: hash });
}

// ── MFA Pending State ────────────────────────────────────────────────────────

export interface MfaPendingPayload {
  userId: string;
  tenantId: string;
  email: string;
  displayName: string;
  tempTotpSecret?: string;
}

const KEY_MFA_PENDING = 'ent:mfa:pending:';
const MFA_PENDING_TTL_SECONDS = 600; // 10 minutes

/**
 * Store MFA pending state (post-SSO, pre-TOTP) and return an opaque token.
 */
export async function issueMfaPendingToken(payload: MfaPendingPayload): Promise<string> {
  const raw = randomBytes(32).toString('hex');
  const redis = getRedis();
  await redis.set(`${KEY_MFA_PENDING}${raw}`, JSON.stringify(payload), {
    EX: MFA_PENDING_TTL_SECONDS,
  });
  return raw;
}

/**
 * Look up MFA pending state by token. Does NOT delete the entry so the
 * same pending token can be used across setup → verify-enrollment.
 */
export async function getMfaPendingPayload(raw: string): Promise<MfaPendingPayload | null> {
  const redis = getRedis();
  const value = await redis.get(`${KEY_MFA_PENDING}${raw}`);
  if (!value) return null;
  try {
    return JSON.parse(value) as MfaPendingPayload;
  } catch {
    return null;
  }
}

/**
 * Attach (or update) the temporary TOTP secret in a pending MFA entry.
 * Used during enrollment so the setup and verify-enrollment steps share state.
 */
export async function setMfaPendingTotpSecret(raw: string, secret: string): Promise<void> {
  const redis = getRedis();
  const key = `${KEY_MFA_PENDING}${raw}`;
  const value = await redis.get(key);
  if (!value) return;
  const payload = JSON.parse(value) as MfaPendingPayload;
  payload.tempTotpSecret = secret;
  // Preserve remaining TTL: KEEPTTL preserves the existing TTL in redis ≥ 6.0
  await redis.set(key, JSON.stringify(payload), { KEEPTTL: true });
}

/**
 * Delete the MFA pending state after login is complete (enrolled or not).
 */
export async function clearMfaPendingToken(raw: string): Promise<void> {
  const redis = getRedis();
  await redis.del(`${KEY_MFA_PENDING}${raw}`);
}

// ── ID-JAG subject_token persistence (P6 — Chariot-as-Client path) ───────────

/**
 * Stored shape for the inbound SSO subject_token. The value goes through
 * the existing crypto.ts encryption layer before write so a Redis snapshot
 * leak does not expose the raw OIDC ID token / SAML assertion. Redact
 * from any audit emission.
 */
export interface IdJagSubjectTokenRecord {
  /** OIDC ID token serialised JWT, or raw SAML assertion XML, or refresh_token string. */
  token: string;
  type: 'id_token' | 'saml2' | 'refresh_token';
  /** NumericDate (seconds) — when the subject_token itself expires. */
  exp: number;
  /** Issuer URL (matches iam_id_jag_idp_clients.issuer for the lookup). */
  issuer: string;
}

/**
 * Store the inbound subject_token for a session. Called at SSO
 * completion from oidc.ts / saml.ts. The Redis TTL is exp - 60s OR
 * 8h, whichever is shorter — once the subject_token expires the user
 * MUST re-authenticate.
 */
export async function setIdJagSubjectToken(
  tenantId: string,
  sessionJti: string,
  record: IdJagSubjectTokenRecord,
): Promise<void> {
  const { encryptFields } = await import('../crypto.js');
  const nowSec = Math.floor(Date.now() / 1000);
  // Refuse to store an already-expired (or about-to-expire) assertion.
  // The previous Math.max-clamp let exp-in-past tokens persist for 60s,
  // creating a replay window for stale SAML / OIDC assertions whose
  // NotOnOrAfter / exp had already passed at SSO completion time.
  // Use `<= 60` (not `< 60`) so the boundary case exp - nowSec == 60
  // doesn't compute ttl=0 and trip Redis's 'ERR invalid expire time'.
  if (record.exp - nowSec <= 60) return;
  const ttl = Math.min(8 * 3600, record.exp - nowSec - 60);
  // CH-10 (§12.2) AAD binding: no adapterId for a session record, so use
  // this record's own unique-within-tenant identity (the session jti) —
  // must match getIdJagSubjectToken's read-side identifier below.
  const { encrypted, iv } = encryptFields({
    token: record.token,
    type: record.type,
    exp: String(record.exp),
    issuer: record.issuer,
  }, tenantId, sessionJti);
  const redis = getRedis();
  await redis.set(
    `${KEY_SESSION_IDJAG_SUBJECT}${sessionJti}`,
    JSON.stringify({ encrypted, iv }),
    { EX: ttl },
  );
}

/**
 * Retrieve the inbound subject_token for a session. Returns null when
 * the session has no stored subject_token (SSO path didn't go through
 * an ID-JAG-capable IdP, or the subject_token has expired and was
 * evicted by Redis TTL). The MCP-dispatch path treats null as
 * "fall back to static credential" when the adapter manifest allows.
 */
export async function getIdJagSubjectToken(
  tenantId: string,
  sessionJti: string,
): Promise<IdJagSubjectTokenRecord | null> {
  const redis = getRedis();
  const raw = await redis.get(`${KEY_SESSION_IDJAG_SUBJECT}${sessionJti}`);
  if (!raw) return null;
  const blob = JSON.parse(raw) as { encrypted: string; iv: string };
  const { decryptFields, VaultUpgradePersistFailedError } = await import('../crypto.js');
  // CH-10 (§12.2) AAD binding — must match setIdJagSubjectToken's
  // write-side identifier above.
  const result = await decryptFields(blob.encrypted, blob.iv, tenantId, sessionJti);
  const decrypted = result.fields;
  if (
    typeof decrypted.token !== 'string'
    || typeof decrypted.type !== 'string'
    || typeof decrypted.exp !== 'string'
    || typeof decrypted.issuer !== 'string'
  ) {
    return null;
  }
  const expNum = Number(decrypted.exp);
  if (!Number.isFinite(expNum)) return null;
  const type = decrypted.type;
  if (type !== 'id_token' && type !== 'saml2' && type !== 'refresh_token') return null;
  // CH-10 upgrade-on-decrypt (§12.2, rulings item 59): re-persist under
  // the SAME remaining TTL setIdJagSubjectToken would have computed for
  // this exp (min(8h, exp-now-60s)) — never a fresh 8h, which would
  // extend a near-expiry subject_token's lifetime past its own exp
  // semantics. A TTL that has already collapsed to <=0 by the time we get
  // here means the record is expiring/expired regardless of ciphertext
  // format — skip the write-back rather than fight Redis's rejection of a
  // non-positive EX.
  // CH-10 upgrade-on-decrypt (§12.2, rulings item 59, "the caller MUST
  // persist {encrypted, iv} back to the SAME record, in the SAME
  // operation"). CAS on `raw` (the exact legacy bytes just read) via
  // casSetWithTtl — a concurrent upgrader's already-written value is an
  // idempotent no-op (never a clobber), a genuine Redis error is NOT
  // swallowed and fails this read.
  if (result.upgraded) {
    const nowSec = Math.floor(Date.now() / 1000);
    const ttl = Math.min(8 * 3600, expNum - nowSec - 60);
    if (ttl > 0) {
      try {
        await casSetWithTtl(
          redis,
          `${KEY_SESSION_IDJAG_SUBJECT}${sessionJti}`,
          raw,
          JSON.stringify({ encrypted: result.upgraded.encrypted, iv: result.upgraded.iv }),
          ttl,
        );
      } catch (writeBackErr) {
        throw new VaultUpgradePersistFailedError('session', sessionJti, writeBackErr);
      }
    }
  }
  return {
    token: decrypted.token,
    type,
    exp: expNum,
    issuer: decrypted.issuer,
  };
}

/** Delete the subject_token at session revocation. */
export async function clearIdJagSubjectToken(sessionJti: string): Promise<void> {
  const redis = getRedis();
  await redis.del(`${KEY_SESSION_IDJAG_SUBJECT}${sessionJti}`);
}

/**
 * CH-10 migration walker (CHARIOT-SPEC.md:1237-1250, §12.2, rulings item
 * 59: "walks every stored ciphertext ... reports counts {legacy, upgraded,
 * failed, alreadyV2}"). Called from `chariot vault migrate` for a SPECIFIC
 * `tenantId` so the marker's "zero legacy remain" claim is proven by
 * walking this store too — closing gate finding F1, which named this
 * exact site as one the migration silently skipped.
 *
 * `ent:session:idjag-subject:{sessionJti}` carries NO tenantId in the key
 * itself (see `KEY_SESSION_IDJAG_SUBJECT` above) — the AAD/HKDF salt is
 * what proves tenant ownership, not the key name. This walker therefore
 * SCANs the whole key prefix and ATTEMPTS decrypt under the given
 * `tenantId` for every match: a decrypt failure is indistinguishable
 * between "belongs to a different tenant" and "genuinely corrupt for this
 * tenant" (both are ordinary AES-GCM auth failures), so it is treated as
 * "not this tenant's record" and skipped — neither counted nor a fatal
 * error. This is an accepted, documented limitation: a corrupt record
 * for the CORRECT tenant would not be caught by this walker, but IS still
 * caught the moment that session reads it (`getIdJagSubjectToken` fails
 * closed on a genuine decrypt failure, same as every other vault read).
 * A v2 (already-upgraded) record likewise cannot be attributed to a
 * tenant without decrypting it, which is unnecessary work for a value
 * that is already correctly upgraded — this walker does not attempt to,
 * so `alreadyV2` always reports 0 here; only `legacy`/`upgraded` (which
 * gate the migration marker) are meaningful for this site.
 */
export async function walkLegacyIdJagSubjectTokens(
  tenantId: string,
  dryRun: boolean,
): Promise<{ legacy: number; upgraded: number; failed: number; alreadyV2: number }> {
  const redis = getRedis();
  const { decryptFieldsForVaultMigration, encryptFields, isLegacyCiphertext } = await import('../crypto.js');
  const counts = { legacy: 0, upgraded: 0, failed: 0, alreadyV2: 0 };

  // node-redis v4's scanIterator yields BATCHES (string[] per cursor
  // step), never a single key at a time — the SCAN command itself always
  // returns a cursor plus an array of matched keys per call, and
  // scanIterator's AsyncGenerator element type is that array, not one of
  // its elements. Iterating the outer loop as if `key` were a single
  // string (get/slice/casSetWithTtl all expect a string) is a type error
  // the compiler catches; the fix is the inner loop over each batch.
  for await (const keysBatch of redis.scanIterator({ MATCH: `${KEY_SESSION_IDJAG_SUBJECT}*`, COUNT: 200 })) {
    for (const key of keysBatch) {
      const sessionJti = key.slice(KEY_SESSION_IDJAG_SUBJECT.length);
      const raw = await redis.get(key);
      if (!raw) continue; // evicted between SCAN and GET — nothing to walk.
      let blob: { encrypted: string; iv: string };
      try {
        blob = JSON.parse(raw) as { encrypted: string; iv: string };
      } catch {
        continue; // not this store's shape — out of scope.
      }
      if (!isLegacyCiphertext(blob.encrypted)) continue; // see doc: v2 not attributable without decrypting.

      let fields: Record<string, string>;
      try {
        const decrypted = await decryptFieldsForVaultMigration(blob.encrypted, blob.iv, tenantId, sessionJti);
        fields = decrypted.fields;
      } catch {
        // Not this tenant's record (or corrupt) — see doc comment above.
        continue;
      }
      counts.legacy++;

      const expNum = Number(fields.exp);
      const nowSec = Math.floor(Date.now() / 1000);
      const ttl = Number.isFinite(expNum) ? Math.min(8 * 3600, expNum - nowSec - 60) : -1;
      if (ttl <= 0) {
        // Already expired/expiring by its own exp semantics — nothing to
        // usefully re-persist; not a failure, just not upgraded.
        continue;
      }
      try {
        if (!dryRun) {
          const { encrypted, iv } = encryptFields(fields, tenantId, sessionJti);
          await casSetWithTtl(redis, key, raw, JSON.stringify({ encrypted, iv }), ttl);
        }
        counts.upgraded++;
      } catch {
        counts.failed++;
      }
    }
  }
  return counts;
}
