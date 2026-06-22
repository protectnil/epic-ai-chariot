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
import type {
  EnterpriseUserDocument,
  TenantDocument,
  EnterpriseSessionPayload,
} from '../types.js';

const DEFAULT_ADMIN_GROUP_NAME = 'EpicAI-Admins';

// Single source of truth for token lifetime. Exported so external token-
// envelope builders (e.g. id-jag-issuer's RFC 8693 expires_in) reference
// the same value rather than duplicating the 8h constant.
export const TOKEN_EXPIRY_SECONDS = 8 * 3600;
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
const KEY_SESSION_REVOKED = 'ent:session:revoked:';
const KEY_USER_SESSIONS = 'ent:user-sessions:';
const KEY_SESSION_ACTIVITY = 'ent:session:active:';
const KEY_REFRESH_TOKEN = 'ent:refresh:';
const KEY_USER_REFRESH_TOKENS = 'ent:user-refresh:';
/**
 * Per-session subject_token cache for the Chariot-as-Client ID-JAG path
 * (P6). Holds the user's inbound SSO assertion so MCP-dispatch (P4) can
 * present it to the enterprise IdP's §4.3 token-exchange endpoint when
 * requesting a per-audience ID-JAG. Encrypted at the credential-loader
 * layer; the Redis value is the encrypted blob. TTL = exp(assertion) -
 * 60s OR 8h, whichever is shorter.
 */
const KEY_SESSION_IDJAG_SUBJECT = 'ent:session:idjag-subject:';

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

function getRedis(): RedisClientType {
  if (!_redis) {
    throw new Error(
      'Session service: Redis client not initialized. ' +
      'Call setRedisClient() during enterprise bootstrap before issuing tokens.'
    );
  }
  return _redis;
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

  // expiresIn sets exp automatically — do NOT put exp in the payload or jwt.sign throws
  const token = jwt.sign(payload, secret, { expiresIn: TOKEN_EXPIRY });

  // Track session for per-user revocation
  const redis = getRedis();
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
    decoded = jwt.verify(token, secret) as EnterpriseSessionPayload & { jti: string };
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

  // SOC 2: Idle session timeout — reject tokens not used within the idle window.
  // missing activity key MUST fail closed. A successful login
  // always writes the activity key (see issueSession); absent key means
  // the session was either evicted/expired by Redis or never tracked —
  // either way the token must be rejected, NOT silently treated as if
  // freshly active.
  const lastActivity = await redis.get(`${KEY_SESSION_ACTIVITY}${decoded.jti}`);
  if (!lastActivity) {
    await redis.set(`${KEY_SESSION_REVOKED}${decoded.jti}`, '1', { EX: 30 * 3600 });
    return null;
  }
  const elapsed = (Date.now() - parseInt(lastActivity, 10)) / 1000;
  if (elapsed > IDLE_TIMEOUT_SECONDS) {
    // Session idle too long — revoke it
    await redis.set(`${KEY_SESSION_REVOKED}${decoded.jti}`, '1', { EX: 30 * 3600 });
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
  await redis.set(`${KEY_SESSION_REVOKED}${jti}`, '1', { EX: 30 * 3600 });
  // P6 — clear any stored ID-JAG subject_token so a leaked Redis snapshot
  // cannot be used by a future actor against the same session jti.
  await redis.del(`${KEY_SESSION_IDJAG_SUBJECT}${jti}`);
}

/**
 * Revoke all sessions for a specific user. Bumps the per-user epoch so
 * tokens issued before the bump (including legacy tokens that were never
 * tracked in the per-user JTI set) fail verification on next use.
 * Also marks every tracked JTI as revoked for fast-path rejection.
 */
export async function revokeAllUserSessions(
  tenantId: string,
  userId: string,
): Promise<number> {
  const redis = getRedis();
  const userKey = `${KEY_USER_SESSIONS}${tenantId}:${userId}`;

  // ALWAYS bump the user epoch (timestamp) AND increment the revocation
  // version (monotonic counter). The counter is the primary check —
  // immune to same-ms races. The timestamp is retained as a defense-in-depth
  // signal for audit / forensics.
  await redis.set(`${KEY_USER_EPOCH}${tenantId}:${userId}`, Date.now().toString());
  await bumpUserRevocationVersion(tenantId, userId);

  const jtis = await redis.sMembers(userKey);
  if (jtis.length === 0) return 0;

  const pipeline = redis.multi();
  for (const jti of jtis) {
    pipeline.set(`${KEY_SESSION_REVOKED}${jti}`, '1', { EX: 30 * 3600 });
    // Forced logout MUST also clear the ID-JAG subject_token blob for
    // every revoked session so a Redis snapshot inside the natural TTL
    // window cannot leak the user's still-valid OIDC ID token or SAML
    // assertion (mirrors revokeSession's per-jti cleanup).
    pipeline.del(`${KEY_SESSION_IDJAG_SUBJECT}${jti}`);
  }
  pipeline.del(userKey);
  await pipeline.exec();

  return jtis.length;
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
  const redis = getRedis();
  await redis.set(`${KEY_REFRESH_TOKEN}${hash}`, JSON.stringify(payload), {
    EX: REFRESH_TOKEN_TTL_SECONDS,
  });
  // Per-user refresh-token index — enables revokeAllUserRefreshTokens to wipe
  // every refresh token a user holds (stolen-token recovery, force-logout, etc.)
  await redis.sAdd(`${KEY_USER_REFRESH_TOKENS}${tenantId}:${userId}`, hash);
  await redis.expire(
    `${KEY_USER_REFRESH_TOKENS}${tenantId}:${userId}`,
    REFRESH_TOKEN_TTL_SECONDS + 3600,
  );
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
  const redis = getRedis();
  // GETDEL is atomic — eliminates the GET+DEL race where two concurrent
  // requests both read the token before either delete lands.
  const value = await redis.getDel(`${KEY_REFRESH_TOKEN}${hash}`);
  if (!value) return null;
  let parsed: RefreshTokenPayload;
  try {
    parsed = JSON.parse(value) as RefreshTokenPayload;
  } catch {
    return null;
  }

  // Remove from the per-user index so the set doesn't grow unbounded.
  // Best-effort: failure here doesn't compromise security (the token is
  // already deleted from the lookup key).
  try {
    await redis.sRem(`${KEY_USER_REFRESH_TOKENS}${parsed.tenantId}:${parsed.userId}`, hash);
  } catch {
    // ignore
  }

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

  const setKey = `${KEY_USER_REFRESH_TOKENS}${tenantId}:${userId}`;
  const hashes = await redis.sMembers(setKey);
  if (hashes.length === 0) return 0;

  const pipeline = redis.multi();
  for (const hash of hashes) {
    pipeline.del(`${KEY_REFRESH_TOKEN}${hash}`);
  }
  pipeline.del(setKey);
  await pipeline.exec();

  return hashes.length;
}

/**
 * Revoke a refresh token without consuming it (e.g., on logout).
 * No-ops silently if the token is already gone. Also cleans the per-user
 * index entry — best-effort: index drift doesn't compromise security since
 * the per-token key is the authoritative lookup.
 */
export async function revokeRefreshToken(raw: string): Promise<void> {
  const hash = hashRefreshToken(raw);
  const redis = getRedis();
  // Read the payload first so we can clean the per-user index entry too.
  const value = await redis.get(`${KEY_REFRESH_TOKEN}${hash}`);
  await redis.del(`${KEY_REFRESH_TOKEN}${hash}`);
  if (value) {
    try {
      const parsed = JSON.parse(value) as RefreshTokenPayload;
      await redis.sRem(
        `${KEY_USER_REFRESH_TOKENS}${parsed.tenantId}:${parsed.userId}`,
        hash,
      );
    } catch {
      // ignore — index cleanup is best-effort
    }
  }
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
  const { encrypted, iv } = encryptFields({
    token: record.token,
    type: record.type,
    exp: String(record.exp),
    issuer: record.issuer,
  }, tenantId);
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
  const { decryptFields } = await import('../crypto.js');
  const decrypted = decryptFields(blob.encrypted, blob.iv, tenantId);
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
