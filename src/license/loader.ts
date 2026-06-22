/**
 * License file loader and validator.
 *
 * The on-disk envelope at ~/.epic-ai/chariot.license is JSON:
 *   { "jwt": "<compact JWT>", "renewal_secret": "<base64url>" }
 *
 * The JWT is signed by the ProtectNIL license signing key (Ed25519, EdDSA)
 * and verified locally against the embedded public key using Node's
 * built-in crypto.verify (sync). The renewal_secret is consumed by the
 * renewal client (Day 4 of the build plan); this loader only validates
 * the JWT half.
 *
 * Spec references:
 *   - chariot-billing-service-april-2026.md §5.1 (envelope shape, claims)
 *   - chariot-entitlement-and-encryption-april-2026.md §3.2 (canonical JWT)
 *   - CHARIOT-ADMIN-UX-SPEC.md §5 (UNLICENSED/LICENSED/GRACE/DEGRADED)
 *
 * JTI revocation list — signed revocation manifest at
 *   <packageRoot>/license/revocations.json. Absent file = empty list.
 * nbf (not-before) check added to verifyAndDecode. Leeway = 60s.
 * Optional tenantId param added to validateLicense(). Mismatch rejects.
 */

import { readFileSync, existsSync, writeFileSync, mkdirSync, renameSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { loadNativeBinding, getBindingLoadError } from './binding.js';
import { PromptCache } from '../engine/resilience/PromptCache.js';

/** Grace period: 14 calendar days (CHARIOT-ADMIN-UX-SPEC §5 — single source of truth) */
const GRACE_PERIOD_DAYS = 14;

/** Leeway for nbf (not-before) check — 60 seconds. */
const NBF_LEEWAY_SECONDS = 60;

// ── JTI Revocation List ─────────────────────────────────────────
//
// Schema: { schemaVersion: 1, signedAt: ISO8601, signature: base64url,
//           revoked: [{ jti, reason, revokedAt }] }
//
// The list is signed using the same Ed25519 key chain that signs licenses.
// At validation time:
//   1. Read the file (absent → treat as empty list; do NOT fail open noisily).
//   2. Verify the Ed25519 signature over the canonical payload.
//      Payload is JSON.stringify({ schemaVersion, signedAt, revoked }).
//   3. If signature fails → treat as empty list (cannot trust content).
//      This fails CLOSED on a JTI that should be revoked but can't be
//      confirmed — the worst realistic case is a stale revocation file
//      where the revoked JTI is NOT in the (unsigned/untrusted) list.
//      An operator who intentionally swaps out the file must also forge
//      the signature, which requires the private signing key.
//   4. Reject any license whose jti appears in revoked[].
//
// Storage: <packageRoot>/license/revocations.json. The package root is
// expected to be writable by the host service; on the production deployment
// the host's systemd unit must list packageRoot in ReadWritePaths.

/** TTL for the parsed-and-verified revocation Set (D1). 5 minutes. */
const REVOCATION_LIST_TTL_MS = 300_000;

/**
 * Module-level revocation cache (D1).
 * Keyed by filePath so that different paths (e.g. test overrides via
 * overridePath / CHARIOT_REVOCATION_LIST_PATH) never serve each other's
 * cached Set. Invalidation per entry: mtime change OR TTL expiry.
 *
 * Previously this was a single nullable object keyed only by mtime+TTL,
 * which meant a second call with a DIFFERENT filePath but identical mtime
 * could receive a stale Set from the first path — wrong revocation list.
 */
const revocationCacheByPath = new Map<string, { set: Set<string>; mtime: number; loadedAt: number }>();

/**
 * Reset the revocation cache (for tests).
 *
 * @internal — test-only. Not part of the public Chariot API surface.
 * Do not call from production code; invalidation is TTL- and mtime-driven.
 */
export function __resetRevocationCache(): void {
  revocationCacheByPath.clear();
}

/** Configurable revocation list path — overridable for tests via env var. */
function getRevocationListPath(): string {
  if (process.env.CHARIOT_REVOCATION_LIST_PATH) {
    return process.env.CHARIOT_REVOCATION_LIST_PATH;
  }
  // Resolve relative to package root: this file compiles to dist/license/loader.js
  // so packageRoot is two levels up from import.meta.url's directory.
  const here = new URL('.', import.meta.url).pathname;
  return join(here, '..', '..', 'license', 'revocations.json');
}

interface RevocationEntry {
  jti: string;
  reason: string;
  revokedAt: string;
}

interface RevocationList {
  schemaVersion: number;
  signedAt: string;
  signature: string;
  revoked: RevocationEntry[];
}

/**
 * Load and verify the JTI revocation list.
 * Returns the set of revoked JTIs, or an empty Set on any failure
 * (missing file, parse error, bad signature). Never throws.
 *
 * Performance (D1): the parsed-and-verified Set is cached with a 5-minute TTL.
 * On each call we do a cheap statSync to compare mtime; if mtime is unchanged
 * AND the cache is within TTL, the cached Set is returned directly (O(1)).
 * The full read+parse+verify path runs only on the first call and after
 * mtime changes or TTL expiry.
 *
 * Performance (D2): Ed25519 key objects are drawn from the shared
 * getCachedPublicKeys() helper — createPublicKey is never called inside this
 * function; key construction happens at most once per accepted key per process.
 *
 * @param overridePath - Optional path override (for tests).
 */
export function loadRevocationList(overridePath?: string): Set<string> {
  const filePath = overridePath ?? getRevocationListPath();

  // D1: check mtime before deciding to re-read.
  // Single statSync replaces the previous existsSync + statSync pair — the
  // existsSync internally did a stat, making it a doubled syscall on the hot
  // path.  ENOENT on statSync is the canonical "file absent" signal.
  let currentMtime: number;
  try {
    currentMtime = statSync(filePath).mtimeMs;
  } catch {
    return new Set();
  }

  const now = Date.now();
  const cached = revocationCacheByPath.get(filePath);
  if (
    cached !== undefined &&
    cached.mtime === currentMtime &&
    now - cached.loadedAt < REVOCATION_LIST_TTL_MS
  ) {
    // Cache hit — same path, mtime unchanged, within TTL.
    return cached.set;
  }

  // Cache miss: read, parse, and verify.
  let raw: string;
  try {
    raw = readFileSync(filePath, 'utf-8');
  } catch {
    return new Set();
  }

  let list: RevocationList;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return new Set();
    const r = parsed as Record<string, unknown>;
    if (
      r.schemaVersion !== 1 ||
      typeof r.signedAt !== 'string' ||
      typeof r.signature !== 'string' ||
      !Array.isArray(r.revoked)
    ) {
      return new Set();
    }
    list = {
      schemaVersion: 1,
      signedAt: r.signedAt as string,
      signature: r.signature as string,
      revoked: (r.revoked as unknown[]).filter(
        (e): e is RevocationEntry =>
          !!e &&
          typeof e === 'object' &&
          typeof (e as Record<string, unknown>).jti === 'string' &&
          typeof (e as Record<string, unknown>).reason === 'string' &&
          typeof (e as Record<string, unknown>).revokedAt === 'string',
      ),
    };
  } catch {
    return new Set();
  }

  // Verify signature: payload is the canonical JSON of { schemaVersion, signedAt, revoked }
  const canonical = JSON.stringify({
    schemaVersion: list.schemaVersion,
    signedAt: list.signedAt,
    revoked: list.revoked,
  });

  let sigOk = false;
  try {
    const sigBuf = Buffer.from(list.signature, 'base64url');
    const payload = Buffer.from(canonical, 'utf-8');
    // D2: getCachedPublicKeys() — no createPublicKey inside this loop.
    for (const key of getCachedPublicKeys()) {
      if (verify(null, payload, key, sigBuf)) {
        sigOk = true;
        break;
      }
    }
  } catch {
    // Signature check failed — treat as empty
  }

  if (!sigOk) return new Set();

  const resultSet = new Set(list.revoked.map((e) => e.jti));
  // Populate cache keyed by filePath only after a successful (signature-verified) read.
  revocationCacheByPath.set(filePath, { set: resultSet, mtime: currentMtime, loadedAt: now });
  return resultSet;
}

export type LicenseMode = 'unlicensed' | 'licensed' | 'grace' | 'degraded';

export interface LicenseInfo {
  valid: boolean;
  companyId?: string;
  companyName?: string;
  totalSeats?: number;
  issuedAt?: string;
  expiresAt?: string;
  graceEndsAt?: string;
  licenseEpoch?: number;
  minSecurityEpoch?: number;
  reason?: string;
  mode: LicenseMode;
}

const LICENSE_FILENAME = 'chariot.license';
const CONFIG_DIR = '.epic-ai';
const STATE_DIR = 'state';
const LICENSE_EPOCH_FILE = 'license_epoch';

/**
 * Embedded ProtectNIL license signing public keys, keyed by `kid`.
 *
 * Production rotation: add the new key alongside the old, ship a release,
 * reissue all active licenses with the new `kid`, then drop the old entry
 * in the next major release. v1 ships a single key; the JWT header `kid`
 * is recorded so future rotations are observable per-license. See
 * chariot-entitlement-and-encryption-april-2026.md §12 billing-service v1
 * exception (added 2026-04-30).
 */
const ACCEPTED_KEYS_PEM: Record<string, string> = {
  'f8b8f6f64a6c43adec00dfff648cf93d6a8e2703122098db46e15c297f2219d0':
    '-----BEGIN PUBLIC KEY-----\n' +
    'MCowBQYDK2VwAyEACBR74DxcFEvMcBO0YOxA9q5X/75uLAh3Z1CHOg2dHEc=\n' +
    '-----END PUBLIC KEY-----',
};

// ── Shared public-key cache (D2) ──────────────────────────────────────────
//
// createPublicKey is called EXACTLY once per accepted key per process lifetime.
// Both verifyAndDecode (via getPublicKey) and loadRevocationList (via
// getCachedPublicKeys) draw from the same Map — no duplicate construction.

let _publicKeyCache: Map<string, KeyObject> | null = null;

function _ensurePublicKeyCache(): Map<string, KeyObject> {
  if (!_publicKeyCache) {
    _publicKeyCache = new Map();
    for (const [k, pem] of Object.entries(ACCEPTED_KEYS_PEM)) {
      _publicKeyCache.set(k, createPublicKey(pem));
    }
  }
  return _publicKeyCache;
}

/** Return the KeyObject for a given kid, or null if unknown. */
function getPublicKey(kid: string | undefined): KeyObject | null {
  if (!kid) return null;
  return _ensurePublicKeyCache().get(kid) ?? null;
}

/** Return all accepted KeyObjects as an array (for iteration in revocation verify). */
function getCachedPublicKeys(): KeyObject[] {
  return Array.from(_ensurePublicKeyCache().values());
}

interface Envelope {
  jwt: string;
  renewal_secret: string;
}

function getLicensePath(): string {
  return join(homedir(), CONFIG_DIR, LICENSE_FILENAME);
}

function sanitizeCompanyIdForPath(companyId: string): string {
  // Map any non-[A-Za-z0-9_-] character to '_' to keep the per-company
  // epoch file inside the state dir. Length-cap at 96 to avoid filesystem
  // path limits on companyIds embedding UUIDs + slugs.
  return companyId.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 96);
}

function getLicenseEpochStatePath(companyId?: string): string {
  // per-tenant epoch floor — single file across tenants creates a
  // cross-block where tenant A's higher epoch rejects tenant B's legitimate
  // lower epoch. Per-companyId path scopes the floor to the issuing entity.
  // Legacy single-tenant deployments continue to use the unscoped file when
  // companyId is omitted (read path falls back when scoped file is absent).
  if (companyId && companyId.length > 0) {
    return join(homedir(), CONFIG_DIR, STATE_DIR, `${LICENSE_EPOCH_FILE}.${sanitizeCompanyIdForPath(companyId)}`);
  }
  return join(homedir(), CONFIG_DIR, STATE_DIR, LICENSE_EPOCH_FILE);
}

/**
 * Read the highest license_epoch ever accepted for this companyId on
 * this host. Missing/corrupt → 0 (accept any incoming epoch). When
 * companyId is provided and no scoped file exists, falls back to the
 * legacy unscoped file so a pre-upgrade deployment keeps its floor.
 */
export function readPersistedLicenseEpoch(companyId?: string): number {
  const p = getLicenseEpochStatePath(companyId);
  let usePath = p;
  if (!existsSync(usePath) && companyId) {
    const legacy = getLicenseEpochStatePath();
    if (!existsSync(legacy)) return 0;
    usePath = legacy;
  } else if (!existsSync(usePath)) {
    return 0;
  }
  try {
    const raw = readFileSync(usePath, 'utf-8').trim();
    const n = parseInt(raw, 10);
    if (!Number.isFinite(n) || n < 0) return 0;
    return n;
  } catch {
    return 0;
  }
}

/**
 * Atomically write the new high-water license_epoch to disk. Write to
 * a temp file then rename so a crash mid-write cannot leave a half-
 * written value that future reads would interpret as 0.
 */
export function persistLicenseEpoch(epoch: number, companyId?: string): void {
  const p = getLicenseEpochStatePath(companyId);
  const dir = join(homedir(), CONFIG_DIR, STATE_DIR);
  try {
    mkdirSync(dir, { recursive: true });
    const tmp = `${p}.tmp.${process.pid}`;
    writeFileSync(tmp, String(epoch), { encoding: 'utf-8', mode: 0o600 });
    renameSync(tmp, p);
  } catch (err) {
    // persistence of the license-epoch floor is anti-rollback
    // defense-in-depth. Previously this caught and console.error'd, which
    // let renewal callers declare success while the floor stayed stale;
    // on next restart the new JWT was rejected as a rollback. Throwing
    // forces validateLicense / activate / renew-client to surface the
    // failure to operators instead of silently degrading.
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Failed to persist license_epoch floor to ${p}: ${msg}. ` +
      'Remediate the underlying write failure (perms, disk space, ' +
      'ProtectSystem readwrite path) before retrying renewal.',
    );
  }
}

function readEnvelope(): Envelope | null {
  const licensePath = getLicensePath();
  if (!existsSync(licensePath)) return null;

  try {
    const content = readFileSync(licensePath, 'utf-8');
    const parsed: unknown = JSON.parse(content);
    if (!parsed || typeof parsed !== 'object') return null;
    const r = parsed as { jwt?: unknown; renewal_secret?: unknown };
    if (typeof r.jwt !== 'string' || typeof r.renewal_secret !== 'string') {
      return null;
    }
    return { jwt: r.jwt, renewal_secret: r.renewal_secret };
  } catch {
    return null;
  }
}

function isoDateFromUnix(unix: number): string {
  return new Date(unix * 1000).toISOString().split('T')[0];
}

function computeGraceEndsAt(expiresAtIso: string): string {
  const expires = new Date(expiresAtIso);
  const graceEnds = new Date(expires.getTime() + GRACE_PERIOD_DAYS * 86400 * 1000);
  return graceEnds.toISOString().split('T')[0];
}

function isDatePast(dateStr: string): boolean {
  const now = new Date().toISOString().split('T')[0];
  return dateStr < now;
}

export interface VerifiedClaims {
  companyId: string;
  companyName?: string;
  totalSeats?: number;
  tier?: string;
  slaTier?: string;
  jti?: string;
 /** tenantId claim from the JWT payload, when present. */
  tenantId?: string;
  issuedAtIso: string;
  expiresAtIso: string;
  expUnix: number;
 /** nbf Unix timestamp from the JWT payload, if present. */
  nbfUnix?: number;
  iss: string;
  licenseEpoch: number;
  minSecurityEpoch: number;
}

/**
 * Verify the JWT signature with Node's built-in Ed25519 verify and decode
 * the claims. Returns null on any failure (bad format, unknown kid,
 * signature invalid, missing required claims, wrong issuer). Does NOT
 * check expiration — caller routes to GRACE/DEGRADED based on `expUnix`.
 *
 * Exported for use by `chariot license activate` and the renewal client,
 * which need to verify a freshly-received JWT before writing it to disk.
 */
export function verifyAndDecode(jwt: string): VerifiedClaims | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;

  let header: { kid?: string; alg?: string; typ?: string };
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf-8'));
  } catch {
    return null;
  }
  if (header.alg !== 'EdDSA') return null;

  const key = getPublicKey(header.kid);
  if (!key) return null;

  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf-8');
  const signature = Buffer.from(sigB64, 'base64url');

  let ok: boolean;
  try {
    ok = verify(null, signingInput, key, signature);
  } catch {
    return null;
  }
  if (!ok) return null;

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
  } catch {
    return null;
  }

  const iss = typeof payload.iss === 'string' ? payload.iss : null;
  const sub = typeof payload.sub === 'string' ? payload.sub : null;
  const exp = typeof payload.exp === 'number' ? payload.exp : null;
  if (iss !== 'license.epic-ai.io' || !sub || !exp) return null;

  const iat = typeof payload.iat === 'number' ? payload.iat : exp;
  const nbfUnix = typeof payload.nbf === 'number' ? payload.nbf : undefined;
  const seats = typeof payload.seats === 'number' ? payload.seats : undefined;
  const companyName =
    typeof payload.company_name === 'string' ? payload.company_name : undefined;
  const tier = typeof payload.tier === 'string' ? payload.tier : undefined;
  const slaTier =
    typeof payload.sla_tier === 'string' ? payload.sla_tier : undefined;
  const jti = typeof payload.jti === 'string' ? payload.jti : undefined;
  // JWT carries `tenant_id` (snake_case per RFC 7519 convention).
  // Accept either `tenant_id` (canonical) or `tenantId` (legacy camelCase
  // legacy bootstrap-issued JWTs) to keep existing licenses valid.
  const tenantId =
    typeof payload.tenant_id === 'string'
      ? payload.tenant_id
      : typeof payload.tenantId === 'string'
        ? payload.tenantId
        : undefined;
  const licenseEpoch =
    typeof payload.license_epoch === 'number' && payload.license_epoch >= 0
      ? payload.license_epoch
      : -1;
  const minSecurityEpoch =
    typeof payload.min_security_epoch === 'number' && payload.min_security_epoch >= 0
      ? payload.min_security_epoch
      : -1;
  // Reject unsigned-by-billing-pipeline JWTs that are missing or malformed
  // license_epoch / min_security_epoch. Both claims are required by
  // chariot-billing-service §5.1 and chariot-entitlement-and-encryption §3.2.
  if (licenseEpoch < 0 || minSecurityEpoch < 0) return null;

 // nbf (not-before) check. Reject if now + leeway < nbf.
  // Leeway = 60s to tolerate minor clock skew across issuer and validator.
  // If nbf is absent, skip the check (backward-compat with legacy licenses).
  if (nbfUnix !== undefined) {
    const nowUnixForNbf = Math.floor(Date.now() / 1000);
    if (nowUnixForNbf + NBF_LEEWAY_SECONDS < nbfUnix) {
      return null;
    }
  }

  return {
    companyId: sub,
    companyName,
    totalSeats: seats,
    tier,
    slaTier,
    jti,
    tenantId,
    issuedAtIso: isoDateFromUnix(iat),
    expiresAtIso: isoDateFromUnix(exp),
    expUnix: exp,
    nbfUnix,
    iss,
    licenseEpoch,
    minSecurityEpoch,
  };
}

/** Path to the canonical license file: ~/.epic-ai/chariot.license. */
export function licenseFilePath(): string {
  return getLicensePath();
}

/** Public envelope read; returns null if missing or malformed. */
export function readLicenseEnvelope(): { jwt: string; renewal_secret: string } | null {
  return readEnvelope();
}

// ── License validation cache (D3) ─────────────────────────────────────────
//
// Keyed by tenantId; empty string '' represents the no-tenantId (single-tenant)
// call path. Each entry carries the LicenseInfo and a 60s TTL per slot.
// This allows validateLicense('tenant-A') and validateLicense('tenant-B') and
// validateLicense() to each maintain an independent 60s cache slot without
// cross-contamination.
//
// PromptCache<LicenseInfo> replaces the previous bespoke Map<string, { info,
// expiresAt }> (REUSE #4).  It provides:
//   - Bounded size (LICENSE_CACHE_MAX_ENTRIES = 10 000, matching tenantBuckets
//     cap) so the cache cannot grow without bound in a high-tenancy deployment.
//   - LRU eviction when the cap is reached, so the oldest-accessed tenant slot
//     is dropped rather than a random or the newest one.
//   - Per-entry TTL via set(key, value, ttlMs) — each slot still gets its own
//     60s window, identical to the prior Map behaviour.
//
// Operations used here: get(key) → T | null, set(key, value, ttlMs), clear(),
// invalidate(key). All are present on PromptCache<T>.

const CACHE_TTL_MS = 60_000;
const LICENSE_CACHE_MAX_ENTRIES = 10_000;

const _licenseCache = new PromptCache<LicenseInfo>({
  maxEntries: LICENSE_CACHE_MAX_ENTRIES,
  defaultTTLMs: CACHE_TTL_MS,
});

/**
 * Reset the entire license cache (for tests).
 *
 * @internal — test-only. Not part of the public Chariot API surface.
 * Do not call from production code; cache entries expire automatically via TTL.
 */
export function __resetLicenseCache(): void {
  _licenseCache.clear();
}

/**
 * Invalidate a single tenant's license cache slot. Distinct from
 * `__resetLicenseCache()` (which clears every tenant) — used from
 * `revalidateLicense(tenantId)` so one tenant's renewal does not force
 * unrelated tenants to re-validate from disk.
 *
 * @internal — used by revalidateLicense.
 */
function invalidateLicenseCacheSlot(tenantId?: string): void {
  _licenseCache.invalidate(tenantId ?? '');
}

/**
 * Validate the Chariot license and return the current state.
 * Sync. Cache TTL 60s per tenant slot; call revalidateLicense() to force re-read.
 *
 * @param tenantId - Optional tenant context. When provided AND the
 *   license carries a `tenantId` claim, they must match or the license is
 *   rejected. When provided but the license has no `tenantId` claim, the
 *   license is accepted (single-tenant/legacy compatibility). When omitted,
 * behavior is unchanged from pre-versions.
 *
 * Cache (D3): keyed by tenantId ('' for the no-tenantId case). Each tenant slot
 * has its own 60s TTL. Cross-tenant isolation is guaranteed by the cache key.
 *
 * Error shape note (QUALITY #5): rejection paths (revoked JTI, nbf failure,
 * tenant mismatch, rollback attempt, expired+grace-ended) all return a plain
 * `LicenseInfo` with `{ valid: false, mode: 'unlicensed' | 'degraded' }`.
 * They do NOT carry a structured `{ code: ChariotErrorCode }` field — the
 * license layer returns a mode string rather than a thrown structured error.
 * Use the `mode` field for branch logic; use `reason` for human-readable
 * diagnostic text. If a structured code is needed by a caller, map `mode` to
 * a `CHARIOT_ERROR_CODES` constant at the call site.
 */
export function validateLicense(tenantId?: string): LicenseInfo {
  const cacheKey = tenantId ?? '';

  const cached = _licenseCache.get(cacheKey);
  if (cached !== null) {
    return cached;
  }

  // Binary-availability check. License verification itself happens in
  // pure TypeScript via Node's crypto.verify (the Ed25519 public key is
  // embedded in this module), so license validity does NOT require the
  // binary. The binary is required for downstream enterprise features
  // (encrypted adapter blobs, RBAC binding, internal API discovery),
  // which call requireNativeBinding() at their own call sites.
  //
  // Only one case still throws here: CHARIOT_ENTERPRISE=true was set
  // explicitly but the binary is missing or broken. That is a
  // misconfiguration the operator wants to know about at startup.
  const binding = loadNativeBinding();
  if (!binding && process.env.CHARIOT_ENTERPRISE === 'true') {
    const loadError = getBindingLoadError();
    throw new Error(
      `Chariot enterprise startup failed: ${loadError || 'native binary not available'}. ` +
        'CHARIOT_ENTERPRISE=true requires a working native binary. ' +
        'Install the matching platform binary or unset CHARIOT_ENTERPRISE to run in single-user mode.',
    );
  }

  /** Write an info object to the per-tenant cache slot and return it. */
  function cache(info: LicenseInfo): LicenseInfo {
    _licenseCache.set(cacheKey, info, CACHE_TTL_MS);
    return info;
  }

  const envelope = readEnvelope();
  if (!envelope) {
    return cache({
      valid: false,
      mode: 'unlicensed',
      reason: binding
        ? 'No license file found'
        : 'No license file found — running in single-user mode.',
    });
  }

  const decoded = verifyAndDecode(envelope.jwt);
  if (!decoded) {
    return cache({
      valid: false,
      mode: 'unlicensed',
      reason: 'License file signature verification failed',
    });
  }

 // JTI revocation check. Load the signed revocation list and reject
  // any license whose jti appears in it. Missing file = empty list (not an
  // error). Bad signature on file = empty list (fail closed on content,
  // but do not reject non-revoked licenses just because the file is bad).
  if (decoded.jti) {
    const revokedJtis = loadRevocationList();
    if (revokedJtis.has(decoded.jti)) {
      return cache({
        valid: false,
        mode: 'unlicensed',
        reason: 'License file signature verification failed',
      });
    }
  }

 // Tenant identity check. When the caller provides a tenantId AND
  // the license carries a tenantId claim, they must match exactly.
  // When the license has no tenantId claim, accept (single-tenant legacy).
  // When caller provides no tenantId, skip (existing single-tenant behavior).
  if (tenantId !== undefined && decoded.tenantId !== undefined) {
    if (decoded.tenantId !== tenantId) {
      // emit a specific reason so operators can distinguish a
      // tenant-mismatch from an actual signature failure. The signature
      // is valid; the license is just not issued for this caller's tenant.
      return cache({
        valid: false,
        mode: 'unlicensed',
        reason:
          'License tenantId does not match expected tenant ' +
          '(license is signed for a different tenant; the signature itself is valid).',
      });
    }
  }

  // Anti-rollback: reject a signed-but-stale license whose license_epoch
  // is below the highest we've already accepted on this host. Defends
  // against an attacker (or a customer accidentally restoring an old
  // backup) replacing the license file with a previously-valid one.
  // Spec: chariot-entitlement-and-encryption-april-2026.md §3.4 step 3
  // (catalog form) — the license-side analog defined in this commit.
  const persistedEpoch = readPersistedLicenseEpoch(decoded.companyId);
  if (decoded.licenseEpoch < persistedEpoch) {
    return cache({
      valid: false,
      mode: 'unlicensed',
      reason: 'License file signature verification failed',
    });
  }

  // Persist new high-water mark on first observation. Done before the
  // expiry check so even an expired-but-newer license bumps the floor —
  // we never want to retreat. persistLicenseEpoch now throws
  // on write failure; treat that as unlicensed so callers cannot
  // mistake a silently-degraded anti-rollback for a valid license.
  if (decoded.licenseEpoch > persistedEpoch) {
    try {
      persistLicenseEpoch(decoded.licenseEpoch, decoded.companyId);
    } catch (err) {
      return cache({
        valid: false,
        mode: 'unlicensed',
        reason:
          'License accepted but license_epoch floor write failed; ' +
          'anti-rollback defense-in-depth is degraded. ' +
          (err instanceof Error ? err.message : String(err)),
      });
    }
  }

  const nowUnix = Math.floor(Date.now() / 1000);
  if (decoded.expUnix < nowUnix) {
    const graceEndsAt = computeGraceEndsAt(decoded.expiresAtIso);
    if (!isDatePast(graceEndsAt)) {
      return cache({
        valid: true,
        mode: 'grace',
        companyId: decoded.companyId,
        companyName: decoded.companyName,
        totalSeats: decoded.totalSeats,
        issuedAt: decoded.issuedAtIso,
        expiresAt: decoded.expiresAtIso,
        graceEndsAt,
        licenseEpoch: decoded.licenseEpoch,
        minSecurityEpoch: decoded.minSecurityEpoch,
        reason: 'License expired — grace period active',
      });
    } else {
      return cache({
        valid: false,
        mode: 'degraded',
        companyId: decoded.companyId,
        companyName: decoded.companyName,
        totalSeats: decoded.totalSeats,
        issuedAt: decoded.issuedAtIso,
        expiresAt: decoded.expiresAtIso,
        graceEndsAt,
        licenseEpoch: decoded.licenseEpoch,
        minSecurityEpoch: decoded.minSecurityEpoch,
        reason: 'License expired and grace period ended',
      });
    }
  }

  return cache({
    valid: true,
    mode: 'licensed',
    companyId: decoded.companyId,
    companyName: decoded.companyName,
    totalSeats: decoded.totalSeats,
    issuedAt: decoded.issuedAtIso,
    expiresAt: decoded.expiresAtIso,
    licenseEpoch: decoded.licenseEpoch,
    minSecurityEpoch: decoded.minSecurityEpoch,
  });
}

/**
 * Force re-validation of the license (bypasses cache). Invalidates only
 * the cache slot for the given tenantId so a renewal for one tenant does
 * not force unrelated tenants to re-validate from disk.
 *
 * @param tenantId - Optional tenant context passed through to validateLicense.
 */
export function revalidateLicense(tenantId?: string): LicenseInfo {
  invalidateLicenseCacheSlot(tenantId);
  return validateLicense(tenantId);
}

/**
 * Check if the current license supports the given number of active users.
 * UNLICENSED and DEGRADED allow 1 seat. LICENSED and GRACE allow totalSeats.
 */
export function checkSeatLimit(activeUserCount: number): {
  allowed: boolean;
  totalSeats: number;
  activeUsers: number;
  remaining: number;
} {
  const license = validateLicense();

  if (license.mode === 'unlicensed' || license.mode === 'degraded') {
    return {
      allowed: activeUserCount <= 1,
      totalSeats: 1,
      activeUsers: activeUserCount,
      remaining: Math.max(0, 1 - activeUserCount),
    };
  }

  const totalSeats = license.totalSeats ?? 1;
  return {
    allowed: activeUserCount <= totalSeats,
    totalSeats,
    activeUsers: activeUserCount,
    remaining: Math.max(0, totalSeats - activeUserCount),
  };
}
