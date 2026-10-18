/**
 * License file loader and validator.
 *
 * The on-disk envelope at ~/.epic-ai/chariot.license is JSON:
 *   { "jwt": "<compact JWT>", "renewal_secret": "<base64url>",
 *     "seal_secret"?: "<standard base64 of 32 bytes>" }
 * (`seal_secret` is the optional §5.7 per-licence secret root; see
 * `LicenseEnvelope`. It never affects licence validity.)
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
 * nbf (not-before) is read (`nbfUnix`) but NOT enforced — CHARIOT::§11.1::10
 * states it "rides the JWT for downstream consumers and audit" and "is not
 * consulted by the loader at all."
 * Optional tenantId param added to validateLicense(). Mismatch rejects.
 */

import { readFileSync, existsSync, writeFileSync, mkdirSync, renameSync, statSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { loadNativeBinding, getBindingLoadError } from './binding.js';
import { PromptCache } from '../engine/resilience/PromptCache.js';
import { CLIENT_SECURITY_EPOCH } from './security-epoch.js';
import { chariotEmitter } from '../observability/emitter.js';

/** Grace period: 14 calendar days (CHARIOT-ADMIN-UX-SPEC §5 — single source of truth) */
const GRACE_PERIOD_DAYS = 14;

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
 * Last-known-good revocation copy (host-level, signature-verified).
 *
 * The primary revocation list lives on a filesystem the licensee controls, so
 * `rm revocations.json` (or truncation) would otherwise silently drop the
 * revoked-JTI set to empty — defeating revocation against exactly the adversary
 * it targets. Once a signature-verified list has EVER been seen on this host we
 * persist an immutable copy here; if the primary later goes missing/corrupt we
 * fall back to it (fail CLOSED to the last trusted list) instead of empty.
 * A signed-but-OLDER primary (rollback that omits a jti) is likewise rejected
 * in favor of the newer persisted copy via a monotonic signedAt check.
 */
const REVOCATION_LKG_FILE = 'revocations.lkg.json';

function getRevocationLkgPath(): string {
  return join(homedir(), CONFIG_DIR, STATE_DIR, REVOCATION_LKG_FILE);
}

/**
 * Parse, schema-check, and Ed25519-verify a revocation-list JSON string.
 * Returns the revoked-JTI set plus its signedAt, or null on any failure
 * (bad JSON, bad schema, bad signature). Never throws.
 */
function verifyRevocationRaw(raw: string): { set: Set<string>; signedAt: string } | null {
  let list: RevocationList;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    const r = parsed as Record<string, unknown>;
    if (
      r.schemaVersion !== 1 ||
      typeof r.signedAt !== 'string' ||
      typeof r.signature !== 'string' ||
      !Array.isArray(r.revoked)
    ) {
      return null;
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
    return null;
  }

  // Payload is the canonical JSON of { schemaVersion, signedAt, revoked }.
  const canonical = JSON.stringify({
    schemaVersion: list.schemaVersion,
    signedAt: list.signedAt,
    revoked: list.revoked,
  });

  let sigOk = false;
  try {
    const sigBuf = Buffer.from(list.signature, 'base64url');
    const payload = Buffer.from(canonical, 'utf-8');
    for (const key of getCachedPublicKeys()) {
      if (verify(null, payload, key, sigBuf)) {
        sigOk = true;
        break;
      }
    }
  } catch {
    // signature check threw — treat as unverifiable
  }
  if (!sigOk) return null;

  return { set: new Set(list.revoked.map((e) => e.jti)), signedAt: list.signedAt };
}

/** signedAt → epoch ms, or -Infinity when unparseable (never wins a monotonic compare). */
function signedAtMs(signedAt: string): number {
  const t = Date.parse(signedAt);
  return Number.isFinite(t) ? t : -Infinity;
}

/** Read + verify the last-known-good revocation copy, or null if absent/invalid. */
function loadLkgRevocation(): { set: Set<string>; signedAt: string } | null {
  try {
    const raw = readFileSync(getRevocationLkgPath(), 'utf-8');
    return verifyRevocationRaw(raw);
  } catch {
    return null;
  }
}

/**
 * Persist a signature-verified revocation list as the new last-known-good copy,
 * but only when it is at least as new as the existing copy (monotonic signedAt).
 * Best-effort: this is anti-tamper defense-in-depth, never a hard dependency, so
 * a write failure is swallowed. `raw` is the exact verified bytes.
 */
function persistLkgRevocation(raw: string, signedAt: string): void {
  try {
    const existing = loadLkgRevocation();
    if (existing && signedAtMs(existing.signedAt) >= signedAtMs(signedAt)) {
      return; // do not regress the high-water revocation list
    }
    const p = getRevocationLkgPath();
    const dir = join(homedir(), CONFIG_DIR, STATE_DIR);
    mkdirSync(dir, { recursive: true });
    const tmp = `${p}.tmp.${process.pid}`;
    writeFileSync(tmp, raw, { encoding: 'utf-8', mode: 0o600 });
    renameSync(tmp, p);
  } catch {
    // best-effort — the primary list already verified; LKG is a backstop
  }
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
  // path. ENOENT on statSync means the PRIMARY file is absent; unlike before we
  // do NOT immediately return an empty Set — deleting the file must not silently
  // disable revocation. We fall through to the last-known-good copy.
  let currentMtime: number | null = null;
  try {
    currentMtime = statSync(filePath).mtimeMs;
  } catch {
    currentMtime = null;
  }

  const now = Date.now();
  if (currentMtime !== null) {
    const cached = revocationCacheByPath.get(filePath);
    if (
      cached !== undefined &&
      cached.mtime === currentMtime &&
      now - cached.loadedAt < REVOCATION_LIST_TTL_MS
    ) {
      // Cache hit — same path, mtime unchanged, within TTL.
      return cached.set;
    }
  }

  // Read + verify the primary list (if present).
  let primaryRaw: string | null = null;
  if (currentMtime !== null) {
    try {
      primaryRaw = readFileSync(filePath, 'utf-8');
    } catch {
      primaryRaw = null;
    }
  }
  const primary = primaryRaw !== null ? verifyRevocationRaw(primaryRaw) : null;

  // Last-known-good copy: the newest signature-verified list this host has seen.
  const lkg = loadLkgRevocation();

  if (primary) {
    // A signed-but-OLDER primary is a rollback (an attacker restoring a stale
    // list that omits a jti already revoked). Prefer the newer persisted copy.
    if (lkg && signedAtMs(primary.signedAt) < signedAtMs(lkg.signedAt)) {
      return lkg.set;
    }
    // Primary is current/newer: adopt it as the new last-known-good and cache.
    persistLkgRevocation(primaryRaw as string, primary.signedAt);
    if (currentMtime !== null) {
      revocationCacheByPath.set(filePath, {
        set: primary.set,
        mtime: currentMtime,
        loadedAt: now,
      });
    }
    return primary.set;
  }

  // Primary absent/corrupt/unverifiable. Fail CLOSED to the last-known-good
  // verified list rather than to an empty (revocation-disabled) set.
  if (lkg) {
    return lkg.set;
  }

  // No primary and no prior trusted copy: genuine fresh install with no
  // revocations ever issued — an empty set is correct here.
  return new Set();
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
const GRACE_ALERT_STATE_FILE = 'license_grace_alert';

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

/**
 * The on-disk licence envelope (`~/.epic-ai/chariot.license`).
 *
 * `seal_secret` (OPTIONAL, dogfood-ready 4.0 contract): the per-licence
 * secret key CHARIOT-SPEC §5.7 names as one admissible §5.7 secret root ("a
 * per-license secret key or ENTERPRISE_MASTER_KEY"). It is standard padded
 * base64 of exactly 32 bytes, generated once at first issuance and never
 * rotated by renewal. It is NEVER consulted for licence validity:
 *   - absent             → `seal_secret` and `seal_secret_error` both undefined;
 *   - valid              → `seal_secret` = the canonical base64 string;
 *   - present, malformed → `seal_secret` undefined and `seal_secret_error`
 *                          set (reason + the raw JSON value, so renewal can
 *                          carry the bytes forward verbatim instead of
 *                          silently dropping them, which would flip a
 *                          sealed deployment onto the ENTERPRISE_MASTER_KEY
 *                          fallback). Sealed access fails closed on this.
 */
export interface LicenseEnvelope {
  jwt: string;
  renewal_secret: string;
  seal_secret?: string;
  seal_secret_error?: { reason: string; raw: unknown };
}

type Envelope = LicenseEnvelope;

/** Byte length a `seal_secret` must decode to. */
export const SEAL_SECRET_BYTES = 32;

/** Standard (RFC 4648 §4) padded base64 of exactly 32 bytes is 44 chars:
 * 42 full chars, one char carrying the last 2 data bits, then one `=`. */
const SEAL_SECRET_B64_RE = /^[A-Za-z0-9+/]{43}=$/;

/**
 * Validate a raw `seal_secret` JSON value. Accepts ONLY standard padded
 * base64 that decodes to exactly {@link SEAL_SECRET_BYTES} bytes AND
 * re-encodes to the identical string (rejects base64url, whitespace,
 * missing/extra padding, and non-canonical trailing bits that Node's
 * lenient decoder would otherwise silently accept). Never throws.
 */
export function validateSealSecret(
  raw: unknown,
): { ok: true; value: string } | { ok: false; reason: string } {
  if (typeof raw !== 'string') {
    return { ok: false, reason: `seal_secret must be a string, got ${raw === null ? 'null' : typeof raw}` };
  }
  if (!SEAL_SECRET_B64_RE.test(raw)) {
    return {
      ok: false,
      reason: `seal_secret must be standard padded base64 of exactly ${SEAL_SECRET_BYTES} bytes (44 characters)`,
    };
  }
  const bytes = Buffer.from(raw, 'base64');
  if (bytes.length !== SEAL_SECRET_BYTES || bytes.toString('base64') !== raw) {
    return {
      ok: false,
      reason: `seal_secret is not the canonical base64 encoding of exactly ${SEAL_SECRET_BYTES} bytes`,
    };
  }
  return { ok: true, value: raw };
}

/**
 * Parse an already-JSON-decoded envelope object. Returns null when the
 * licence half (`jwt`, `renewal_secret`) is unusable; a malformed
 * `seal_secret` NEVER nulls the envelope (see {@link LicenseEnvelope}).
 */
function envelopeFromParsed(parsed: unknown): Envelope | null {
  if (!parsed || typeof parsed !== 'object') return null;
  const r = parsed as { jwt?: unknown; renewal_secret?: unknown; seal_secret?: unknown };
  if (typeof r.jwt !== 'string' || typeof r.renewal_secret !== 'string') {
    return null;
  }
  const out: Envelope = { jwt: r.jwt, renewal_secret: r.renewal_secret };
  if (Object.prototype.hasOwnProperty.call(r, 'seal_secret')) {
    const v = validateSealSecret(r.seal_secret);
    if (v.ok) out.seal_secret = v.value;
    else out.seal_secret_error = { reason: v.reason, raw: r.seal_secret };
  }
  return out;
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

// ── GRACE-mode alert dedup state (§11.2::2, rulings item 88(3)) ───────────
//
// CHARIOT-SPEC.md:1155 — "| `GRACE` | Present, signature valid, `exp ≤ now
// ≤ exp + 14d` | All seats, all features, alert admin |". Ruling item
// 88(3): "one `license.grace_entered` per grace-period entry (state
// persisted beside the cached license), re-emitted once per 24h while in
// grace." Persisted (not in-memory) because the in-memory 60s
// `_licenseCache` slot expires far more often than 24h — an in-memory-only
// dedup would re-emit on every cache-miss-while-in-grace (roughly every
// 60s), which is exactly the over-alerting this ruling forecloses. State
// lives beside the license file, per companyId, mirroring the
// license_epoch floor's own per-company scoping and atomic tmp+rename
// write pattern above.

interface GraceAlertState {
  /** ISO timestamp of the first cache-miss that observed mode==='grace' for this companyId, since the state was last cleared. */
  enteredAt: string;
  /** ISO timestamp of the most recent license.grace_entered emission for this companyId. */
  lastAlertAt: string;
}

const GRACE_ALERT_REEMIT_MS = 24 * 60 * 60 * 1000;

function getGraceAlertStatePath(companyId?: string): string {
  if (companyId && companyId.length > 0) {
    return join(homedir(), CONFIG_DIR, STATE_DIR, `${GRACE_ALERT_STATE_FILE}.${sanitizeCompanyIdForPath(companyId)}`);
  }
  return join(homedir(), CONFIG_DIR, STATE_DIR, GRACE_ALERT_STATE_FILE);
}

/** Read the persisted grace-alert dedup state. Missing/corrupt -> null (treated as "no prior grace entry seen"). Never throws. */
function readGraceAlertState(companyId?: string): GraceAlertState | null {
  const p = getGraceAlertStatePath(companyId);
  if (!existsSync(p)) return null;
  try {
    const raw = JSON.parse(readFileSync(p, 'utf-8')) as unknown;
    if (
      raw && typeof raw === 'object' &&
      typeof (raw as Record<string, unknown>).enteredAt === 'string' &&
      typeof (raw as Record<string, unknown>).lastAlertAt === 'string'
    ) {
      return raw as GraceAlertState;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Atomically persist the grace-alert dedup state (tmp write + rename,
 * matching persistLicenseEpoch's crash-safety pattern above). Best-effort:
 * a write failure here must not block the license.grace_entered emission
 * itself (the alert is the thing operators actually need); it only risks
 * a duplicate re-emission on the next cache miss, which is the safe
 * failure direction (over-alert, never silently under-alert).
 */
function persistGraceAlertState(state: GraceAlertState, companyId?: string): void {
  const p = getGraceAlertStatePath(companyId);
  const dir = join(homedir(), CONFIG_DIR, STATE_DIR);
  try {
    mkdirSync(dir, { recursive: true });
    const tmp = `${p}.tmp.${process.pid}`;
    writeFileSync(tmp, JSON.stringify(state), { encoding: 'utf-8', mode: 0o600 });
    renameSync(tmp, p);
  } catch {
    // Best-effort — see doc comment above. Do not throw: a failed dedup
    // write must not prevent validateLicense() from returning the correct
    // LicenseInfo, and must not suppress the alert that already fired.
  }
}

/**
 * Clear the persisted grace-alert state. Called whenever a cache-miss
 * observes a mode OTHER than 'grace' (licensed, degraded, or unlicensed):
 * the license is no longer in its grace window, so a LATER re-entry into
 * grace (e.g. license renewed, then lapses again after the new exp) must
 * be treated as a fresh grace-period entry, not a continuation of the old
 * one. Best-effort delete; a leftover stale file is harmless — the
 * `enteredAt`-vs-mode-transition check in the cache() emit gate below
 * still recognizes the next entry as new because deletion (or its
 * absence) is re-derived from the CURRENT mode, not solely from the file.
 */
function clearGraceAlertState(companyId?: string): void {
  const p = getGraceAlertStatePath(companyId);
  try {
    if (existsSync(p)) {
      unlinkSync(p);
    }
  } catch {
    // best-effort, see doc comment.
  }
}

/**
 * CHARIOT §11.2::2 (rulings item 88(3)) — the grace-alert dedup DECISION,
 * extracted from `cache()`'s grace branch as its own exported, directly
 * testable function. Pure with respect to `now` (the only side effect is
 * the persisted-state READ, not a write — call `recordGraceAlertEmitted`
 * separately after actually emitting, exactly as `cache()` does below).
 *
 * Extracted specifically so this decision can be behaviorally tested
 * without a signed JWT: `validateLicense()`'s `licensed`/`grace`/
 * `degraded` branches require verifying against the embedded PRODUCTION
 * Ed25519 public key (`ACCEPTED_KEYS_PEM` above) — there is no test-key
 * override in this module, so driving `validateLicense()` itself into
 * grace mode from a test is not possible without forging a license
 * (out of scope; see `loader.taxonomy-adoption.test.ts`'s doc comment for
 * the same finding from an independent unit touching this same function).
 * This function isolates the part of the grace branch that has nothing to
 * do with JWT verification — the persisted-file dedup arithmetic — so it
 * can be driven directly instead of only via brittle source-regex
 * inspection of the compiled `cache()` body (which two different builders
 * editing this same helper concurrently already broke once).
 *
 * Returns true when: no prior grace-alert state exists for this
 * companyId (a NEW grace-period entry), OR the persisted `lastAlertAt` is
 * >= `GRACE_ALERT_REEMIT_MS` (24h) old.
 */
export function shouldEmitGraceAlert(companyId: string | undefined, now: number): boolean {
  const priorGraceState = readGraceAlertState(companyId);
  if (priorGraceState === null) return true;
  return now - Date.parse(priorGraceState.lastAlertAt) >= GRACE_ALERT_REEMIT_MS;
}

/**
 * Persist that a `license.grace_entered` alert was just emitted for
 * `companyId` at `now`. Call ONLY after actually emitting — pairs with
 * `shouldEmitGraceAlert` above (which does not itself write).
 * `enteredAt` is preserved across re-emits within the same still-open
 * grace period (first-ever call for this companyId sets it; every
 * subsequent re-emit keeps the original entry timestamp), so it always
 * answers "when did this grace period start", not "when did we last
 * alert" — that second question is `lastAlertAt`.
 */
export function recordGraceAlertEmitted(companyId: string | undefined, now: number): void {
  const priorGraceState = readGraceAlertState(companyId);
  persistGraceAlertState(
    {
      enteredAt: priorGraceState !== null ? priorGraceState.enteredAt : new Date(now).toISOString(),
      lastAlertAt: new Date(now).toISOString(),
    },
    companyId,
  );
}

/**
 * Test-only access to the grace-alert dedup state primitives (§11.2::2,
 * rulings item 88(3)) so its 24h re-emit gate can be exercised without a
 * signed JWT / real license file (the state file is keyed by companyId
 * only, independent of license validity).
 *
 * @internal — test-only. Not part of the public Chariot API surface.
 */
export const __graceAlertStateForTest = {
  path: getGraceAlertStatePath,
  read: readGraceAlertState,
  persist: persistGraceAlertState,
  clear: clearGraceAlertState,
  reemitWindowMs: GRACE_ALERT_REEMIT_MS,
};

function readEnvelope(): Envelope | null {
  const licensePath = getLicensePath();
  if (!existsSync(licensePath)) return null;

  try {
    const content = readFileSync(licensePath, 'utf-8');
    const parsed: unknown = JSON.parse(content);
    return envelopeFromParsed(parsed);
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
  /**
   * Deployment topology claim, carried for downstream consumers only
   * (CHARIOT::§11.1::10: the loader never consults it to accept or reject a
   * license). Absent when the JWT carries no recognised value — consumers
   * must treat ABSENT as undetermined, never as connected (C4AMD §8:
   * automatic telemetry transport requires a determined connected topology).
   */
  topology?: 'public-llm' | 'hybrid' | 'air-gapped';
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

 // CHARIOT::§11.1::10 — nbf is producer-emitted and rides the JWT for
  // downstream consumers and audit; the loader does not consult it. Per
  // the spec's claim table (§11.1): "nbf | number | no | Not-before
  // (= iat). Producer-emitted; jose enforces if present." and "The
  // remainder (nbf, topology, grace_days, renewal_token_hash) ride the
  // JWT for downstream consumers and audit and are not consulted by the
  // loader at all." nbfUnix is still captured above and carried into the
  // returned VerifiedClaims for those downstream consumers — it is simply
  // never used to reject a license here.
  // `topology` is decoded the same way — carried, never consulted here.
  const topologyClaim = payload.topology;
  const topology =
    topologyClaim === 'public-llm' || topologyClaim === 'hybrid' || topologyClaim === 'air-gapped'
      ? topologyClaim
      : undefined;

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
    ...(topology !== undefined ? { topology } : {}),
  };
}

/** Path to the canonical license file: ~/.epic-ai/chariot.license. */
export function licenseFilePath(): string {
  return getLicensePath();
}

/**
 * Public envelope read; returns null if missing or the licence half
 * (`jwt`/`renewal_secret`) is malformed. A malformed OPTIONAL `seal_secret`
 * is reported via `seal_secret_error`, never by returning null.
 */
export function readLicenseEnvelope(): LicenseEnvelope | null {
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
 * CHARIOT §11.4::3 — "The license loader caches the parsed license in
 * process memory for 60 seconds. ... The cache is invalidated on SIGHUP for
 * operator-driven reloads." (CHARIOT-SPEC.md:1167)
 *
 * Public, production-facing entry point for that SIGHUP-driven reload —
 * distinct from `__resetLicenseCache()` (test-only, "not part of the public
 * Chariot API surface" per its own doc comment). SIGHUP is a single global
 * operator signal with no tenant context, so — unlike
 * `revalidateLicense(tenantId)`'s single-slot invalidation — this clears
 * EVERY tenant's cache slot: an operator reloading the license file (e.g.
 * after `chariot license activate <path>`) expects every tenant's next
 * `validateLicense()` call to re-read disk, not just one.
 *
 * The signal handler itself lives in `src/engine/bin/setup.ts`'s HTTP/REST
 * keep-alive block (the long-running server process); this function is the
 * pure cache operation the handler calls.
 */
export function invalidateLicenseCache(): void {
  _licenseCache.clear();
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
/**
 * Whether the operator has requested enterprise mode via `CHARIOT_ENTERPRISE`
 * (§18.2). Enabling spellings are exactly `1` and `true`, case-insensitive and
 * surrounding-whitespace-tolerant; every other value — and unset — is disabled.
 * A security control must not switch on for anything that merely looks truthy
 * (`yes`, `on`, `2`, non-empty), and must not silently stay off when an operator
 * follows the documented `CHARIOT_ENTERPRISE=1`.
 */
export function isEnterpriseEnvEnabled(): boolean {
  const raw = process.env.CHARIOT_ENTERPRISE;
  if (raw === undefined) return false;
  const v = raw.trim().toLowerCase();
  return v === '1' || v === 'true';
}

/**
 * Decide and emit the pinned CHARIOT::§16.1 License events for a computed
 * `LicenseInfo` (rulings item 91). Called from `validateLicense`'s internal
 * `cache()` helper on a cache MISS ONLY — a cache HIT returns earlier and
 * never reaches `cache()`, so a cached/repeated lookup never re-emits.
 *
 * Extracted to a top-level, exported, pure-with-respect-to-its-inputs
 * function (chariotEmitter.send and the grace-alert dedup file are its
 * only side effects — no envelope/signature/cache dependency of its own)
 * so it is directly behaviorally testable by constructing a `LicenseInfo`
 * fixture per mode, without a signed Ed25519 license JWT: this module's
 * embedded public-key set (`ACCEPTED_KEYS_PEM`) has no matching private
 * key anywhere in this repo (production-only, held externally), and
 * `getLicensePath()` has no env-var override — see
 * `loader.invalidate-cache.test.ts`'s header comment for the same
 * constraint, previously documented for a different function. A
 * `LicenseInfo` is the ALREADY-VERIFIED plain-object output `validateLicense`
 * computes per mode; faking one for a test carries none of that signing
 * constraint, unlike faking the JWT itself would.
 *
 * Mapping, evidence-based against this file's own `reason` strings (not
 * guessed):
 *   - `mode: 'licensed'` -> `license.loaded` (no `reason` naming a
 *     failure — a genuine fresh valid load).
 *   - `mode: 'grace'` -> `license.expired` + `license.grace_entered`
 *     (this file's own `reason: 'License expired — grace period active'`
 *     literally names both facts: the license IS expired, and grace was
 *     entered as a result).
 *   - `mode: 'degraded'` -> `license.expired` + `license.degraded`
 *     (this file's own `reason: 'License expired and grace period
 *     ended'` — same evidence).
 *   - `mode: 'unlicensed'`: deliberately emits NONE of the 6 pinned
 *     License events. Every `unlicensed` return in `validateLicense` is
 *     for an absent/invalid/revoked/rolled-back/underpinned license
 *     (missing file, bad signature, revoked jti, tenant mismatch, epoch
 *     rollback, epoch-floor write failure, below-minimum security epoch)
 *     — none of which is "expired" in the time sense the spec's
 *     `license.expired` names, and none of the other 5 pinned names fit
 *     either. Mapping `unlicensed` to `license.expired` anyway would
 *     misreport, e.g., "no license file present" (this install has never
 *     had one) as an expiry — an ABSENT-is-not-FALSE violation this
 *     comment records so a future reader does not "fix" it into a wrong
 *     mapping.
 *
 * CHARIOT §11.2::2 (rulings item 88(3)) grace-alert dedup — "alert admin",
 * deduped to one emission per grace-period ENTRY, re-emitted at most once
 * per 24h while still in grace — preserved verbatim from the prior
 * inline version: `shouldEmitGraceAlert`/`recordGraceAlertEmitted` gate
 * `license.grace_entered`, and `clearGraceAlertState` resets the dedup
 * file for every mode OTHER than 'grace' (see `loader.grace-alert-dedup
 * .test.ts` for that gate's own direct coverage).
 */
export function emitLicenseEvents(info: LicenseInfo, tenantId: string | undefined): void {
  if (info.mode === 'licensed') {
    chariotEmitter.send('license.loaded', {
      data: { companyId: info.companyId, tenantId: tenantId ?? null },
    });
  } else if (info.mode === 'grace') {
    chariotEmitter.send('license.expired', {
      severity: 'warning',
      data: { companyId: info.companyId, tenantId: tenantId ?? null, graceEndsAt: info.graceEndsAt },
    });
    const now = Date.now();
    if (shouldEmitGraceAlert(info.companyId, now)) {
      chariotEmitter.send('license.grace_entered', {
        severity: 'warning',
        alertWorthy: true,
        data: { companyId: info.companyId, tenantId: tenantId ?? null, graceEndsAt: info.graceEndsAt },
        message: info.reason,
      });
      recordGraceAlertEmitted(info.companyId, now);
    }
  } else if (info.mode === 'degraded') {
    chariotEmitter.send('license.expired', {
      severity: 'urgent',
      data: { companyId: info.companyId, tenantId: tenantId ?? null },
    });
    chariotEmitter.send('license.degraded', {
      severity: 'urgent',
      alertWorthy: true,
      data: { companyId: info.companyId, tenantId: tenantId ?? null },
      message: info.reason,
    });
  }
  if (info.mode !== 'grace') {
    // §11.2::2 dedup reset for every mode OTHER than 'grace' (licensed,
    // degraded, unlicensed): a license that renews out of grace, moves
    // past the grace window into degraded, or becomes unlicensed for any
    // reason, must not have a stale grace-alert dedup file suppress the
    // alert the next time this companyId genuinely re-enters grace.
    clearGraceAlertState(info.companyId);
  }
}

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
  if (!binding && isEnterpriseEnvEnabled()) {
    const loadError = getBindingLoadError();
    throw new Error(
      `Chariot enterprise startup failed: ${loadError || 'native binary not available'}. ` +
        'CHARIOT_ENTERPRISE=true requires a working native binary. ' +
        'Install the matching platform binary or unset CHARIOT_ENTERPRISE to run in single-user mode.',
    );
  }

  function cache(info: LicenseInfo): LicenseInfo {
    _licenseCache.set(cacheKey, info, CACHE_TTL_MS);
    emitLicenseEvents(info, tenantId);
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

  // Mandated-patch-level floor. The license's min_security_epoch is the
  // minimum client patch level the entitlement requires; a client patched
  // below that floor must be fenced out (kill-switch for a mandatory security
  // patch). Enforced AFTER the anti-rollback bump so the epoch floor still
  // advances, but BEFORE granting any licensed/grace state. See
  // ./security-epoch.ts (CLIENT_SECURITY_EPOCH).
  if (decoded.minSecurityEpoch > CLIENT_SECURITY_EPOCH) {
    return cache({
      valid: false,
      mode: 'unlicensed',
      companyId: decoded.companyId,
      companyName: decoded.companyName,
      licenseEpoch: decoded.licenseEpoch,
      minSecurityEpoch: decoded.minSecurityEpoch,
      reason:
        `License requires security epoch ${decoded.minSecurityEpoch}; this ` +
        `client is at ${CLIENT_SECURITY_EPOCH}. Update Chariot to a build that ` +
        'satisfies the mandated security patch level.',
    });
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
