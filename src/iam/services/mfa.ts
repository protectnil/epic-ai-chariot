/**
 * IAM — MFA Service (TOTP)
 *
 * TOTP enrollment and verification via otplib.
 * TOTP secrets are AES-256-GCM encrypted at rest using ENTERPRISE_MASTER_KEY
 * with a per-tenant-feature key derived via SHA-256(masterKey || "mfa:" || tenantId).
 *
 * Does NOT use the Rust native binding so this works without the compiled binary.
 */

import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { TOTP, NobleCryptoPlugin, ScureBase32Plugin } from 'otplib';
import { getCollection } from '../db.js';
import type { MfaSecretDocument } from '../types.js';
import { chariotEmitter } from '../../observability/emitter.js';
import { getSessionRedisClient, isSessionRedisDegraded } from './session.js';

const ISSUER = 'Epic AI® Chariot';

// Shared TOTP instance with the required crypto/base32 plugins for otplib 13.x
const totp = new TOTP({
  crypto: new NobleCryptoPlugin(),
  base32: new ScureBase32Plugin(),
});

// ── Key derivation ───────────────────────────────────────────────────────────

function getMasterKey(): Buffer {
  const raw = process.env.ENTERPRISE_MASTER_KEY;
  if (!raw || raw.trim() === '' || raw === 'change-me' || raw === 'changeme') {
    throw new Error(
      'ENTERPRISE_MASTER_KEY is not set or is an insecure default. ' +
      'MFA secret encryption requires a real master key.',
    );
  }
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length < 32) {
    throw new Error(
      `ENTERPRISE_MASTER_KEY is too short (${decoded.length} bytes, minimum 32 for AES-256).`,
    );
  }
  return decoded;
}

// Per-tenant AES-256 key derived via HKDF-SHA256 (RFC 5869) from the master
// key. We use HKDF rather than SHA-256(masterKey || tenantId) because:
//   1. SHA-256 of concatenated values is theoretically vulnerable to length-
//      extension and offers no formal key-derivation guarantees.
//   2. HKDF is the standardized KDF expected by SOC 2 / cryptographic review.
//   3. The salt+info parameters bind the derived key to the MFA feature and
//      tenant, preventing key reuse across features even if the same input
//      key material is shared.
// CHARIOT::§12.2::11 — this consumer's (salt, info) pair is disjoint from
// every other ENTERPRISE_MASTER_KEY consumer's (the vault's tenant-prefixed
// salt with empty info; the §5.7 edge-snapshot seal's opaque salt with a
// distinct literal info). Registered + mechanically checked in
// `src/iam/masterKeyConsumers.ts`.
const MFA_HKDF_SALT = Buffer.from('epic-ai/chariot/iam/mfa', 'utf8');

function deriveMfaKey(tenantId: string): Buffer {
  const master = getMasterKey();
  const info = Buffer.from(`mfa:${tenantId}`, 'utf8');
  // hkdfSync returns ArrayBuffer; wrap in Buffer for AES-256 (32 bytes).
  return Buffer.from(hkdfSync('sha256', master, MFA_HKDF_SALT, info, 32));
}

// ── Crypto: encrypt / decrypt ────────────────────────────────────────────────

export function encryptTotpSecret(
  plaintext: string,
  tenantId: string,
): { encrypted: string; iv: string } {
  const key = deriveMfaKey(tenantId);
  const iv = randomBytes(12); // 96-bit IV for AES-256-GCM
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag(); // 128-bit GCM tag
  return {
    encrypted: Buffer.concat([body, tag]).toString('base64'),
    iv: iv.toString('base64'),
  };
}

export function decryptTotpSecret(
  encrypted: string,
  ivB64: string,
  tenantId: string,
): string {
  const key = deriveMfaKey(tenantId);
  const iv = Buffer.from(ivB64, 'base64');
  const combined = Buffer.from(encrypted, 'base64');
  const tag = combined.subarray(combined.length - 16);
  const ciphertext = combined.subarray(0, combined.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

// ── TOTP ─────────────────────────────────────────────────────────────────────

/**
 * Generate a new TOTP secret and the otpauth:// URI for QR enrollment.
 */
export async function generateTotpSecret(
  accountLabel: string,
): Promise<{ secret: string; otpauthUrl: string }> {
  const secret = await totp.generateSecret();
  const otpauthUrl = await totp.toURI({ secret, label: accountLabel, issuer: ISSUER });
  return { secret, otpauthUrl };
}

/**
 * Verify a TOTP code against a known secret. Returns true if valid.
 * otplib allows a 1-step window (±30 s) by default.
 */
export async function verifyTotpCode(secret: string, token: string): Promise<boolean> {
  try {
    const result = await totp.verify(token, { secret });
    return result.valid;
  } catch {
    return false;
  }
}

// ── MongoDB ──────────────────────────────────────────────────────────────────

export async function getUserMfaSecret(
  tenantId: string,
  userId: string,
): Promise<MfaSecretDocument | null> {
  const col = await getCollection<MfaSecretDocument>('iam_mfa_secrets');
  return col.findOne({ tenantId, userId }) as Promise<MfaSecretDocument | null>;
}

export async function isMfaEnrolled(tenantId: string, userId: string): Promise<boolean> {
  const col = await getCollection<MfaSecretDocument>('iam_mfa_secrets');
  return (await col.countDocuments({ tenantId, userId }, { limit: 1 })) > 0;
}

/**
 * CHARIOT::§16.1 IAM (CHARIOT-SPEC.md:1346, rulings item 91) — this upsert
 * IS the enrollment write (the TOTP secret record is created/replaced
 * here, keyed `{tenantId, userId}`); `chariotEmitter.send('mfa.enrolled')`
 * fires only after the write succeeds (below the `await`), never before,
 * so a failed write (thrown error propagates, function never returns)
 * cannot produce a false enrollment event.
 */
export async function saveMfaSecret(
  tenantId: string,
  userId: string,
  plaintextSecret: string,
): Promise<void> {
  const { encrypted, iv } = encryptTotpSecret(plaintextSecret, tenantId);
  const col = await getCollection<MfaSecretDocument>('iam_mfa_secrets');
  await col.updateOne(
    { tenantId, userId },
    { $set: { tenantId, userId, encrypted, iv, enrolledAt: new Date() } },
    { upsert: true },
  );
  chariotEmitter.send('mfa.enrolled', { data: { tenantId, userId } });
}

export async function deleteMfaSecret(tenantId: string, userId: string): Promise<void> {
  const col = await getCollection<MfaSecretDocument>('iam_mfa_secrets');
  await col.deleteOne({ tenantId, userId });
}

// ── MFA assertion binding/revocation (CHARIOT::§8.2::3) ─────────────────────
//
// CHARIOT-SPEC.md:679 — "WHEN an MFA-required tool is dispatched the
// generator instance for that turn SHALL be bound to the MFA assertion, and
// a revoked MFA SHALL invalidate the generator without affecting the rest
// of the agent state." Node text (traceability graph, CHARIOT::§8.2::3):
// "WHEN an MFA-required tool is dispatched the generator instance for that
// turn SHALL be bound to the MFA assertion, and a revoked MFA SHALL
// invalidate the generator without affecting the rest of the agent state."
//
// This codebase has NO pre-existing "MFA assertion" as a distinct,
// revokable, per-dispatch entity before this change — grepped
// `generator|invalidat|revoke` in this file before this change: 0 hits.
// The only existing MFA concept is `tenant.settings.mfaRequired`
// (session.ts / middleware.ts: whether the TENANT requires MFA at login)
// and `session.mfaVerified` (whether THIS session satisfied it) — both
// session-scoped, not per-tool-dispatch-scoped. §8.2::3 requires something
// narrower: an identity minted at the moment a specific MFA-required tool
// dispatch happens, revokable independently of the session/tenant epoch.
//
// Reuses the session-revocation epoch MACHINERY (session.ts
// KEY_TENANT_EPOCH/KEY_USER_EPOCH: a Redis key holding a millisecond
// timestamp, bumped by a "revoke" call, compared against the timestamp a
// caller captured at bind time) at ASSERTION scope: one Redis key per
// mintMfaAssertion() call, not per tenant/user. Same Redis client
// (getSessionRedisClient(), exported additively from session.ts for this).

const KEY_MFA_ASSERTION_EPOCH = 'ent:mfa-assertion-epoch:';
// RCA (chariot-verify-wave1): the FIRST version of this file used only the
// epoch-timestamp comparison below (`epochMs <= epochAtBindMs`) as the
// revocation check. That is the exact same-millisecond race session.ts's
// OWN tenant/user epoch already solves and explicitly calls out:
// "the counter is the primary check — immune to same-ms races. The
// timestamp is retained as a defense-in-depth signal" (session.ts,
// revokeAllUserSessions doc comment). mintMfaAssertion() and
// revokeMfaAssertion() can execute within the same wall-clock millisecond
// (trivial with the in-process Redis shim's zero I/O latency, and not
// provably impossible against a real Redis either) — when they do, the
// epoch-only comparison treated a just-revoked assertion as still valid.
// Fixed by mirroring session.ts's OWN two-signal pattern exactly: a
// monotonic per-assertion version counter (`incr()`, immune to same-ms
// collisions by construction) is now the PRIMARY check; the epoch key is
// retained only as the "was this ever minted" existence/forensic signal.
const KEY_MFA_ASSERTION_VERSION = 'ent:mfa-assertion-version:';

export interface MfaAssertion {
  assertionId: string;
  /** Epoch (ms) captured at bind time — retained for forensics/audit; NOT the revocation check (see RCA above). */
  epochAtBindMs: number;
}

/**
 * Mint a fresh MFA assertion for one turn's MFA-required tool dispatch.
 * Seeds `ent:mfa-assertion-epoch:<assertionId>` to the current timestamp so
 * a bind is never pre-invalidated by a missing key (mirrors
 * revokeAllTenantSessions' "set epoch to now" pattern, but at a fresh,
 * assertion-unique key rather than an existing tenant/user key). Does NOT
 * touch the version key — `assertionId` is a fresh randomUUID() every
 * call, so no prior revoke() could have incremented ITS version key; an
 * absent version key is correctly read as 0 (not-yet-revoked) by
 * isMfaAssertionValid() below.
 */
export async function mintMfaAssertion(): Promise<MfaAssertion> {
  const assertionId = randomUUID();
  const epochAtBindMs = Date.now();
  const redis = getSessionRedisClient();
  await redis.set(`${KEY_MFA_ASSERTION_EPOCH}${assertionId}`, epochAtBindMs.toString());
  return { assertionId, epochAtBindMs };
}

/**
 * Revoke one MFA assertion. Increments ONLY that assertion's monotonic
 * version counter (the primary, same-ms-race-immune revocation signal —
 * see the RCA above) and bumps its epoch key to a later timestamp
 * (forensic signal only). Every OTHER assertion's keys (every other
 * turn's generator binding, and the session/tenant/user epochs session.ts
 * owns) are untouched, satisfying §8.2::3's "without affecting the rest
 * of the agent state."
 */
export async function revokeMfaAssertion(assertionId: string): Promise<void> {
  const redis = getSessionRedisClient();
  await redis.incr(`${KEY_MFA_ASSERTION_VERSION}${assertionId}`);
  await redis.set(`${KEY_MFA_ASSERTION_EPOCH}${assertionId}`, Date.now().toString());
}

/**
 * Check whether an MFA assertion is still valid (i.e. has not been
 * revoked since bind). `epochAtBindMs` is accepted for API/caller-shape
 * stability (Orchestrator.ts's mfaBinding carries it) but is NOT the
 * revocation decision (see the RCA above) — only used, together with the
 * epoch key's mere presence, as the "was this assertion ever minted"
 * fail-closed existence check.
 *
 * Fail-closed on a missing epoch key, intentionally DIFFERENT from
 * session.ts's tenant/user epoch convention: there, a MISSING key
 * legitimately means "never revoked" (a tenant/user that has simply never
 * had a revocation event). Here, mintMfaAssertion() ALWAYS writes the
 * epoch key before an assertionId is ever handed to a caller, so a
 * missing key at check time can only mean the assertion was never minted
 * (caller bug) or the key was evicted from Redis unexpectedly — both
 * anomalous for a security-scoped revocation channel, so both are treated
 * as INVALID.
 *
 * Degraded-Redis handling mirrors the existing session-revocation posture
 * (isSessionRedisDegraded(), session.ts:196-210: "sessions fall back to
 * JWT-signature-only revocation" during a documented Redis outage): while
 * degraded, this returns `true` (skip the check) rather than fail-closed,
 * consistent with the rest of the session-revocation system's already-
 * ratified degraded-mode trade-off — it does NOT introduce a stricter
 * posture for MFA assertions alone during an outage the rest of the system
 * already tolerates.
 */
export async function isMfaAssertionValid(assertionId: string, epochAtBindMs: number): Promise<boolean> {
  if (isSessionRedisDegraded()) return true;
  void epochAtBindMs; // retained in the signature for caller-shape stability; not the decision (see doc comment)
  const redis = getSessionRedisClient();
  const epochValue = await redis.get(`${KEY_MFA_ASSERTION_EPOCH}${assertionId}`);
  if (!epochValue) return false; // never minted / evicted -> fail closed
  const versionRaw = await redis.get(`${KEY_MFA_ASSERTION_VERSION}${assertionId}`);
  if (versionRaw === null) return true; // no revoke() has ever incremented this assertion's version
  const currentVersion = parseInt(versionRaw, 10);
  if (!Number.isFinite(currentVersion)) return false; // corrupt counter -> fail closed
  return currentVersion === 0;
}
