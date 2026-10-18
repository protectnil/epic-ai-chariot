/**
 * Enterprise IAM Credential Vault Cryptography
 *
 * Delegates AES-256-GCM encryption to the compiled Rust binary when available.
 * Falls back to Node.js crypto for SCIM token hashing (non-sensitive, no Rust needed).
 *
 * Epic AI® Chariot — Enterprise IAM Module
 */

import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { loadNativeBinding, type NativeBinding } from '../license/binding.js';
import { getCollection } from './db.js';

const SCIM_TOKEN_LENGTH = 48;

// ── CH-10 hard cutover (CHARIOT §12.2, rulings item 59) ─────────────────────

/**
 * Marks the tenant's CH-10 (§12.2) legacy-ciphertext migration complete.
 * Written by `chariot vault migrate` once a tenant has zero remaining
 * unprefixed (legacy, empty-AAD) records across every persistence site it
 * walks. Its PRESENCE is what triggers the hard-cutover refusal below —
 * see `resolveLegacyDecryptPolicy`.
 */
export const VAULT_MIGRATIONS_COLLECTION = 'iam_vault_migrations';

/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10), rulings item 59: "One-shot
 * migration ... reports counts {legacy, upgraded, failed, alreadyV2}".
 * Shared shape for every persistence-site walker (`chariot vault migrate`
 * in src/bin/chariot.ts, and each site's own `walkLegacy*` export) so the
 * migration report and the per-site coverage test speak one vocabulary.
 */
export interface VaultMigrateCounts {
  legacy: number;
  upgraded: number;
  failed: number;
  alreadyV2: number;
}

export function emptyVaultMigrateCounts(): VaultMigrateCounts {
  return { legacy: 0, upgraded: 0, failed: 0, alreadyV2: 0 };
}

export interface VaultMigrationMarkerDocument {
  _id: string; // tenantId
  tenantId: string;
  migratedAt: Date;
  counts: { legacy: number; upgraded: number; failed: number; alreadyV2: number };
}

/**
 * CH-10 (§12.2) hard-cutover distinct error code (rulings item 59). Thrown
 * by `decryptFields` instead of attempting a legacy decrypt when the
 * caller's context refuses legacy ciphertexts. Never falls back to an
 * empty-AAD decrypt attempt on this path — see the constructor call sites.
 */
export class VaultLegacyCiphertextRefusedError extends Error {
  readonly code = 'VAULT_LEGACY_CIPHERTEXT_REFUSED';
  constructor(tenantId: string, reason: string) {
    super(
      `VAULT_LEGACY_CIPHERTEXT_REFUSED: legacy (pre-CH-10) credential decryption ` +
      `refused for tenant=${tenantId}: ${reason}`
    );
    this.name = 'VaultLegacyCiphertextRefusedError';
  }
}

/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10). Rulings item 59: "the caller
 * MUST persist `{encrypted, iv}` back to the SAME record, in the SAME
 * operation" that consumed the decrypted fields. A write-back failure is
 * NOT a best-effort/log-and-continue condition — it must surface as a
 * distinct, typed failure of that SAME operation, so the caller never
 * reports success while the record silently stayed legacy with no signal.
 * Every upgrade-on-decrypt call site (credential-loader.ts, oidc.ts,
 * id-jag-client.ts, session.ts, chainSigner.ts) throws this — never logs
 * and swallows — when its compare-and-set write-back errors (as opposed
 * to a benign CAS no-op, which means a CONCURRENT upgrader already wrote
 * the same upgrade and is not a failure at all).
 */
export class VaultUpgradePersistFailedError extends Error {
  readonly code = 'VAULT_UPGRADE_PERSIST_FAILED';
  constructor(site: string, recordId: string, cause: unknown) {
    super(
      `VAULT_UPGRADE_PERSIST_FAILED: CH-10 upgrade-on-decrypt write-back failed at ${site} ` +
      `for record=${recordId}: ${cause instanceof Error ? cause.message : String(cause)}`
    );
    this.name = 'VaultUpgradePersistFailedError';
  }
}

/**
 * Standard base64 (the alphabet `encryptCredential`/`decryptCredential` use)
 * never contains a `:` byte (RFC 4648 §4) — see `native/src/vault.rs`'s
 * `V2_PREFIX` doc comment. A record produced by `encryptFields` therefore
 * has AT MOST one internal `:` (the `v2:` prefix); the LAST `:` in a
 * `${encrypted}:${iv}` combined blob is always the encrypted/iv separator,
 * regardless of whether `encrypted` carries the prefix. `indexOf(':')` /
 * `.split(':')` are WRONG for a `v2:`-prefixed value — they split at the
 * prefix's own colon instead — which is exactly the bug this helper fixes
 * at every combined-blob call site (oidc.ts, id-jag-client.ts).
 */
export function splitEncryptedIv(combined: string): { encrypted: string; iv: string } | null {
  const sep = combined.lastIndexOf(':');
  if (sep <= 0 || sep === combined.length - 1) return null;
  return { encrypted: combined.slice(0, sep), iv: combined.slice(sep + 1) };
}

/**
 * True when `encrypted` is a legacy (pre-CH-10) ciphertext — i.e. it does
 * NOT carry the `v2:` prefix `encryptCredential` always writes going
 * forward. Legacy ciphertexts were encrypted with empty AAD and are
 * relocatable within a tenant (CHARIOT §12.2, CH-10) until upgraded.
 */
export function isLegacyCiphertext(encrypted: string): boolean {
  return !encrypted.startsWith('v2:');
}

/**
 * The minimal structural surface `hasVaultLegacyGate`/`callNativeDecrypt`
 * need from a binding — NOT the full `NativeBinding` (which also requires
 * `validateLicense`, `checkAccess`, `discoverInternalApis`, …). Other
 * CH-10-adjacent consumers with their own narrow, locally-injectable
 * binding type (e.g. `SqliteCheckpointStore.ts`'s `CryptoBinding`, whose
 * checkpoint rows are ALWAYS v2/AAD-bound — see that module's own
 * `legacyAllowed=false` citation) only need to satisfy THIS shape to reuse
 * both helpers, not implement every `NativeBinding` method.
 */
export type VaultDecryptCapableBinding = {
  decryptCredential: NativeBinding['decryptCredential'];
  vaultProtocolVersion?: NativeBinding['vaultProtocolVersion'];
};

/**
 * CH-10 (rulings item 59) native capability probe. A binary compiled
 * before this change (the currently signed Sep-1 build, per the operator
 * re-sign gap) has no `vaultProtocolVersion` export at all. Its ABSENCE
 * must never be read as "legacy decryption is allowed" — see the module
 * doc on `resolveLegacyDecryptPolicy` — it only means the NATIVE layer
 * cannot enforce `legacy_allowed` itself; `decryptFields` below still
 * enforces the cutover policy in TypeScript BEFORE any native call, on
 * every binary version, using only the caller-visible `v2:` prefix.
 */
export function hasVaultLegacyGate(binding: VaultDecryptCapableBinding): boolean {
  return typeof binding.vaultProtocolVersion === 'function' && binding.vaultProtocolVersion() >= 2;
}

/**
 * Resolve whether legacy (pre-CH-10, empty-AAD) credential decryption is
 * currently permitted for `tenantId` (CHARIOT §12.2, CH-10, rulings item
 * 59 — "hard cutover"). Three independent refusal triggers, combined by
 * OR, checked in cheapest-first order:
 *
 *   1. `CHARIOT_VAULT_LEGACY_DECRYPT=0`            -> always refused.
 *   2. Enterprise mode without an explicit override -> refused UNLESS
 *      `CHARIOT_VAULT_LEGACY_DECRYPT=1` is explicitly set (the operator's
 *      deliberate window).
 *   3. The tenant's migration marker exists (`iam_vault_migrations`)      -> always refused, no override.
 *
 * A caller with `allowed=true` is still responsible for verifying the
 * NATIVE binding actually enforces `legacy_allowed` (`hasVaultLegacyGate`)
 * before deciding what to pass it — this function answers only "is legacy
 * decryption POLICY-permitted", independent of what any given binary can
 * enforce.
 */
export async function resolveLegacyDecryptPolicy(
  tenantId: string,
): Promise<{ allowed: boolean; reason: string }> {
  const envFlag = process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
  if (envFlag === '0') {
    return { allowed: false, reason: 'CHARIOT_VAULT_LEGACY_DECRYPT=0' };
  }
  const enterpriseMode = process.env.CHARIOT_ENTERPRISE === '1';
  if (enterpriseMode && envFlag !== '1') {
    return {
      allowed: false,
      reason: 'CHARIOT_ENTERPRISE=1 refuses legacy vault ciphertexts by default (CHARIOT::§12.2::CH-10); ' +
        'set CHARIOT_VAULT_LEGACY_DECRYPT=1 for a deliberate operator window',
    };
  }
  // Mongo is only wired up during ENTERPRISE bootstrap (`setMongoClient`,
  // see db.ts). Single-user/OSS builds decrypt vault records too (the
  // sealed audit-signing key via chainSigner.ts) with no Mongo client at
  // all — there is no per-tenant migration concept in that mode, so "no
  // database available" is read as "no marker", not as a hard failure.
  // This does NOT weaken the cutover: the two env-based checks above still
  // apply unconditionally in every mode.
  let marker: VaultMigrationMarkerDocument | null = null;
  try {
    const col = await getCollection<VaultMigrationMarkerDocument>(VAULT_MIGRATIONS_COLLECTION);
    marker = await col.findOne({ tenantId });
  } catch {
    marker = null;
  }
  if (marker) {
    return {
      allowed: false,
      reason: `tenant ${tenantId} completed its CH-10 vault migration at ` +
        `${marker.migratedAt.toISOString()} — no legacy ciphertexts should remain`,
    };
  }
  return { allowed: true, reason: 'no CH-10 cutover condition active' };
}

// ── Credential Vault (Rust binary) ──────────────────────────────────────────

/**
 * Returns the master key, validated at every call.
 * The bootstrap function validates this at startup; this is a defense-in-depth check.
 */
function getMasterKeyB64(): string {
  const raw = process.env.ENTERPRISE_MASTER_KEY;
  if (!raw || raw.trim() === '' || raw === 'change-me' || raw === 'changeme') {
    throw new Error(
      'ENTERPRISE_MASTER_KEY is not set or is an insecure default. ' +
      'Credential vault operations require a real master key. ' +
      'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"'
    );
  }
  const decoded = Buffer.from(raw, 'base64');
  // AES-256 takes a 32-byte key — accept exactly 32 bytes only.
  // A `< 32` check let a 33-byte (or longer) key through; HKDF would
  // then derive from a key the operator may have generated with the
  // wrong tool and silently truncate / expand surprising bytes. Refuse
  // anything that isn't exactly 32 bytes so the failure surfaces at
  // bootstrap (where the operator can fix it) rather than after rows
  // have been encrypted under the wrong material.
  if (decoded.length !== 32) {
    throw new Error(
      `ENTERPRISE_MASTER_KEY must decode to exactly 32 bytes (got ${decoded.length}). ` +
      'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"'
    );
  }
  return raw;
}

/**
 * Validate the master key eagerly at startup (called from bootstrap).
 * Throws immediately if missing or insecure.
 */
export function validateMasterKey(): void {
  getMasterKeyB64();
}

/**
 * Encrypt a record of credential fields into a single encrypted blob.
 * Uses the Rust binary for AES-256-GCM with HKDF-SHA256 key derivation.
 *
 * `recordId` is the CH-10 (§12.2, amended 2026-09-02) AAD binding — the native
 * layer forms AAD = LE_u32(len(tenantId_bytes)) ‖ tenantId_bytes ‖ recordId_bytes —
 * bound into the ciphertext alongside `tenantId` so it
 * cannot be relocated from one record's row to another within the same
 * tenant and still decrypt. For rows in `iam_adapter_credentials` this MUST
 * be the adapter's own id. For every other credential record type (OIDC
 * client secret, ID-JAG client secret/private key, session subject_token,
 * ...) it MUST be a stable identifier unique within that record's own
 * collection/keyspace for this tenant, so the same anti-relocation binding
 * applies there too — see each call site for the identifier it uses.
 */
export function encryptFields(
  fields: Record<string, string | undefined>,
  tenantId: string,
  recordId: string,
): { encrypted: string; iv: string } {
  const binding = loadNativeBinding();
  if (!binding) {
    throw new Error(
      'Credential vault requires the Chariot native binary. ' +
      'Install @epicai/chariot to enable credential encryption.'
    );
  }

  // Strip undefined values before encrypting
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined) clean[k] = v;
  }

  const plaintext = JSON.stringify(clean);
  return binding.encryptCredential(plaintext, tenantId, recordId, getMasterKeyB64());
}

/**
 * Call the native `decryptCredential` export with whatever argument count
 * the LOADED binary actually supports. A binary compiled before rulings
 * item 59 (e.g. the currently signed Sep-1 build, per the operator
 * re-sign gap noted on `hasVaultLegacyGate`) has the OLD 5-arg signature
 * with no `legacyAllowed` parameter at all; calling it with a 6th argument
 * is unverified behavior this module does not rely on. This is not the
 * cutover enforcement point — `decryptFields` below refuses a legacy
 * ciphertext in TypeScript, from the caller-visible `v2:` prefix alone,
 * BEFORE this function is ever invoked for a record under cutover — this
 * wrapper exists only to hand the native call the argument shape it can
 * actually parse.
 *
 * EXPORTED (not module-private) so other CH-10-adjacent callers whose
 * `legacyAllowed` value is a fixed constant rather than a policy lookup —
 * e.g. `SqliteCheckpointStore.ts`, whose checkpoint rows have been
 * v2/AAD-bound since the same commit that introduced this format and so
 * pass a constant `false` — get the same old-binary-safe call shape
 * without duplicating this argument-count logic.
 */
export function callNativeDecrypt(
  binding: VaultDecryptCapableBinding,
  encrypted: string,
  iv: string,
  tenantId: string,
  recordId: string,
  masterKeyB64: string,
  legacyAllowed: boolean,
): string {
  if (hasVaultLegacyGate(binding)) {
    return binding.decryptCredential(encrypted, iv, tenantId, recordId, masterKeyB64, legacyAllowed);
  }
  const legacyShape = binding.decryptCredential as unknown as (
    e: string, i: string, t: string, r: string, m: string,
  ) => string;
  return legacyShape(encrypted, iv, tenantId, recordId, masterKeyB64);
}

export interface DecryptedCredentialResult {
  fields: Record<string, string>;
  /**
   * Present ONLY when `encrypted` was a legacy (pre-CH-10) ciphertext that
   * this call successfully decrypted and re-encrypted under the current
   * v2 AAD-bound format (CHARIOT §12.2, rulings item 59 — upgrade-on-
   * decrypt). The caller MUST persist `{ encrypted, iv }` back to the SAME
   * record, in the SAME operation that consumes `fields`, so the
   * ciphertext is upgraded on first successful use rather than remaining
   * relocatable indefinitely.
   */
  upgraded: { encrypted: string; iv: string } | null;
}

/**
 * Decrypt a combined encrypted blob back into credential fields.
 * Uses the Rust binary for AES-256-GCM with HKDF-SHA256 key derivation.
 *
 * `recordId` MUST be the exact same CH-10 AAD binding value passed to
 * `encryptFields` when this blob was written (see that doc comment). A
 * mismatch (including a ciphertext relocated from a different record) is a
 * hard decrypt failure — the native layer never silently falls back to an
 * unbound decrypt for a record encrypted under this contract.
 *
 * CH-10 hard cutover + upgrade-on-decrypt (§12.2, rulings item 59):
 *   - A `v2:`-prefixed (already AAD-bound) record decrypts exactly as
 *     before; `upgraded` is always `null`.
 *   - An UNPREFIXED (legacy, empty-AAD) record first has its decrypt
 *     POLICY resolved (`resolveLegacyDecryptPolicy`); if refused, this
 *     throws `VaultLegacyCiphertextRefusedError` WITHOUT attempting any
 *     decrypt — the refusal never falls back to an empty-AAD attempt. If
 *     allowed, the legacy plaintext is decrypted and immediately
 *     re-encrypted under the v2 format (same tenantId/recordId AAD
 *     binding), returned as `upgraded` for the caller to persist.
 */
export async function decryptFields(
  encrypted: string,
  iv: string,
  tenantId: string,
  recordId: string,
): Promise<DecryptedCredentialResult> {
  const binding = loadNativeBinding();
  if (!binding) {
    throw new Error(
      'Credential vault requires the Chariot native binary. ' +
      'Install @epicai/chariot to enable credential decryption.'
    );
  }

  const legacy = isLegacyCiphertext(encrypted);
  if (legacy) {
    const policy = await resolveLegacyDecryptPolicy(tenantId);
    if (!policy.allowed) {
      throw new VaultLegacyCiphertextRefusedError(tenantId, policy.reason);
    }
  }

  const masterKeyB64 = getMasterKeyB64();
  const json = callNativeDecrypt(binding, encrypted, iv, tenantId, recordId, masterKeyB64, true);
  const fields = JSON.parse(json) as Record<string, string>;

  if (!legacy) {
    return { fields, upgraded: null };
  }

  // Upgrade-on-decrypt: a legacy record just proved it holds the correct
  // tenant key. Re-encrypt it under the v2 AAD-bound format so it is no
  // longer relocatable within the tenant. Re-encryption failure must not
  // hide the plaintext the caller already validly obtained — but it also
  // must not silently persist nothing; propagate the encrypt error rather
  // than swallow it, so a broken re-encrypt surfaces instead of leaving
  // the record legacy forever with no signal.
  const upgraded = encryptFields(fields, tenantId, recordId);
  return { fields, upgraded };
}

/**
 * CLI-ONLY escape hatch for `chariot vault migrate` (CHARIOT §12.2, rulings
 * item 59). The migration's entire purpose is to read legacy ciphertexts
 * in order to upgrade them, so it deliberately bypasses
 * `resolveLegacyDecryptPolicy` — an operator running this command IS the
 * "deliberate window" the policy exists to gate everywhere else. NEVER
 * call this from a request-serving code path; every such path MUST go
 * through `decryptFields` above.
 */
export async function decryptFieldsForVaultMigration(
  encrypted: string,
  iv: string,
  tenantId: string,
  recordId: string,
): Promise<{ fields: Record<string, string>; wasLegacy: boolean }> {
  const binding = loadNativeBinding();
  if (!binding) {
    throw new Error(
      'Credential vault requires the Chariot native binary. ' +
      'Install @epicai/chariot to enable credential decryption.'
    );
  }
  const wasLegacy = isLegacyCiphertext(encrypted);
  const masterKeyB64 = getMasterKeyB64();
  const json = callNativeDecrypt(binding, encrypted, iv, tenantId, recordId, masterKeyB64, true);
  return { fields: JSON.parse(json) as Record<string, string>, wasLegacy };
}

// ── SCIM Token Management (Node.js crypto — no Rust needed) ─────────────────

/**
 * Hash a token using SHA-256, returned as hex.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Verify a token against a SHA-256 hash using timing-safe comparison.
 */
export function verifyToken(token: string, hash: string): boolean {
  const computed = Buffer.from(hashToken(token), 'hex');
  const expected = Buffer.from(hash, 'hex');
  if (computed.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(computed, expected);
}

/**
 * Generate a cryptographically random SCIM bearer token and its SHA-256 hash.
 */
export function generateScimToken(): { token: string; hash: string } {
  const token = randomBytes(SCIM_TOKEN_LENGTH).toString('base64url');
  const hash = hashToken(token);
  return { token, hash };
}
