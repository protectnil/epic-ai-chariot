/**
 * @epicai/chariot — Audit Chain Signing Key Rotation (CHARIOT::§9.8.1::3)
 *
 * CHARIOT-SPEC.md §9.8.1 (docs/spec/CHARIOT-SPEC.md:899-906):
 *   "Key rotation is forward-only: rotate to a new key, record the
 *   rotation event in the chain, and publish the new public key via the
 *   same distribution path as the old one. Historical records remain
 *   verifiable only if the old public key is retained in a multi-key
 *   verification set (CH-03 pattern)."
 *
 * Mirrors the existing `federation.adapter.revoked` audit-record pattern
 * (src/engine/EpicAI.ts:307-320: a system event appended via
 * `auditTrail.record({...})`, not a tool invocation) — the rotation event
 * is appended to the SAME hash chain as every other action record, so it
 * inherits the chain's own tamper-evidence (HashChain.ts) rather than
 * being a side-channel log entry that could be edited independently.
 *
 * gate finding F2 (2026-09-04): the first cut returned the new
 * public key to the caller but published it NOWHERE — `resolveVerifyKeys()`
 * had no durable store to read it back from. `rotateSigningKey()` now
 * appends the new key to the persistent verify-key store
 * (`verifyKeyStore.ts`, `<epicAiDir>/audit/verify-keys.json`) ATOMICALLY,
 * in the SAME call that records the chain event — that store IS the
 * "same distribution path" `resolveVerifyKeys()` reads from, so a fresh
 * `resolveVerifyKeys()` call after rotation sees both the old and new kid
 * with no further operator action required. This module never deletes or
 * supersedes a prior key.
 *
 * gate finding F3 (2026-09-04): the first cut generated a keypair and
 * RETURNED the plaintext PKCS#8 PEM to the caller — a private key crossing
 * a function boundary is exactly the exposure CHARIOT::§9.8.1::1 exists to
 * prevent. Rotation is now backend-specific and NEVER returns private
 * material for any backend:
 *   - sealed-store: a fresh Ed25519 keypair is generated in memory and
 *     sealed immediately via `sealSigningKey()` (chainSigner.ts) — the
 *     private key PEM exists only in a local variable inside this
 *     function's own stack frame and is never returned.
 *   - kms: the operator creates the NEW key out-of-band (KMS has no
 *     in-place "rotate" for an asymmetric key — a fresh key is a fresh
 *     KeyId) with KeySpec=ECC_NIST_EDWARDS25519; this function only fetches
 *     and validates that new key's PUBLIC half via `fetchKmsPublicKey()`.
 *   - vault-transit: this function calls Vault's native transit key
 *     rotate endpoint (`POST /v1/transit/keys/<name>/rotate`, via
 *     `rotateVaultTransitKey()`), which bumps `latest_version` IN Vault —
 *     the private key material never leaves Vault, let alone this process.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { generateKeyPairSync } from 'node:crypto';
import type { AuditTrail } from './AuditTrail.js';
import type { ActionRecord } from '../types/index.js';
import { computeKid, sealSigningKey, fetchKmsPublicKey, rotateVaultTransitKey, type ChainSignerDeps } from './chainSigner.js';
import { appendVerifyKey } from './verifyKeyStore.js';

export const SIGNING_KEY_ROTATED_EVENT = 'audit.signing_key.rotated';

export type RotateSigningKeyBackend = 'sealed-store' | 'kms' | 'vault-transit';

export interface RotateSigningKeyOpts {
  backend: RotateSigningKeyBackend;
  /** PEM of the key being retired, if any (first rotation has none). */
  oldPublicKeyPem?: string;
  /** Attribution persona for the chain record; defaults to 'system'. */
  persona?: string;
  /** Directory the persistent verify-key store lives under — same value as
   * `resolveEpicAiDir()`. Required for every backend (the store is where
   * the new public key gets published, regardless of where the PRIVATE
   * key lives). */
  epicAiDir: string;
  /** backend: 'sealed-store' — where the new sealed private-key artifact
   * is written. Usually the same directory as `epicAiDir`. */
  packageRoot?: string;
  /** backend: 'kms' — the NEW KMS key id/ARN, created out-of-band by the
   * operator with KeySpec=ECC_NIST_EDWARDS25519. KMS has no in-place
   * rotate for asymmetric keys, so this is a REQUIRED, distinct value from
   * whatever CHARIOT_AUDIT_KMS_KEY_ID currently is. */
  newKmsKeyId?: string;
  kmsRegion?: string;
  /** backend: 'vault-transit' — the transit key name to rotate in place
   * (same name, new version). */
  vaultAddr?: string;
  vaultToken?: string;
  vaultKeyName?: string;
  /** Injectable fake transports for kms/vault-transit tests (no network). */
  deps?: ChainSignerDeps;
}

export interface RotateSigningKeyResult {
  publicKeyPem: string;
  kid: string;
  oldKid: string | null;
  record: ActionRecord;
}

/**
 * CHARIOT::§9.8.1::3 — rotate to a new key for `opts.backend`, publish its
 * public half into the persistent verify-key store, and append a
 * `audit.signing_key.rotated` record to `auditTrail`'s chain. NEVER
 * returns private key material — see the module doc comment for the
 * per-backend private-key handling.
 *
 * Callers still add the new public key to `CHARIOT_AUDIT_VERIFY_KEYS` if
 * they want an env-level override, but that is now optional: the
 * persistent store this function writes to is read by
 * `resolveVerifyKeys()` on every call, so a fresh process picks up the
 * rotation with no further action.
 */
export async function rotateSigningKey(
  auditTrail: AuditTrail,
  opts: RotateSigningKeyOpts,
): Promise<RotateSigningKeyResult> {
  let publicKeyPem: string;

  switch (opts.backend) {
    case 'sealed-store': {
      if (!opts.packageRoot) {
        throw new Error('rotateSigningKey: packageRoot is required for backend=sealed-store.');
      }
      // Generated and sealed in the SAME local scope — the plaintext
      // PKCS#8 PEM never leaves this block, let alone this function.
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const newPublicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
      const newPrivateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
      sealSigningKey(opts.packageRoot, newPrivateKeyPem);
      publicKeyPem = newPublicKeyPem;
      break;
    }
    case 'kms': {
      if (!opts.newKmsKeyId) {
        throw new Error(
          'rotateSigningKey: newKmsKeyId is required for backend=kms — create the new key out-of-band with ' +
            'KeySpec=ECC_NIST_EDWARDS25519, then pass its key id/ARN here (KMS has no in-place rotate for ' +
            'asymmetric keys).',
        );
      }
      const fetched = await fetchKmsPublicKey(opts.newKmsKeyId, opts.kmsRegion, opts.deps);
      publicKeyPem = fetched.publicKeyPem;
      break;
    }
    case 'vault-transit': {
      if (!opts.vaultAddr || !opts.vaultToken || !opts.vaultKeyName) {
        throw new Error(
          'rotateSigningKey: vaultAddr, vaultToken, and vaultKeyName are all required for backend=vault-transit.',
        );
      }
      const rotated = await rotateVaultTransitKey(opts.vaultAddr, opts.vaultToken, opts.vaultKeyName, opts.deps);
      publicKeyPem = rotated.publicKeyPem;
      break;
    }
    default: {
      const _exhaustive: never = opts.backend;
      throw new Error(`rotateSigningKey: unknown backend '${String(_exhaustive)}'.`);
    }
  }

  const kid = computeKid(publicKeyPem);
  const oldKid = opts.oldPublicKeyPem ? computeKid(opts.oldPublicKeyPem) : null;
  const rotatedAt = new Date().toISOString();

  // CHARIOT::§9.8.1::3 (review gate F2) — "publish the new public key via
  // the same distribution path as the old one": append to the persistent
  // verify-key store BEFORE recording the chain event, so a crash between
  // these two steps leaves the key published (safe: an unrecorded-but-
  // published key is inert until something actually signs under it) rather
  // than recorded-but-unpublished (which would leave a chain event nothing
  // can verify against).
  appendVerifyKey(opts.epicAiDir, kid, publicKeyPem, rotatedAt);

  const record = await auditTrail.record({
    timestamp: new Date(),
    action: SIGNING_KEY_ROTATED_EVENT,
    tool: '',
    server: 'chariot-audit-chain-signer',
    tier: 'auto',
    status: 'completed',
    input: { oldKid, backend: opts.backend },
    output: { newKid: kid, newPublicKeyPem: publicKeyPem, rotatedAt },
    persona: opts.persona ?? 'system',
    durationMs: 0,
  });

  return { publicKeyPem, kid, oldKid, record };
}
