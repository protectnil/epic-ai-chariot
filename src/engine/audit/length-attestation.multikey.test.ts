/**
 * @epicai/chariot — Adversarial eval: reconcileChainLength wired onto the
 * CH-03 multi-key verification set (CHARIOT::§9.8.1::3)
 *
 * `reconcileChainLength` is the SAME function both the `GET
 * /enterprise/{tenantId}/admin/audit-logs` export route
 * (src/iam/routes/admin.ts) and `chariot audit verify-length`
 * (src/bin/chariot.ts) call — this file proves, against the actual live
 * function (not a route/CLI reimplementation), that:
 *
 *   1. A length attestation signed under a key that has since been
 *      ROTATED OUT still reconciles successfully once its public key is
 *      retained in the multi-key verification set passed to
 *      `reconcileChainLength` — exactly what admin.ts now builds via
 *      `resolveVerifyKeys()` (chainSigner.ts) instead of a single PEM.
 *   2. An attestation signed under a key that is NOT in the set is
 *      excluded from the verified set — fails closed (unverifiable, or
 *      not counted toward the attested length), never silently accepted.
 *   3. Passing a single PEM string (the pre-existing call shape) still
 *      works unchanged — this file's `reconcileChainLength` signature
 *      change is additive, not breaking.
 *
 * Run after `tsc`: node --test dist/engine/audit/length-attestation.multikey.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { reconcileChainLength, persistAttestation, signLengthAttestation } from './length-attestation.js';

function genEd25519(): { privateKeyPem: string; publicKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

test('CHARIOT::§9.8.1::3 — reconcileChainLength accepts an attestation signed under a RETIRED key when the multi-key set retains it', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-multikey-'));
  try {
    const oldKey = genEd25519();
    const newKey = genEd25519();

    // Simulate: chain was attested under `oldKey` before rotation.
    const att = signLengthAttestation(
      { schemaVersion: 1, chainId: 'tenant-1', length: 3, headHash: 'b'.repeat(64), attestedAt: new Date().toISOString() },
      oldKey.privateKeyPem,
    );
    persistAttestation(packageRoot, att);

    // Verifier's set retains BOTH keys post-rotation — CH-03 pattern, exactly
    // what admin.ts's resolveVerifyKeys() builds from CHARIOT_AUDIT_VERIFY_KEYS.
    const verifyKeys = new Map<string, ReturnType<typeof createPublicKey>>();
    verifyKeys.set('old-kid', createPublicKey(oldKey.publicKeyPem));
    verifyKeys.set('new-kid', createPublicKey(newKey.publicKeyPem));

    const result = await reconcileChainLength(packageRoot, 'tenant-1', 3, verifyKeys);
    assert.equal(result.unverifiable, false, 'a retired-but-retained key must still verify the attestation');
    assert.equal(result.truncated, false);
    assert.equal(result.attestedLength, 3);
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — reconcileChainLength fails closed (unverifiable) when the attestation key is NOT in the multi-key set', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-multikey-unknown-'));
  try {
    const signingKey = genEd25519();
    const unrelatedKey = genEd25519(); // never retained anywhere

    const att = signLengthAttestation(
      { schemaVersion: 1, chainId: 'tenant-2', length: 5, headHash: 'c'.repeat(64), attestedAt: new Date().toISOString() },
      signingKey.privateKeyPem,
    );
    persistAttestation(packageRoot, att);

    const verifyKeys = new Map<string, ReturnType<typeof createPublicKey>>();
    verifyKeys.set('unrelated-kid', createPublicKey(unrelatedKey.publicKeyPem));

    const result = await reconcileChainLength(packageRoot, 'tenant-2', 5, verifyKeys);
    assert.equal(result.unverifiable, true, 'an attestation signed under an unretained key must be unverifiable, never silently accepted');
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — reconcileChainLength still accepts a single PEM string (pre-existing call shape, unchanged)', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-single-pem-'));
  try {
    const key = genEd25519();
    const att = signLengthAttestation(
      { schemaVersion: 1, chainId: 'tenant-3', length: 2, headHash: 'd'.repeat(64), attestedAt: new Date().toISOString() },
      key.privateKeyPem,
    );
    persistAttestation(packageRoot, att);

    const result = await reconcileChainLength(packageRoot, 'tenant-3', 2, key.publicKeyPem);
    assert.equal(result.unverifiable, false);
    assert.equal(result.attestedLength, 2);
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});
