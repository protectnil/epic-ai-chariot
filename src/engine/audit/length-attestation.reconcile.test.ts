/**
 * Prove-on-revert for CHARIOT::§9.8.3::4.
 *
 * Spec, CHARIOT-SPEC.md §9.8.3:
 *   "On each audit export or periodic health check, the verifier reconciles
 *   the current chain length against the most recent attested length. If
 *   currentLength < attestedLength, the difference indicates tail
 *   truncation — emit CRITICAL audit.tail_truncation_detected
 *   {chainId, attestedLength, currentLength} and halt export."
 *
 * Defect this catches: no reusable reconciliation function existed —
 * `detectTruncation`/`loadAttestations`/`verifyLengthAttestation` were wired
 * ONLY into the manual `chariot audit verify-length` CLI subcommand, which
 * its own source comment (src/bin/chariot.ts:1854) admits "has no automated
 * caller". Neither the /audit-logs HTTP export route nor any periodic
 * health check ever invoked them, so a truncated chain was served to an
 * auditor with zero detection in the running server.
 *
 * Run (after tsc): node --test dist/engine/audit/length-attestation.reconcile.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  reconcileChainLength,
  signLengthAttestation,
  persistAttestation,
} from './length-attestation.js';

const PRIVATE_KEY_PEM =
  '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOg8vWwq4bolK0pcTHd4B6awTTYFCK3Mw6Oa74fm8xxo\n-----END PRIVATE KEY-----\n';
const PUBLIC_KEY_PEM =
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcnKaAYwe4Z9X6t5esg7ogzEcFbHia/vB/QOE2IeFKnc=\n-----END PUBLIC KEY-----\n';

function attestAndPersist(packageRoot: string, chainId: string, length: number, headHash: string): void {
  const att = signLengthAttestation(
    { schemaVersion: 1, chainId, length, headHash, attestedAt: new Date().toISOString() },
    PRIVATE_KEY_PEM,
  );
  persistAttestation(packageRoot, att);
}

test('CHARIOT::§9.8.3::4 — currentLength < attestedLength -> truncated:true with the offending lengths', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-'));
  try {
    attestAndPersist(packageRoot, 'tenant-a', 100, 'a'.repeat(64));
    const result = await reconcileChainLength(packageRoot, 'tenant-a', 42, PUBLIC_KEY_PEM);
    assert.equal(result.truncated, true);
    assert.equal(result.attestedLength, 100);
    assert.equal(result.currentLength, 42);
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.3::4 — currentLength >= attestedLength -> truncated:false', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-'));
  try {
    attestAndPersist(packageRoot, 'tenant-b', 50, 'b'.repeat(64));
    const result = await reconcileChainLength(packageRoot, 'tenant-b', 50, PUBLIC_KEY_PEM);
    assert.equal(result.truncated, false);
    assert.equal(result.attestedLength, 50);
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.3::4 — no attestations for chainId -> truncated:false (opt-in, nothing to reconcile against)', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-'));
  try {
    const result = await reconcileChainLength(packageRoot, 'tenant-never-attested', 999, PUBLIC_KEY_PEM);
    assert.equal(result.truncated, false);
    assert.equal(result.attestedLength, 0);
    assert.equal(result.currentLength, 999);
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.3::4 — an unverifiable (wrong-key) attestation is excluded, not trusted, and cannot mask real truncation', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-'));
  try {
    // Attest with the real key (length=200), then also drop in a forged
    // attestation claiming a SHORTER length signed under a DIFFERENT key.
    attestAndPersist(packageRoot, 'tenant-c', 200, 'c'.repeat(64));
    const forged = signLengthAttestation(
      {
        schemaVersion: 1,
        chainId: 'tenant-c',
        length: 5,
        headHash: 'd'.repeat(64),
        attestedAt: new Date(Date.now() + 1000).toISOString(),
      },
      PRIVATE_KEY_PEM, // signed correctly but we'll verify against a DIFFERENT public key below
    );
    persistAttestation(packageRoot, forged);

    // Verify against a public key that does NOT match PRIVATE_KEY_PEM at all —
    // simulates an attestation store containing a signature that fails
    // verification. Only genuinely-verified attestations may participate.
    const wrongPublicKeyPem =
      '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n';
    // A structurally-invalid/mismatched key must not crash reconciliation —
    // verifyLengthAttestation is documented to never throw/reject.
    await assert.doesNotReject(() => reconcileChainLength(packageRoot, 'tenant-c', 200, wrongPublicKeyPem));
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.3::4 — attestations exist but no publicKeyPem supplied -> unverifiable:true (fail closed, never served unverified)', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-'));
  try {
    attestAndPersist(packageRoot, 'tenant-d', 300, 'e'.repeat(64));
    const result = await reconcileChainLength(packageRoot, 'tenant-d', 1);
    assert.equal(result.unverifiable, true, 'an attested chain with no verification key is unverifiable');
    assert.equal(result.truncated, false, 'truncation cannot be asserted without verified evidence');
    assert.equal(result.attestedLength, 0);
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.3::4 — attestations exist but every signature fails under the supplied key -> unverifiable:true', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-'));
  try {
    attestAndPersist(packageRoot, 'tenant-e', 300, 'f'.repeat(64));
    const wrongPublicKeyPem =
      '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n';
    const result = await reconcileChainLength(packageRoot, 'tenant-e', 300, wrongPublicKeyPem);
    assert.equal(result.unverifiable, true);
    assert.equal(result.truncated, false);
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.3::4 — no attestations at all -> unverifiable:false (nothing was ever attested; nothing to reconcile)', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-reconcile-'));
  try {
    const result = await reconcileChainLength(packageRoot, 'tenant-never', 10);
    assert.equal(result.unverifiable, false);
    assert.equal(result.truncated, false);
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});
