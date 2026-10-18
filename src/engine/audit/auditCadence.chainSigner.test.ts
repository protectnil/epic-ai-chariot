/**
 * @epicai/chariot — Adversarial eval: auditCadence.ts wired onto ChainSigner
 * (CHARIOT::§9.8.1::1)
 *
 * Prove-on-revert that the LIVE periodic attest path
 * (src/engine/audit/auditCadence.ts) no longer reads
 * `process.env.CHARIOT_AUDIT_SIGNING_KEY` directly — it goes through
 * `createChainSigner()` (chainSigner.ts), so:
 *   1. gate finding F1 (2026-09-04): the plaintext `env` backend is
 *      GONE — `CHARIOT_AUDIT_SIGNING_KEY` alone, with no custody backend
 *      ever provisioned, does NOT make attestation "configured". With
 *      nothing else configured either, `startAuditCadence` returns
 *      `undefined` (fully inert) rather than silently treating a stray
 *      plaintext env var as a trust root.
 *   2. A provisioned sealed-store key, with NO `CHARIOT_AUDIT_SIGNER_BACKEND`
 *      set (relying on the default), DOES make attestation "configured" —
 *      `isSealedStoreProvisioned()` detects it and cadence starts.
 *   3. The exact signing algorithm `runAttest` now uses (ChainSigner.sign()
 *      over `canonicalAttestationPayload`) round-trips through
 *      `verifyLengthAttestation` against the `sealed-store` backend
 *      (CHARIOT::§9.8.1::1's KMS/HSM/sealed-store MUST).
 *
 * Run after `tsc`: node --test dist/engine/audit/auditCadence.chainSigner.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startAuditCadence } from './auditCadence.js';
import { canonicalAttestationPayload, verifyLengthAttestation } from './length-attestation.js';
import { createChainSigner, sealSigningKey } from './chainSigner.js';

const ENV_KEYS = [
  'CHARIOT_ENTERPRISE',
  'CHARIOT_AUDIT_SIGNER_BACKEND',
  'CHARIOT_TSA_URL',
  'CHARIOT_AUDIT_SIGNING_KEY',
  'CHARIOT_ANCHOR_EVENT_INTERVAL',
  'CHARIOT_ANCHOR_TIME_INTERVAL_MS',
  'CHARIOT_ATTEST_EVENT_INTERVAL',
  'CHARIOT_ATTEST_TIME_INTERVAL_MS',
  'ENTERPRISE_MASTER_KEY',
] as const;

function withEnv<T>(vars: Partial<Record<(typeof ENV_KEYS)[number], string>>, fn: () => T): T {
  const prev: Partial<Record<string, string | undefined>> = {};
  for (const k of ENV_KEYS) prev[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  for (const [k, v] of Object.entries(vars)) process.env[k] = v;
  try {
    return fn();
  } finally {
    for (const k of ENV_KEYS) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

function genEd25519Pem(): { privateKeyPem: string; publicKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

test('CHARIOT::§9.8.1::1 (F1) — CHARIOT_AUDIT_SIGNING_KEY alone (no custody backend provisioned) does NOT configure attestation — cadence stays fully inert', () => {
  const { privateKeyPem } = genEd25519Pem();
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-cadence-no-custody-'));
  try {
    withEnv(
      {
        CHARIOT_AUDIT_SIGNING_KEY: privateKeyPem, // now-inert; no signing path reads it directly
        CHARIOT_ATTEST_EVENT_INTERVAL: '10',
      },
      () => {
        const handle = startAuditCadence({
          chainId: 'default',
          packageRoot,
          chainFilePath: join(packageRoot, 'audit', 'default.jsonl'),
          logger: () => {},
        });
        assert.equal(handle, undefined, 'no anchor and no provisioned custody backend — cadence must be fully inert');
      },
    );
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::1 — a provisioned sealed-store key (default backend, no CHARIOT_AUDIT_SIGNER_BACKEND set) makes attestation configured', () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-cadence-default-sealed-'));
  try {
    withEnv(
      {
        ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 11).toString('base64'),
        CHARIOT_ATTEST_EVENT_INTERVAL: '10',
      },
      () => {
        const { privateKeyPem } = genEd25519Pem();
        sealSigningKey(packageRoot, privateKeyPem);
        const handle = startAuditCadence({
          chainId: 'default',
          packageRoot,
          chainFilePath: join(packageRoot, 'audit', 'default.jsonl'),
          logger: () => {},
        });
        assert.ok(handle, 'a provisioned sealed-store key must configure attestation under the default backend');
        handle?.stop();
      },
    );
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::1 — the sealed-store-backed signature construction auditCadence.runAttest uses round-trips through verifyLengthAttestation', async () => {
  // Proves the EXACT algorithm src/engine/audit/auditCadence.ts's runAttest()
  // now uses (canonicalAttestationPayload + ChainSigner.sign + base64url)
  // against the `sealed-store` backend — the KMS/HSM/sealed-store custody
  // CHARIOT::§9.8.1::1 MUST requires — not just the `env` backend.
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cadence-sealed-'));
  try {
    await withEnv({ ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 3).toString('base64') }, async () => {
      const { privateKeyPem, publicKeyPem } = genEd25519Pem();
      sealSigningKey(dir, privateKeyPem);

      const signer = await createChainSigner({ backend: 'sealed-store', packageRoot: dir });

      const payload = {
        schemaVersion: 1 as const,
        chainId: 'default',
        length: 3,
        headHash: 'a'.repeat(64),
        attestedAt: new Date().toISOString(),
      };
      const signature = await signer.sign(canonicalAttestationPayload(payload));
      const att = { ...payload, signature: signature.toString('base64url') };

      const result = await verifyLengthAttestation(att, publicKeyPem);
      assert.equal(result.valid, true, `attestation signed via sealed-store ChainSigner must verify: ${result.error ?? ''}`);
      assert.equal(result.attestedLength, 3);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::1 — startAuditCadence with CHARIOT_AUDIT_SIGNER_BACKEND=sealed-store explicitly set does not throw at startup', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cadence-sealed-start-'));
  try {
    // Single withEnv call — nesting would clear ENTERPRISE_MASTER_KEY set by
    // an outer call before sealSigningKey/createChainSigner can read it.
    withEnv(
      {
        ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 5).toString('base64'),
        CHARIOT_AUDIT_SIGNER_BACKEND: 'sealed-store',
        CHARIOT_ATTEST_EVENT_INTERVAL: '10',
      },
      () => {
        const { privateKeyPem } = genEd25519Pem();
        sealSigningKey(dir, privateKeyPem);
        const handle = startAuditCadence({
          chainId: 'default',
          packageRoot: dir,
          chainFilePath: join(dir, 'audit', 'default.jsonl'),
          logger: () => {},
        });
        assert.ok(handle, 'cadence must start when a non-env backend is configured and an attest trigger is set');
        handle?.stop();
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
