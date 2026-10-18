/**
 * Prove-on-revert for CHARIOT::§9.8.4::4 and CHARIOT::§9.8.4::2.
 *
 * Spec, CHARIOT-SPEC.md §9.8.4:
 *   "Enabling TSA anchoring (CHARIOT_TSA_URL set) without setting at least
 *   one cadence trigger is a configuration error and MUST produce a startup
 *   warning."
 *   "For length attestation, the cadence should match or exceed the anchor
 *   cadence — a gap between the last attestation and the last anchor
 *   creates an un-attested window where tail truncation is undetectable."
 *
 * Defect this catches: (1) the anchor-misconfiguration branch THREW,
 * aborting the entire `chariot serve` startup (setup.ts calls
 * startAuditCadence outside any try/catch) instead of producing the
 * spec-mandated non-fatal "startup warning"; (2) there was no comparison
 * anywhere between the attest and anchor cadence intervals, so an operator
 * could configure attestation less frequently than anchoring with no
 * warning.
 *
 * Updated 2026-09-04 (gate finding F1): attestation "configured"
 * detection no longer reads the removed plaintext `env` backend's
 * `CHARIOT_AUDIT_SIGNING_KEY` — the two cadence-comparison tests below now
 * provision a real sealed-store key (`sealSigningKey`, chainSigner.ts) so
 * `isSealedStoreProvisioned()` reports attestation as configured, exactly
 * the path an operator hits with the (now-default) sealed-store backend.
 *
 * Fixed 2026-09-04: `sealSigningKey()` calls `resolvePrivateKey()` ->
 * `createPrivateKey()` synchronously at provisioning time (unlike the
 * removed `env` backend, which only read `CHARIOT_AUDIT_SIGNING_KEY` as a
 * boolean-presence check here — the string was never actually decoded by
 * these two tests before, since they `.stop()` before any attest tick
 * fires). The placeholder PEM previously used here
 * (`MC4CAQAwBQYDK2VwBCIEIA==`) decodes to a 16-byte PKCS#8 prefix with NO
 * seed bytes appended — not a valid key at all, just the fixed DER header
 * — so it was never exercised by real crypto until this file started
 * calling `sealSigningKey()`. Each test below now generates a REAL
 * `generateKeyPairSync('ed25519')` PKCS#8 PEM instead.
 *
 * Run (after tsc): node --test dist/engine/audit/auditCadence.warning-not-throw.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startAuditCadence } from './auditCadence.js';
import { sealSigningKey } from './chainSigner.js';

/** A fresh, real Ed25519 PKCS#8 PEM — used only to provision a sealed-store
 * artifact so attestation reads as "configured"; the key material itself
 * is never asserted on. Generated per call (never reused across tests). */
function freshEd25519Pem(): string {
  const { privateKey } = generateKeyPairSync('ed25519');
  return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
}

const ENV_KEYS = [
  'CHARIOT_TSA_URL',
  'CHARIOT_AUDIT_SIGNER_BACKEND',
  'ENTERPRISE_MASTER_KEY',
  'CHARIOT_ANCHOR_EVENT_INTERVAL',
  'CHARIOT_ANCHOR_TIME_INTERVAL_MS',
  'CHARIOT_ATTEST_EVENT_INTERVAL',
  'CHARIOT_ATTEST_TIME_INTERVAL_MS',
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

test('CHARIOT::§9.8.4::4 — anchor misconfiguration produces a startup warning, does NOT throw', () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-cadence-'));
  const logs: string[] = [];
  try {
    withEnv({ CHARIOT_TSA_URL: 'https://tsa.example.invalid/' }, () => {
      assert.doesNotThrow(() => {
        startAuditCadence({
          chainId: 'default',
          packageRoot,
          chainFilePath: join(packageRoot, 'audit', 'default.jsonl'),
          logger: (m) => logs.push(m),
        })?.stop();
      });
    });
    assert.ok(
      logs.some((m) => /WARNING/i.test(m) && /CHARIOT_TSA_URL/.test(m)),
      `expected a WARNING log mentioning CHARIOT_TSA_URL; got: ${JSON.stringify(logs)}`,
    );
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.4::2 — a looser attest event-cadence than anchor event-cadence produces a warning', () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-cadence-'));
  const logs: string[] = [];
  try {
    withEnv(
      {
        CHARIOT_TSA_URL: 'https://tsa.example.invalid/',
        CHARIOT_ANCHOR_EVENT_INTERVAL: '500',
        ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 9).toString('base64'),
        CHARIOT_ATTEST_EVENT_INTERVAL: '2000', // looser than the 500-event anchor cadence
      },
      () => {
        // Sealed-store is the default backend — provisioning a key here is
        // what makes attestation read as "configured" (isSealedStoreProvisioned).
        sealSigningKey(packageRoot, freshEd25519Pem());
        startAuditCadence({
          chainId: 'default',
          packageRoot,
          chainFilePath: join(packageRoot, 'audit', 'default.jsonl'),
          logger: (m) => logs.push(m),
        })?.stop();
      },
    );
    assert.ok(
      logs.some((m) => /WARNING/i.test(m) && /CHARIOT_ATTEST_EVENT_INTERVAL/.test(m)),
      `expected a cadence-mismatch WARNING; got: ${JSON.stringify(logs)}`,
    );
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.4::2 — attest cadence at least as tight as anchor cadence produces NO warning', () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-cadence-'));
  const logs: string[] = [];
  try {
    withEnv(
      {
        CHARIOT_TSA_URL: 'https://tsa.example.invalid/',
        CHARIOT_ANCHOR_EVENT_INTERVAL: '2000',
        ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 9).toString('base64'),
        CHARIOT_ATTEST_EVENT_INTERVAL: '500', // at least as frequent as anchoring
      },
      () => {
        sealSigningKey(packageRoot, freshEd25519Pem());
        startAuditCadence({
          chainId: 'default',
          packageRoot,
          chainFilePath: join(packageRoot, 'audit', 'default.jsonl'),
          logger: (m) => logs.push(m),
        })?.stop();
      },
    );
    assert.ok(
      !logs.some((m) => /cadence/i.test(m) && /WARNING/i.test(m) && /looser/.test(m)),
      `expected no cadence-mismatch WARNING; got: ${JSON.stringify(logs)}`,
    );
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});
