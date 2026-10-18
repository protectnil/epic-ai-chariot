/**
 * @epicai/chariot — Adversarial eval for CHARIOT::§9.8.1::3 (keyRotation.ts)
 *
 * Failure classes enumerated from CHARIOT-SPEC.md §9.8.1 (docs/spec/CHARIOT-SPEC.md:899-906),
 * "Key rotation is forward-only: rotate to a new key, record the rotation
 * event in the chain, and publish the new public key via the same
 * distribution path as the old one ... Historical records remain
 * verifiable only if the old public key is retained in a multi-key
 * verification set":
 *   1. A rotation appends a chained record (`audit.signing_key.rotated`)
 *      that participates in the SAME hash chain as every other record —
 *      HashChain.verifyChain() over the whole chain still passes.
 *   2. First rotation (no prior key) records oldKid: null.
 *   3. Second rotation records the FIRST rotation's new kid as its oldKid —
 *      forward chaining of custody, not a flat list.
 *   4. gate finding F2: rotation actually PUBLISHES the new public
 *      key — a fresh `resolveVerifyKeys(epicAiDir)` call (no manual map
 *      construction) sees BOTH the old and new kid after two rotations.
 *   5. gate finding F3: `rotateSigningKey` never returns private key
 *      material (the result type has no `privateKeyPem` field at all —
 *      compile-time proof) — signing under a retired kid is done by
 *      constructing a real ChainSigner pinned to that kid
 *      (`sealedStoreKid`), never by reconstructing a raw private key from
 *      a returned string.
 *   6. A record signed under a RETIRED key still verifies once its public
 *      key is retained in the multi-key verification set; a record whose
 *      kid is unknown to the set fails.
 *
 * Run after `tsc`: node --test dist/engine/audit/keyRotation.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AuditTrail } from './AuditTrail.js';
import { HashChain } from './HashChain.js';
import { rotateSigningKey, SIGNING_KEY_ROTATED_EVENT } from './keyRotation.js';
import { computeKid, verifyWithKeySet, createChainSigner, resolveVerifyKeys } from './chainSigner.js';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T): T {
  const prev: Record<string, string | undefined> = {};
  for (const k of Object.keys(vars)) prev[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('CHARIOT::§9.8.1::3 — sealed-store rotation event is appended into the SAME hash chain and verifies clean', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-rotate-chain-'));
  try {
    await withEnv({ ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 2).toString('base64') }, async () => {
      const trail = new AuditTrail({ store: 'memory', integrity: 'sha256-chain' });
      await trail.init();
      await trail.record({
        timestamp: new Date(),
        action: 'chariot_call',
        tool: 'search',
        server: 'adapter-a',
        tier: 'auto',
        status: 'completed',
        input: {},
        output: {},
        persona: 'tenant-1',
        durationMs: 10,
      });

      const first = await rotateSigningKey(trail, { backend: 'sealed-store', packageRoot: dir, epicAiDir: dir });
      assert.equal(first.record.action, SIGNING_KEY_ROTATED_EVENT);
      assert.equal(first.oldKid, null);
      assert.equal((first.record.input as { oldKid: string | null }).oldKid, null);
      assert.equal((first.record.output as { newKid: string }).newKid, first.kid);
      // gate finding F3: the result never carries private material.
      assert.ok(!('privateKeyPem' in first), 'RotateSigningKeyResult must not carry a private key field');

      const second = await rotateSigningKey(trail, {
        backend: 'sealed-store',
        packageRoot: dir,
        epicAiDir: dir,
        oldPublicKeyPem: first.publicKeyPem,
      });
      assert.equal(second.oldKid, first.kid, "second rotation must chain from the FIRST rotation's new kid");
      assert.notEqual(second.kid, first.kid);

      const all = await trail.query({});
      const result = HashChain.verifyChain(all);
      assert.equal(result.valid, true, 'chain must remain internally consistent after rotation events');

      const rotationRecords = all.filter((r) => r.action === SIGNING_KEY_ROTATED_EVENT);
      assert.equal(rotationRecords.length, 2);
      const toolRecord = all.find((r) => r.action === 'chariot_call');
      assert.ok(toolRecord);
      for (const r of rotationRecords) {
        assert.ok(r.sequenceNumber > toolRecord!.sequenceNumber);
      }
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 (F2) — rotation PUBLISHES the new key: resolveVerifyKeys sees BOTH kids after two rotations, no manual wiring', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-rotate-publish-'));
  try {
    await withEnv({ ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 4).toString('base64') }, async () => {
      const trail = new AuditTrail({ store: 'memory', integrity: 'sha256-chain' });
      await trail.init();

      const first = await rotateSigningKey(trail, { backend: 'sealed-store', packageRoot: dir, epicAiDir: dir });
      const second = await rotateSigningKey(trail, {
        backend: 'sealed-store',
        packageRoot: dir,
        epicAiDir: dir,
        oldPublicKeyPem: first.publicKeyPem,
      });

      // No manual Map construction, no env vars set — this is EXACTLY what
      // admin.ts / chariot.ts verify-length now call.
      const verifyKeys = resolveVerifyKeys(dir);
      assert.ok(verifyKeys.has(first.kid), 'the FIRST (now-retired) key must still be published');
      assert.ok(verifyKeys.has(second.kid), 'the SECOND (current) key must be published');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 (F3/F2) — a record signed under a RETIRED key still verifies via a real signer pinned to that kid; unknown kid fails', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-rotate-retired-sign-'));
  try {
    await withEnv({ ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 6).toString('base64') }, async () => {
      const trail = new AuditTrail({ store: 'memory', integrity: 'sha256-chain' });
      await trail.init();

      const first = await rotateSigningKey(trail, { backend: 'sealed-store', packageRoot: dir, epicAiDir: dir });
      await rotateSigningKey(trail, {
        backend: 'sealed-store',
        packageRoot: dir,
        epicAiDir: dir,
        oldPublicKeyPem: first.publicKeyPem,
      });

      // Sign a payload using a REAL ChainSigner explicitly pinned to the
      // FIRST (now-retired, no longer the sealed-store "current") kid —
      // never a reconstructed raw private key.
      const retiredSigner = await createChainSigner({ backend: 'sealed-store', packageRoot: dir, sealedStoreKid: first.kid });
      const payload = Buffer.from('historical-record-payload');
      const sigUnderRetiredKey = await retiredSigner.sign(payload);

      const verifyKeys = resolveVerifyKeys(dir);
      assert.equal(verifyWithKeySet(payload, sigUnderRetiredKey, first.kid, verifyKeys), true);
      // A record whose kid was never published must fail, not throw.
      assert.equal(verifyWithKeySet(payload, sigUnderRetiredKey, 'unknown-kid-0000', verifyKeys), false);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — computeKid is stable and distinguishes distinct rotated keys', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-rotate-kid-stable-'));
  try {
    await withEnv({ ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 8).toString('base64') }, async () => {
      const first = await rotateSigningKey(new AuditTrail({ store: 'memory', integrity: 'sha256-chain' }), {
        backend: 'sealed-store',
        packageRoot: dir,
        epicAiDir: dir,
      });
      assert.equal(computeKid(first.publicKeyPem), first.kid);
      const second = await rotateSigningKey(new AuditTrail({ store: 'memory', integrity: 'sha256-chain' }), {
        backend: 'sealed-store',
        packageRoot: dir,
        epicAiDir: dir,
      });
      assert.notEqual(computeKid(first.publicKeyPem), computeKid(second.publicKeyPem));
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
