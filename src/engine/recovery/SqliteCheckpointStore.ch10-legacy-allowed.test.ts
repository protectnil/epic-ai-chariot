/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10, rulings item 59) — "AAD = the
 * length-prefixed concatenation LE_u32(len(tenantId_bytes)) ‖
 * tenantId_bytes ‖ adapterId_bytes" (identical on encrypt and decrypt).
 *
 * `SqliteCheckpointStore.ts` was CREATED in commit 624c2b9 — the same
 * commit that introduced the `v2:` AAD-bound ciphertext prefix — so every
 * checkpoint row this store has ever written is v2/AAD-bound; there is no
 * code path, past or present, that could have produced a legacy
 * (pre-CH-10, empty-AAD) checkpoint row. Its decrypt call sites therefore
 * pass a FIXED `legacyAllowed=false` to `callNativeDecrypt` (crypto.ts) —
 * never a policy lookup — so a legacy-shaped row here (corruption, or a
 * foreign write) fails closed exactly like a genuine relocation attack.
 *
 * This suite proves two things with an injected mock binding (no native
 * binary needed):
 *   1. The store always passes `legacyAllowed === false` on the read path
 *      when the binding advertises the CH-10 gate (`vaultProtocolVersion`).
 *   2. On a binding WITHOUT that capability (the old, currently-signed
 *      shape `decryptCredential` had before rulings item 59),
 *      `callNativeDecrypt` calls it with the OLD 5-argument shape — never
 *      a 6th argument the binary was never built to accept.
 *
 * Run (after `npm run build` and `tsc`):
 *   node --test dist/engine/recovery/SqliteCheckpointStore.ch10-legacy-allowed.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');

const { SqliteCheckpointStore } = await import('./SqliteCheckpointStore.js');
const { canonicalStringify } = await import('../../util/canonical-json.js');

function tmpDbPath(): string {
  return join(mkdtempSync(join(tmpdir(), 'ch10-checkpoint-')), 'checkpoints.db');
}

function fixedCheckpoint() {
  return {
    tenantId: 'tenant-a',
    stepId: 'step-1',
    parentStepId: null,
    traceId: 'trace-1',
    iteration: 0,
    input: { a: 1 },
    output: { b: 2 },
    timestamp: new Date(),
  };
}

test('§12.2/CH-10 item 59: SqliteCheckpointStore passes legacyAllowed=false on a binding that supports the gate', async () => {
  const decryptCalls: unknown[][] = [];
  const binding = {
    encryptCredential(plaintext: string) {
      // Fake "ciphertext" that round-trips: the mock decrypt below ignores
      // it and returns fixed JSON, so the actual bytes here are opaque.
      return { encrypted: `stub:${plaintext.length}`, iv: 'stub-iv' };
    },
    decryptCredential(...args: unknown[]) {
      decryptCalls.push(args);
      return canonicalStringify({ a: 1 });
    },
    vaultProtocolVersion() {
      return 2;
    },
  };

  const store = new SqliteCheckpointStore(tmpDbPath(), { binding });
  const cp = fixedCheckpoint();
  await store.record(cp);
  const latest = await store.latest(cp.tenantId, cp.traceId);
  assert.ok(latest, 'a recorded checkpoint must be readable back');
  store.close();

  // record() writes input+output; latest() reads them back — 2 decrypt
  // calls minimum (one per field).
  assert.ok(decryptCalls.length >= 2, 'expected at least one decrypt call per field');
  for (const call of decryptCalls) {
    assert.equal(call.length, 6, 'a gate-capable binding must be called with all 6 arguments');
    assert.equal(call[5], false, 'legacyAllowed must be the fixed constant false, never true or a policy lookup');
  }
});

test('§12.2/CH-10 item 59: SqliteCheckpointStore calls a gate-incapable binding with the OLD 5-argument shape', async () => {
  const decryptCalls: unknown[][] = [];
  const binding = {
    encryptCredential(plaintext: string) {
      return { encrypted: `stub:${plaintext.length}`, iv: 'stub-iv' };
    },
    decryptCredential(...args: unknown[]) {
      decryptCalls.push(args);
      return canonicalStringify({ a: 1 });
    },
    // Deliberately NO vaultProtocolVersion — simulates the currently
    // signed Sep-1 binary, which has no CH-10 legacyAllowed parameter at
    // all. callNativeDecrypt (crypto.ts) must not hand it a 6th argument
    // it was never built to accept.
  };

  const store = new SqliteCheckpointStore(tmpDbPath(), { binding });
  const cp = fixedCheckpoint();
  await store.record(cp);
  const latest = await store.latest(cp.tenantId, cp.traceId);
  assert.ok(latest);
  store.close();

  assert.ok(decryptCalls.length >= 2);
  for (const call of decryptCalls) {
    assert.equal(call.length, 5, 'a gate-incapable binding must be called with exactly the old 5 arguments');
  }
});
