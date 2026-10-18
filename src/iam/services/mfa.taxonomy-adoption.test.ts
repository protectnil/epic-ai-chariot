// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)
/**
 * CHARIOT::§16.1 IAM (CHARIOT-SPEC.md:1346, rulings item 91) — "IAM: ...
 * `mfa.enrolled`, ..."
 *
 * REAL BEHAVIORAL test (revised per chariot-verify-wave2 finding: the
 * prior source-inspection version isolated `saveMfaSecret`'s body by
 * searching for the following `deleteMfaSecret` declaration in compiled
 * output — a concurrent edit to mfa.ts by another builder (assertion-
 * scope primitives, then a version-counter fix) moved that boundary and
 * broke the isolation). Rather than harden the boundary-finding regex
 * again, this now drives `saveMfaSecret()` for real against the repo's
 * `fakeMongoCollection` fixture (src/iam/testFakes), with a genuine
 * (random, disposable) master key set so `encryptTotpSecret()` — the
 * actual encrypt call, made BY mfa.ts, an already-registered
 * `MASTER_KEY_CONSUMERS` entry — runs unmocked. This file itself performs
 * no derivation or delegator call (see the VALIDATION_ONLY_FILES entry in
 * masterKeyConsumers.ts this file is registered under, for the exact
 * accounting), so a real behavioral test is possible without becoming an
 * unregistered structural candidate.
 *
 * Run (after tsc): node --test dist/iam/services/mfa.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

process.env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');

const { saveMfaSecret } = await import('./mfa.js');
const { setMongoClient } = await import('../db.js');
const { makeFakeCollection, makeFakeMongoClient } = await import('../testFakes/fakeMongoCollection.js');
const { chariotEmitter } = await import('../../observability/emitter.js');

test('§16.1 IAM: saveMfaSecret() emits mfa.enrolled with the tenantId/userId AFTER the write succeeds', async () => {
  const col = makeFakeCollection([]);
  setMongoClient(makeFakeMongoClient({ iam_mfa_secrets: col }), 'chariot');

  const events: Array<{ type: string; data: Record<string, unknown> }> = [];
  const cb = (e: { type: string; data: Record<string, unknown> }) => events.push(e);
  chariotEmitter.on(cb);
  try {
    await saveMfaSecret('tenant-mfa-test', 'user-1', 'JBSWY3DPEHPK3PXP');

    const found = events.find((e) => e.type === 'mfa.enrolled');
    assert.ok(found, 'expected an mfa.enrolled event');
    assert.equal(found!.data.tenantId, 'tenant-mfa-test');
    assert.equal(found!.data.userId, 'user-1');

    // The write itself actually happened — the event is not a false
    // positive from an emit-before-write ordering bug.
    const stored = await col.findOne({ tenantId: 'tenant-mfa-test', userId: 'user-1' });
    assert.ok(stored, 'the MFA secret record must actually be persisted');
  } finally {
    chariotEmitter.off(cb);
  }
});

test('§16.1 IAM: saveMfaSecret() re-enrollment (upsert over an existing secret) still emits mfa.enrolled exactly once', async () => {
  const col = makeFakeCollection([
    { _id: 'x', tenantId: 'tenant-mfa-test-2', userId: 'user-2', encrypted: 'old', iv: 'old', enrolledAt: new Date(0) },
  ]);
  setMongoClient(makeFakeMongoClient({ iam_mfa_secrets: col }), 'chariot');

  const events: Array<{ type: string }> = [];
  const cb = (e: { type: string }) => events.push(e);
  chariotEmitter.on(cb);
  try {
    await saveMfaSecret('tenant-mfa-test-2', 'user-2', 'ANOTHERSECRETBASE32');
    assert.equal(events.filter((e) => e.type === 'mfa.enrolled').length, 1);
  } finally {
    chariotEmitter.off(cb);
  }
});

test('§16.1 IAM: a write failure does NOT emit mfa.enrolled (the emit must be conditioned on write success, not unconditional)', async () => {
  const col = makeFakeCollection([]);
  col.failNextUpdateOnce(new Error('simulated Mongo write failure'));
  setMongoClient(makeFakeMongoClient({ iam_mfa_secrets: col }), 'chariot');

  const events: Array<{ type: string }> = [];
  const cb = (e: { type: string }) => events.push(e);
  chariotEmitter.on(cb);
  try {
    await assert.rejects(() => saveMfaSecret('tenant-mfa-test-3', 'user-3', 'YETANOTHERSECRET'));
    assert.equal(events.filter((e) => e.type === 'mfa.enrolled').length, 0, 'a failed write must not report a false enrollment success');
  } finally {
    chariotEmitter.off(cb);
  }
});
