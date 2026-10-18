/**
 * @epicai/chariot — Adversarial eval for CHARIOT::§9.8.1::3 verify-key store
 * (gate finding F2: "publish the new public key via the same
 * distribution path as the old one" had no concrete distribution path.)
 *
 * Failure classes:
 *   1. loadVerifyKeyStore on a fresh dir (no file yet) returns {} rather
 *      than throwing.
 *   2. appendVerifyKey persists an entry that a fresh loadVerifyKeyStore()
 *      call reads back with the SAME publicKeyPem.
 *   3. appendVerifyKey NEVER overwrites a prior kid's entry with a
 *      different one — appending twice under different kids retains BOTH
 *      (forward-only, per CHARIOT §9.8.1::3).
 *   4. retireVerifyKey stamps retiredAt but the entry (and its
 *      verifiability contract) remains in the store.
 *   5. A corrupt store file degrades to {} rather than throwing (mirrors
 *      loadAttestations' "skip unparseable" posture).
 *   6. The on-disk file never contains private-key material (it only ever
 *      receives public keys as input in the first place, but this proves
 *      the write path doesn't accidentally serialize anything else).
 *
 * Run after `tsc`: node --test dist/engine/audit/verifyKeyStore.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadVerifyKeyStore, appendVerifyKey, retireVerifyKey } from './verifyKeyStore.js';

function genPem(): string {
  const { publicKey } = generateKeyPairSync('ed25519');
  return publicKey.export({ type: 'spki', format: 'pem' }) as string;
}

test('CHARIOT::§9.8.1::3 — loadVerifyKeyStore on a fresh directory returns {} (no throw)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-verifykeystore-fresh-'));
  try {
    assert.deepEqual(loadVerifyKeyStore(dir), {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — appendVerifyKey persists an entry a fresh load reads back', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-verifykeystore-append-'));
  try {
    const pem = genPem();
    appendVerifyKey(dir, 'kid-a', pem, '2026-01-01T00:00:00.000Z');
    const store = loadVerifyKeyStore(dir);
    assert.equal(store['kid-a']?.publicKeyPem, pem);
    assert.equal(store['kid-a']?.addedAt, '2026-01-01T00:00:00.000Z');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — appendVerifyKey is forward-only: a second kid does not evict the first', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-verifykeystore-forward-'));
  try {
    const pemA = genPem();
    const pemB = genPem();
    appendVerifyKey(dir, 'kid-a', pemA);
    appendVerifyKey(dir, 'kid-b', pemB);
    const store = loadVerifyKeyStore(dir);
    assert.equal(store['kid-a']?.publicKeyPem, pemA, 'kid-a must survive a later append of kid-b');
    assert.equal(store['kid-b']?.publicKeyPem, pemB);
    assert.equal(Object.keys(store).length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — retireVerifyKey stamps retiredAt but the entry (and its verifiability) remains', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-verifykeystore-retire-'));
  try {
    const pem = genPem();
    appendVerifyKey(dir, 'kid-a', pem);
    retireVerifyKey(dir, 'kid-a', '2026-06-01T00:00:00.000Z');
    const store = loadVerifyKeyStore(dir);
    assert.equal(store['kid-a']?.publicKeyPem, pem, 'a retired key must still be present for historical verification');
    assert.equal(store['kid-a']?.retiredAt, '2026-06-01T00:00:00.000Z');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — retireVerifyKey on an unknown kid is a no-op, not a throw', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-verifykeystore-retire-unknown-'));
  try {
    assert.doesNotThrow(() => retireVerifyKey(dir, 'never-existed'));
    assert.deepEqual(loadVerifyKeyStore(dir), {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — a corrupt store file degrades to {} rather than throwing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-verifykeystore-corrupt-'));
  try {
    mkdirSync(join(dir, 'audit'), { recursive: true });
    writeFileSync(join(dir, 'audit', 'verify-keys.json'), 'not valid json{{{', 'utf-8');
    assert.deepEqual(loadVerifyKeyStore(dir), {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — the on-disk store file never contains PRIVATE KEY bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-verifykeystore-noplain-'));
  try {
    appendVerifyKey(dir, 'kid-a', genPem());
    const content = readFileSync(join(dir, 'audit', 'verify-keys.json'), 'utf-8');
    assert.ok(!content.includes('PRIVATE KEY'));
    assert.ok(content.includes('PUBLIC KEY'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
