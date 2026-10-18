/**
 * Prove-on-revert for CHARIOT-SPEC.md §12.2 / CH-10 — "AAD = tenantId
 * concatenated with adapterId. A bad auth tag fails the decrypt explicitly;
 * corrupt records are not silently skipped."
 *
 * Defect this catches: `vault.rs` called AES-GCM with no AAD at all
 * (`.encrypt(nonce, plaintext.as_bytes())`), and `encryptFields`/
 * `decryptFields` (this module) had no way to supply one — a ciphertext
 * could be relocated from one adapter's `iam_adapter_credentials` row to
 * another row for the SAME tenant and still decrypt successfully, because
 * the only binding was the tenant-scoped HKDF key. Fixed by adding a
 * required `recordId` (CH-10's `adapterId`) parameter to both functions,
 * bound into the native layer's AES-GCM AAD.
 *
 * This test drives the REAL native binary (not a mock) end-to-end through
 * the `encryptFields`/`decryptFields` boundary, so it also proves the
 * TypeScript→Rust plumbing (the parameter is actually threaded through, not
 * just accepted and dropped).
 *
 * Run (after `npm run build:native` and `tsc`): node --test dist/iam/crypto.aad-binding.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

process.env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');

const { encryptFields, decryptFields } = await import('./crypto.js');

test('§12.2/CH-10: round-trip — (tenant, adapter) encrypt then decrypt returns the plaintext', async () => {
  const { encrypted, iv } = encryptFields({ apiKey: 'secret-123' }, 'tenant-a', 'adapter-x');
  const result = await decryptFields(encrypted, iv, 'tenant-a', 'adapter-x');
  assert.deepEqual(result.fields, { apiKey: 'secret-123' });
  // v2 (AAD-bound) round trip — never a legacy/upgrade candidate.
  assert.equal(result.upgraded, null, 'a v2 record must not report an upgrade');
});

test('§12.2/CH-10: relocation attack — a ciphertext from adapter-x cannot decrypt as adapter-y in the same tenant', async () => {
  const { encrypted, iv } = encryptFields({ apiKey: 'secret-123' }, 'tenant-a', 'adapter-x');
  await assert.rejects(
    () => decryptFields(encrypted, iv, 'tenant-a', 'adapter-y'),
    /Decryption failed/,
    'relocating the ciphertext to a different adapterId within the same tenant must fail closed, not decrypt',
  );
});

test('§12.2/CH-10 regression: cross-tenant decrypt still fails (per-tenant key derivation)', async () => {
  const { encrypted, iv } = encryptFields({ apiKey: 'secret-123' }, 'tenant-a', 'adapter-x');
  await assert.rejects(
    () => decryptFields(encrypted, iv, 'tenant-b', 'adapter-x'),
    /Decryption failed/,
  );
});

test('§12.2/CH-10: AAD boundary collision — tenant "a"+adapter "bc" must not decrypt as tenant "ab"+adapter "c"', async () => {
  const { encrypted, iv } = encryptFields({ apiKey: 'secret-123' }, 'a', 'bc');
  await assert.rejects(
    () => decryptFields(encrypted, iv, 'ab', 'c'),
    /Decryption failed/,
    'a bare tenantId+adapterId string concatenation would collide here; the AAD encoding must not',
  );
});

test('§12.2/CH-10: encryptFields requires a recordId argument (TypeScript signature proof)', () => {
  // Arity proof that the fix is not just accepted-and-dropped: the compiled
  // function must declare (fields, tenantId, recordId) — 3 parameters.
  assert.equal(encryptFields.length, 3, 'encryptFields must require fields, tenantId, AND recordId');
  assert.equal(decryptFields.length, 4, 'decryptFields must require encrypted, iv, tenantId, AND recordId');
});
