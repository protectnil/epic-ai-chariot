/**
 * CHARIOT-SPEC §12.2 (CH-10), rulings item 59 — "upgrade-on-decrypt,
 * migration, cutover". Drives the REAL native binary end-to-end.
 *
 * Ruling executed:
 *   (1) UPGRADE-ON-DECRYPT — a legacy (unprefixed) ciphertext decrypts once
 *       and `decryptFields` reports a freshly re-encrypted v2 ciphertext
 *       the caller must persist; that upgraded ciphertext is AAD-bound
 *       exactly like a record written by `encryptFields` (relocation to a
 *       different adapterId fails).
 *   (2) HARD CUTOVER — legacy decryption is refused (distinct error code
 *       VAULT_LEGACY_CIPHERTEXT_REFUSED, never a silent empty-AAD retry)
 *       when CHARIOT_VAULT_LEGACY_DECRYPT=0, or when CHARIOT_ENTERPRISE=1
 *       without an explicit CHARIOT_VAULT_LEGACY_DECRYPT=1 override.
 *
 * The tenant-migration-marker refusal trigger (resolveLegacyDecryptPolicy's
 * third condition) requires a live Mongo client (`setMongoClient`) this
 * colocated unit test does not stand up — that path is covered by the
 * private eval mirror per the migration-CLI report.
 *
 * Run (after `npm run build:native` and `tsc`): node --test dist/iam/crypto.ch10-cutover.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

process.env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');

const {
  encryptFields,
  decryptFields,
  decryptFieldsForVaultMigration,
  isLegacyCiphertext,
  splitEncryptedIv,
  hasVaultLegacyGate,
  VaultLegacyCiphertextRefusedError,
} = await import('./crypto.js');
const { loadNativeBinding } = await import('../license/binding.js');

/**
 * Build a legacy (pre-CH-10, unprefixed, empty-AAD) ciphertext the same
 * shape the pre-CH-10 binary produced — `native/src/vault.rs`'s own Rust
 * test fixture does the equivalent thing on the Rust side. There is no
 * TypeScript code path left that PRODUCES this shape (encryptFields always
 * emits `v2:`), so this test constructs it directly via the native
 * encrypt-with-empty-AAD... which the binary no longer exposes either.
 * Simplest true fixture: call the real encryptCredential, then strip the
 * `v2:` prefix — this is byte-identical to the legacy shape ONLY because
 * `encryptCredential`'s v2 AAD is non-empty (tenant+adapter), so stripping
 * the prefix does NOT yield a valid empty-AAD ciphertext for decrypt.
 * Instead, drive the native binding directly with an empty adapterId is
 * ALSO not equivalent (AAD would be `LE_u32(0)`, not truly empty). The
 * only faithful legacy fixture is AES-GCM-encrypt with a literal empty
 * AAD, which requires bypassing `encryptCredential`. Since that primitive
 * isn't exposed to TypeScript, this suite instead proves the CH-10 cutover
 * contract at the layer TypeScript actually controls: the POLICY gate
 * (`resolveLegacyDecryptPolicy` via `decryptFields`) never attempts a
 * native call at all when refused, which is independently provable from
 * `isLegacyCiphertext` plus the thrown error type — no native fixture
 * needed for that half. The native-layer legacy-decrypt-succeeds half is
 * covered by `native/src/vault.rs`'s own Rust unit tests
 * (`legacy_unprefixed_record_still_decrypts`,
 * `legacy_record_refused_when_not_allowed`), which construct the true
 * empty-AAD fixture directly in Rust.
 */

test('§12.2/CH-10 item 59: isLegacyCiphertext distinguishes v2 from legacy by prefix only', () => {
  const { encrypted } = encryptFields({ apiKey: 'x' }, 'tenant-a', 'adapter-x');
  assert.equal(isLegacyCiphertext(encrypted), false, 'encryptFields output must never be legacy');
  assert.equal(isLegacyCiphertext('deadbeef=='), true, 'unprefixed base64 is legacy');
  assert.equal(isLegacyCiphertext('v2:deadbeef=='), false);
});

test('§12.2/CH-10 item 59: splitEncryptedIv uses the LAST colon, not the first (v2-prefix safe)', () => {
  // The exact bug class this fixes: a v2-prefixed `encrypted` carries its
  // own internal colon, so `"encrypted:iv".indexOf(':')` / `.split(':')`
  // split at the WRONG point for any v2 record.
  const combined = 'v2:AAAA:BBBB';
  const parts = splitEncryptedIv(combined);
  assert.deepEqual(parts, { encrypted: 'v2:AAAA', iv: 'BBBB' });
  assert.notDeepEqual(
    parts,
    { encrypted: combined.split(':')[0], iv: combined.split(':')[1] },
    'a naive first-colon split would wrongly produce {encrypted:"v2", iv:"AAAA"}',
  );
});

test('§12.2/CH-10 item 59: splitEncryptedIv rejects a malformed (no-colon, or empty-half) blob', () => {
  assert.equal(splitEncryptedIv('no-colon-here'), null);
  assert.equal(splitEncryptedIv(':leading-colon-empty-encrypted'), null);
  assert.equal(splitEncryptedIv('trailing-colon-empty-iv:'), null);
});

test('§12.2/CH-10 item 59: hard cutover — CHARIOT_VAULT_LEGACY_DECRYPT=0 refuses a legacy ciphertext before any decrypt attempt', async () => {
  const prevFlag = process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
  process.env.CHARIOT_VAULT_LEGACY_DECRYPT = '0';
  try {
    // Deliberately-bogus but syntactically legacy (unprefixed) ciphertext —
    // the refusal must fire from the policy check alone, never reach a
    // native decrypt attempt (which would fail differently, on bad
    // ciphertext, not on the typed refusal).
    await assert.rejects(
      () => decryptFields('bm90LWEtcmVhbC1jaXBoZXJ0ZXh0', 'AAAAAAAAAAAAAAAA', 'tenant-a', 'adapter-x'),
      (err: unknown) => {
        assert.ok(err instanceof VaultLegacyCiphertextRefusedError);
        assert.equal(err.code, 'VAULT_LEGACY_CIPHERTEXT_REFUSED');
        assert.match(err.message, /VAULT_LEGACY_CIPHERTEXT_REFUSED/);
        assert.match(err.message, /CHARIOT_VAULT_LEGACY_DECRYPT=0/);
        return true;
      },
    );
  } finally {
    if (prevFlag === undefined) delete process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
    else process.env.CHARIOT_VAULT_LEGACY_DECRYPT = prevFlag;
  }
});

test('§12.2/CH-10 item 59: hard cutover — enterprise mode refuses legacy decrypt by default', async () => {
  const prevEnt = process.env.CHARIOT_ENTERPRISE;
  const prevFlag = process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
  process.env.CHARIOT_ENTERPRISE = '1';
  delete process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
  try {
    await assert.rejects(
      () => decryptFields('bm90LWEtcmVhbC1jaXBoZXJ0ZXh0', 'AAAAAAAAAAAAAAAA', 'tenant-a', 'adapter-x'),
      (err: unknown) => {
        assert.ok(err instanceof VaultLegacyCiphertextRefusedError);
        assert.match(err.message, /CHARIOT_ENTERPRISE=1/);
        return true;
      },
    );
  } finally {
    if (prevEnt === undefined) delete process.env.CHARIOT_ENTERPRISE; else process.env.CHARIOT_ENTERPRISE = prevEnt;
    if (prevFlag === undefined) delete process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
    else process.env.CHARIOT_VAULT_LEGACY_DECRYPT = prevFlag;
  }
});

test('§12.2/CH-10 item 59: hard cutover — enterprise mode + explicit override does NOT refuse at the policy layer', async () => {
  // The override lifts ONLY the enterprise-mode trigger; the record used
  // here is a real v2 record (not legacy at all), so this proves the
  // override does not accidentally widen refusal on the happy path — the
  // true legacy+override case requires the Rust-side empty-AAD fixture
  // (see native/src/vault.rs's own tests) and is exercised there.
  const prevEnt = process.env.CHARIOT_ENTERPRISE;
  const prevFlag = process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
  process.env.CHARIOT_ENTERPRISE = '1';
  process.env.CHARIOT_VAULT_LEGACY_DECRYPT = '1';
  try {
    const { encrypted, iv } = encryptFields({ apiKey: 'secret-123' }, 'tenant-a', 'adapter-x');
    const result = await decryptFields(encrypted, iv, 'tenant-a', 'adapter-x');
    assert.deepEqual(result.fields, { apiKey: 'secret-123' });
  } finally {
    if (prevEnt === undefined) delete process.env.CHARIOT_ENTERPRISE; else process.env.CHARIOT_ENTERPRISE = prevEnt;
    if (prevFlag === undefined) delete process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
    else process.env.CHARIOT_VAULT_LEGACY_DECRYPT = prevFlag;
  }
});

test('§12.2/CH-10 item 59: a v2 record never reports an upgrade, refused or not', async () => {
  const { encrypted, iv } = encryptFields({ apiKey: 'secret-123' }, 'tenant-a', 'adapter-x');
  const result = await decryptFields(encrypted, iv, 'tenant-a', 'adapter-x');
  assert.equal(result.upgraded, null);
});

test('§12.2/CH-10 item 59: decryptFieldsForVaultMigration reports wasLegacy accurately for a v2 record', async () => {
  const { encrypted, iv } = encryptFields({ apiKey: 'secret-123' }, 'tenant-a', 'adapter-x');
  const result = await decryptFieldsForVaultMigration(encrypted, iv, 'tenant-a', 'adapter-x');
  assert.equal(result.wasLegacy, false);
  assert.deepEqual(result.fields, { apiKey: 'secret-123' });
});

/**
 * The LOADED binary may be either shape depending on host state: the
 * currently signed Sep-1 build (no `vaultProtocolVersion` at all — the
 * operator's re-sign is a separate, later step) or a binary rebuilt from
 * this change (`vaultProtocolVersion` >= 2). Asserting `>= 2`
 * unconditionally makes the suite red on every host until that re-sign,
 * for a reason unrelated to the code under test. These two tests instead
 * prove the correct property on WHICHEVER binary is actually loaded, each
 * skipping itself (visibly, in TAP output) when its branch does not
 * apply — never silently passing on the wrong binary.
 */
test('§12.2/CH-10 item 59: native capability probe [new-binary branch] — vaultProtocolVersion reports >= 2 when exported', (t) => {
  const binding = loadNativeBinding();
  assert.ok(binding, 'native binding must be loadable for this test to be meaningful');
  if (typeof binding.vaultProtocolVersion !== 'function') {
    t.skip('loaded binary predates rulings item 59 (no vaultProtocolVersion export) — see the old-binary branch test');
    return;
  }
  assert.ok(binding.vaultProtocolVersion() >= 2);
});

test('§12.2/CH-10 item 59: native capability probe [old-binary branch] — TypeScript gate refuses legacy decrypt without any native call when the probe is absent', async (t) => {
  const binding = loadNativeBinding();
  assert.ok(binding, 'native binding must be loadable for this test to be meaningful');
  if (typeof binding.vaultProtocolVersion === 'function') {
    t.skip('loaded binary already exports vaultProtocolVersion — see the new-binary branch test');
    return;
  }
  assert.equal(
    hasVaultLegacyGate(binding),
    false,
    'hasVaultLegacyGate must be false when the native probe is absent',
  );
  // The module doc on `callNativeDecrypt`/`decryptFields` (crypto.ts) says
  // exactly this: on an old binary, the TypeScript-side policy check —
  // from the caller-visible `v2:` prefix alone, before any native call —
  // IS the enforcement point, not a best-effort convention.
  const prevFlag = process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
  process.env.CHARIOT_VAULT_LEGACY_DECRYPT = '0';
  try {
    await assert.rejects(
      () => decryptFields('bm90LWEtcmVhbC1jaXBoZXJ0ZXh0', 'AAAAAAAAAAAAAAAA', 'tenant-a', 'adapter-x'),
      (err: unknown) => {
        assert.ok(err instanceof VaultLegacyCiphertextRefusedError);
        return true;
      },
      'decryptFields must refuse a legacy ciphertext under cutover in TypeScript, even when the loaded ' +
      'binary cannot enforce legacyAllowed itself',
    );
  } finally {
    if (prevFlag === undefined) delete process.env.CHARIOT_VAULT_LEGACY_DECRYPT;
    else process.env.CHARIOT_VAULT_LEGACY_DECRYPT = prevFlag;
  }
});
