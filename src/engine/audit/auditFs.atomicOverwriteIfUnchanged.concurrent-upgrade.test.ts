/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10), rulings item 59. Gate finding
 * F2/F3 follow-up: "tests per site: CAS no-op on a concurrent upgrade,
 * failure surfaces, success persists exactly {encrypted, iv}."
 *
 * CAS predicate under test (src/engine/audit/auditFs.ts,
 * `atomicOverwriteIfUnchanged`): the on-disk bytes are re-read and
 * compared, byte-for-byte, to `expectedCurrentBytes` immediately before
 * replacing them — `if (!onDisk.equals(expectedBuf)) return { written:
 * false, path: finalPath };`. `chainSigner.ts`'s `createSealedStoreSigner`
 * passes the exact serialization it read the artifact from as
 * `expectedCurrentBytes` (see that module's own CAS comment).
 *
 * Documented outcome per the ruling ("a genuine write failure ... fails
 * this call ... a benign CAS mismatch ... is a no-op, not a failure"):
 * writer B here does NOT get an exception — `atomicOverwriteIfUnchanged`
 * returns `{ written: false }` on a mismatch, exactly like a concurrent-
 * upgrade no-op elsewhere in this ruling (Mongo `matchedCount === 0`,
 * Redis `EVAL` returning 0). `chainSigner.ts`'s caller treats `written
 * === false` the same way — logged, not thrown — because losing a CAS
 * race is not a failure of THIS write; only an actual I/O error (e.g. a
 * failed rename) throws.
 *
 * Run (after `npm run build:native` and `tsc`): node --test dist/engine/audit/auditFs.atomicOverwriteIfUnchanged.concurrent-upgrade.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { atomicOverwriteIfUnchanged, atomicWriteNew } = await import('./auditFs.js');

test('§12.2/CH-10 item 59: atomicOverwriteIfUnchanged — concurrent upgrade race: writer A persists, writer B is a CAS no-op (never a clobber)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ch10-atomic-cas-'));
  const filename = 'signing-key.test.sealed.json';
  const originalBytes = JSON.stringify({ schemaVersion: 1, encrypted: 'legacy-ciphertext', iv: 'legacy-iv' }, null, 2) + '\n';
  atomicWriteNew(dir, filename, originalBytes);

  // Two independent "readers" of the SAME legacy artifact, each computing
  // their own real upgraded content (distinct — genuinely different
  // ciphertexts, as two concurrent upgraders racing on the same legacy
  // artifact would produce).
  const upgradedByA = JSON.stringify({ schemaVersion: 1, encrypted: 'v2:upgraded-by-writer-a', iv: 'iv-a' }, null, 2) + '\n';
  const upgradedByB = JSON.stringify({ schemaVersion: 1, encrypted: 'v2:upgraded-by-writer-b', iv: 'iv-b' }, null, 2) + '\n';

  // Writer A: CAS against the ORIGINAL legacy bytes it read — succeeds.
  const resultA = atomicOverwriteIfUnchanged(dir, filename, originalBytes, upgradedByA);
  assert.equal(resultA.written, true, 'writer A must win the race — the file still held the legacy bytes it read');
  assert.equal(readFileSync(join(dir, filename), 'utf-8'), upgradedByA);

  // Writer B: still holding the SAME stale originalBytes it read before A
  // won — CAS must be a no-op, never a clobber of A's write, and must NOT
  // throw (a benign mismatch, not a failure).
  const resultB = atomicOverwriteIfUnchanged(dir, filename, originalBytes, upgradedByB);
  assert.equal(resultB.written, false, 'writer B\'s CAS must report written:false — a no-op, not an error');
  assert.equal(
    readFileSync(join(dir, filename), 'utf-8'),
    upgradedByA,
    'the file on disk must STILL hold exactly writer A\'s bytes — never clobbered by B',
  );
});

test('§12.2/CH-10 item 59: atomicOverwriteIfUnchanged — a genuine write failure (rename target unwritable) throws, not swallowed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ch10-atomic-cas-fail-'));
  const filename = 'signing-key.test2.sealed.json';
  const originalBytes = JSON.stringify({ encrypted: 'legacy', iv: 'legacy-iv' }) + '\n';
  atomicWriteNew(dir, filename, originalBytes);

  // Make the directory read-only so the rename() inside atomicOverwrite
  // fails with EACCES — a genuine I/O error, distinct from a CAS
  // mismatch, and MUST propagate (throw), not be swallowed as a no-op.
  chmodSync(dir, 0o500);
  try {
    assert.throws(() => atomicOverwriteIfUnchanged(dir, filename, originalBytes, 'new-content'));
  } finally {
    chmodSync(dir, 0o700); // restore so the OS can clean up the temp dir
  }
});
