/**
 * CHARIOT::§5.7 — `unsealSealedShardIntoDevDir` staging/promotion mechanics.
 *
 * Adversarial review findings F1 (High, plaintext staging file not cleaned
 * up on a failing/partial write or a failing/partial unpack) and F2 (High,
 * TOCTOU — predictable shared-tmpdir path, no exclusive create) on CHARIOT
 * §5.7, 2026-09-04. These tests drive `unsealSealedShardIntoDevDir`
 * directly (not through `loadShard()`, which is covered by
 * `ChariotState.sealed-shard.test.ts`) with fake `native` bindings and an
 * injected `mkStagingDir` factory, so every failure class can be forced
 * deterministically without a real native binary.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  symlinkSync,
  existsSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  chmodSync,
  lstatSync,
  utimesSync,
} from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import type { NativeEdgeBinding, NativeEdgeShard } from '../retrieval/nativeEdge.js';
import type { SealedShardConfig } from '../retrieval/sealedShardConfig.js';

const {
  unsealSealedShardIntoDevDir,
  SealedShardUnrecoverableError,
  __testOnlyAddStaleRegistryEntry,
  __testOnlyReadStaleRegistry,
  __testOnlyAcquireRegistryLock,
  __testOnlyRegistryLockPath,
} = await import('./ChariotState.js');

async function captureStderr(fn: () => void | Promise<void>): Promise<string> {
  let out = '';
  const original = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (chunk: unknown) => boolean }).write = (chunk: unknown) => {
    out += String(chunk);
    return true;
  };
  try {
    await fn();
  } finally {
    process.stderr.write = original;
  }
  return out;
}

// ── gate round 3/4 (2026-09-04): stale-backup registry test helpers ───────
// Mirrors `ChariotState.ts`'s own `metaDirFor`/`staleRegistryPath`/registry
// file shape — duplicated here deliberately (the production functions
// mostly are not exported; only the observable file format and the two
// `__testOnly*` exports are the stable contract these tests rely on).

interface RegistryEntry {
  path: string;
  createdAt: string;
  pid: number;
}

const META_DIRNAME = '.chariot-sealed-meta';
const REGISTRY_FILENAME = '.chariot-sealed-stale-registry.json';

function metaDirFor(devDir: string): string {
  return join(dirname(devDir), META_DIRNAME);
}

function registryPathFor(devDir: string): string {
  return join(metaDirFor(devDir), REGISTRY_FILENAME);
}

/** Write a registry file directly to disk with CORRECT provenance (gate
 * round 4 F3: owned by us, mode 0600, inside a 0700 meta dir) — bypasses
 * the interprocess lock (single-threaded test setup, not a concurrency
 * concern) but must still pass `readStaleRegistry`'s provenance check or
 * every test using it would spuriously hit `SealedShardUnrecoverableError`. */
function writeRegistry(devDir: string, entries: Array<Partial<RegistryEntry> & { path: string }>): void {
  const meta = metaDirFor(devDir);
  mkdirSync(meta, { recursive: true, mode: 0o700 });
  chmodSync(meta, 0o700);
  const full: RegistryEntry[] = entries.map((e) => ({
    path: e.path,
    createdAt: e.createdAt ?? new Date().toISOString(),
    pid: e.pid ?? process.pid,
  }));
  const registryPath = registryPathFor(devDir);
  writeFileSync(registryPath, JSON.stringify(full, null, 2), { mode: 0o600 });
  chmodSync(registryPath, 0o600); // belt-and-suspenders against umask
}

function readRegistry(devDir: string): RegistryEntry[] {
  try {
    return JSON.parse(readFileSync(registryPathFor(devDir), 'utf8')) as RegistryEntry[];
  } catch {
    return [];
  }
}

/**
 * Working JS fake for `native.removeStaleDirValidated` (gate round 4 F2),
 * used as `baseNative()`'s default so every EXISTING cleanup-touching test
 * continues to exercise the TS-side registry/validation/logging logic
 * meaningfully (the Rust implementation's OWN correctness — fd-relative
 * TOCTOU-safety, quarantine rename, etc. — is covered separately by
 * `native/src/edge_cleanup.rs`'s own Rust tests, not reachable from here
 * without a compiled native binary). Mirrors the documented contract
 * exactly: `Ok(false)`/`false` only for ENOENT; `REMOVE_VALIDATION_FAILED:`
 * for a pre-removal validation failure; `REMOVE_IO_FAILED:` for a failure
 * AFTER validation passed.
 */
function fakeRemoveStaleDirValidated(parent: string, name: string, expectedUid: number): boolean {
  if (expectedUid === 0) {
    throw new Error('REMOVE_VALIDATION_FAILED: refusing expected_uid=0 (root)');
  }
  const fullPath = join(parent, name);
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(fullPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw new Error(`REMOVE_VALIDATION_FAILED: lstat failed on ${fullPath}: ${String(err)}`);
  }
  if (!st.isDirectory()) {
    throw new Error(`REMOVE_VALIDATION_FAILED: ${fullPath} is not a real directory (it may be a symlink)`);
  }
  if (typeof process.getuid === 'function' && st.uid !== expectedUid) {
    throw new Error(`REMOVE_VALIDATION_FAILED: ${fullPath} is owned by uid ${st.uid} not ${expectedUid}`);
  }
  try {
    rmSync(fullPath, { recursive: true, force: true });
  } catch (err) {
    throw new Error(`REMOVE_IO_FAILED: failed to remove ${fullPath}: ${String(err)}`);
  }
  return true;
}

const sandbox = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-'));

function makeCfg(): SealedShardConfig {
  return {
    descriptor: { ciphertextB64: 'ct', ivB64: 'iv', signatureB64: 'sig', salt: 's', aad: 's|epoch=1' },
    publicKeyPem: 'pem',
    secretRootB64: 'root',
    licenseJwt: 'header.payload.signature',
  };
}

const okShard = { pointsCount: () => 1 } as unknown as NativeEdgeShard;

/** A fake `native.edgeUnpackSnapshot` that writes N files into the target
 * directory before optionally throwing — simulates a real (partial) unpack. */
function unpackThatWritesThenMaybeThrows(shouldThrow: boolean) {
  return (_snapshotPath: string, targetPath: string, _receipt: string) => {
    mkdirSync(targetPath, { recursive: true });
    writeFileSync(join(targetPath, 'segment-0.dat'), 'partial-shard-bytes');
    if (shouldThrow) {
      throw new Error('simulated qdrant-edge unpack failure');
    }
  };
}

function baseNative(overrides: Partial<NativeEdgeBinding> = {}): NativeEdgeBinding {
  return {
    EdgeShardHandle: {
      create: () => {
        throw new Error('must not be called');
      },
      load: () => okShard,
    },
    unsealAndVerifySnapshot: () => ({ plaintextB64: Buffer.from('plaintext-bytes').toString('base64'), receipt: 'r' }),
    edgeUnpackSnapshot: unpackThatWritesThenMaybeThrows(false),
    removeStaleDirValidated: fakeRemoveStaleDirValidated,
    ...overrides,
  } as unknown as NativeEdgeBinding;
}

test('happy path: staging directory is fully removed after a successful promotion', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'happy-devdir-')), 'happy-devdir');
  let capturedStagingDir = '';
  const mkStagingDir = () => {
    capturedStagingDir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-happy-'));
    return capturedStagingDir;
  };

  const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  assert.equal(result, okShard, 'successful promotion must return the loaded shard');
  assert.ok(existsSync(devDir), 'devDir must exist after promotion');
  assert.ok(
    existsSync(join(devDir, 'segment-0.dat')),
    'the unpacked content must have been promoted into devDir',
  );
  assert.equal(existsSync(capturedStagingDir), false, 'the staging directory must be fully removed after success');
  // No orphaned .stale-<uuid> siblings.
  const siblings = readdirSync(dirname(devDir)).filter((f) => f.startsWith('happy-devdir.stale-'));
  assert.deepEqual(siblings, [], 'no .stale-* backup directory may be left behind');
});

test('happy path: promotion REPLACES an existing devDir, not merges into it', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'replace-devdir-')), 'replace-devdir');
  mkdirSync(devDir, { recursive: true });
  writeFileSync(join(devDir, 'old-stale-segment.dat'), 'old shard bytes that must not survive');

  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-replace-'));
  const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  assert.equal(result, okShard);
  assert.ok(existsSync(join(devDir, 'segment-0.dat')), 'new content must be present');
  assert.equal(
    existsSync(join(devDir, 'old-stale-segment.dat')),
    false,
    'the OLD devDir content must not survive a successful promotion',
  );
});

test('F1: edgeUnpackSnapshot throws after writing partial files — staging tree fully removed, devDir untouched', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f1-unpack-failure-devdir-')), 'f1-unpack-failure-devdir');
  mkdirSync(devDir, { recursive: true });
  writeFileSync(join(devDir, 'existing-valid-segment.dat'), 'previously valid shard content');

  let capturedStagingDir = '';
  const mkStagingDir = () => {
    capturedStagingDir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f1-'));
    return capturedStagingDir;
  };
  const native = baseNative({ edgeUnpackSnapshot: unpackThatWritesThenMaybeThrows(true) });

  const result = unsealSealedShardIntoDevDir(native, makeCfg(), devDir, { mkStagingDir });
  assert.equal(result, null, 'a failing unpack must return null, never throw out of this function');
  assert.equal(
    existsSync(capturedStagingDir),
    false,
    'F1: the staging directory (including the partially-unpacked files edgeUnpackSnapshot wrote before ' +
      'throwing) must be fully removed — nothing partial may be left on disk',
  );
  assert.ok(
    existsSync(join(devDir, 'existing-valid-segment.dat')),
    'F1: a failing unpack must NEVER touch the existing devDir — the prior valid shard must survive intact',
  );
});

test('F1: unsealAndVerifySnapshot itself throws — no staging directory is ever created', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f1-unseal-failure-devdir-')), 'f1-unseal-failure-devdir');
  let stagingFactoryCalls = 0;
  const mkStagingDir = () => {
    stagingFactoryCalls += 1;
    return mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-should-not-happen-'));
  };
  const native = baseNative({
    unsealAndVerifySnapshot: () => {
      throw new Error('license JWT signature verification failed (fixture)');
    },
  });

  const result = unsealSealedShardIntoDevDir(native, makeCfg(), devDir, { mkStagingDir });
  assert.equal(result, null);
  assert.equal(stagingFactoryCalls, 0, 'no staging directory should be created if unseal itself fails first');
  assert.equal(existsSync(devDir), false, 'devDir must not have been created');
});

test('F2 (TOCTOU): a pre-existing regular file at the staging archive path is refused (O_EXCL)', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f2-preexisting-file-devdir-')), 'f2-preexisting-file-devdir');
  const mkStagingDir = () => {
    const dir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f2-file-'));
    // Pre-seed a regular file at the exact path unsealSealedShardIntoDevDir
    // will try to O_CREAT|O_EXCL.
    writeFileSync(join(dir, 'plaintext.archive'), 'attacker-or-stale-content');
    return dir;
  };
  const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  assert.equal(result, null, 'a pre-existing file at the staging archive path must be refused, not overwritten');
  assert.equal(existsSync(devDir), false, 'devDir must not be created on this failure');
});

test('F2 (TOCTOU): a pre-existing SYMLINK at the staging archive path is refused, never followed', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f2-symlink-devdir-')), 'f2-symlink-devdir');
  const evilTarget = join(sandbox, 'f2-symlink-target.txt');
  writeFileSync(evilTarget, 'attacker-controlled target file');

  const mkStagingDir = () => {
    const dir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f2-symlink-'));
    symlinkSync(evilTarget, join(dir, 'plaintext.archive'));
    return dir;
  };
  const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  assert.equal(result, null, 'a pre-existing symlink at the staging archive path must be refused');
  assert.equal(existsSync(devDir), false, 'devDir must not be created on this failure');
  // The symlink target itself must be untouched — proves we never followed
  // and wrote through it.
  assert.equal(
    readFileSync(evilTarget, 'utf8'),
    'attacker-controlled target file',
    'the symlink target must never be written to',
  );
});

test('F1 + F2 combined: staging directory is removed even when the symlink refusal fires', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f1-f2-cleanup-devdir-')), 'f1-f2-cleanup-devdir');
  let capturedStagingDir = '';
  const mkStagingDir = () => {
    capturedStagingDir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-cleanup-'));
    symlinkSync('/nonexistent-target', join(capturedStagingDir, 'plaintext.archive'));
    return capturedStagingDir;
  };
  unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  assert.equal(
    existsSync(capturedStagingDir),
    false,
    'the staging directory itself (holding the refused symlink) must still be cleaned up',
  );
});

// ── gate round 2 (2026-09-04): cross-filesystem promotion safety ──────────

test('gate round 2: preflight device mismatch aborts BEFORE touching devDir', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'preflight-mismatch-devdir-')), 'preflight-mismatch-devdir');
  let capturedStagingDir = '';
  const mkStagingDir = () => {
    capturedStagingDir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-preflight-'));
    return capturedStagingDir;
  };
  // Force a mismatch regardless of the sandbox's real mount layout.
  const statDev = (path: string) => (path === capturedStagingDir ? 111 : 222);

  const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir, statDev });
  assert.equal(result, null, 'a cross-filesystem staging directory must be refused');
  assert.equal(existsSync(devDir), false, 'devDir must not be created when the preflight aborts');
  assert.equal(
    existsSync(capturedStagingDir),
    false,
    'the (unusable) staging directory must still be cleaned up even though the preflight aborted',
  );
});

test('gate round 2: EXDEV on the second promotion rename restores the original devDir intact', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'exdev-devdir-')), 'exdev-devdir');
  mkdirSync(devDir, { recursive: true });
  writeFileSync(join(devDir, 'original-segment.dat'), 'original valid shard content');

  let capturedStagingDir = '';
  const mkStagingDir = () => {
    capturedStagingDir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-exdev-'));
    return capturedStagingDir;
  };

  // Call 1: devDir -> stale backup (must succeed, real rename).
  // Call 2: staged unpack -> devDir — simulates EXDEV (staging on a
  //         different filesystem than devDir's parent).
  // Call 3: stale backup -> devDir — the RESTORE, must succeed (real rename).
  let renameCallCount = 0;
  const renameSyncFake = (oldPath: string, newPath: string) => {
    renameCallCount += 1;
    if (renameCallCount === 2) {
      const err = new Error('EXDEV: cross-device link not permitted') as NodeJS.ErrnoException;
      err.code = 'EXDEV';
      throw err;
    }
    renameSync(oldPath, newPath);
  };

  const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, {
    mkStagingDir,
    renameSync: renameSyncFake,
  });

  assert.equal(result, null, 'a RECOVERED EXDEV promotion failure returns null, not the loaded shard');
  assert.equal(
    renameCallCount,
    3,
    'exactly 3 renames must occur: devDir->stale, unpack->devDir (EXDEV), stale->devDir (restore)',
  );
  assert.ok(existsSync(devDir), 'devDir must exist after the restore');
  assert.ok(
    existsSync(join(devDir, 'original-segment.dat')),
    'the ORIGINAL shard content must be restored intact — not left missing, not the half-promoted new content',
  );
  assert.equal(
    existsSync(join(devDir, 'segment-0.dat')),
    false,
    'the NEW (never successfully promoted) content must not be present after a restored EXDEV failure',
  );
  const siblings = readdirSync(dirname(devDir)).filter((f) => f.startsWith('exdev-devdir.stale-'));
  assert.deepEqual(siblings, [], 'no orphaned .stale-* backup directory may remain after a successful restore');
  assert.equal(existsSync(capturedStagingDir), false, 'the staging directory must still be cleaned up');
});

test('gate round 2: promotion AND restore both fail → SealedShardUnrecoverableError is thrown, never a silent null', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'unrecoverable-devdir-')), 'unrecoverable-devdir');
  mkdirSync(devDir, { recursive: true });
  writeFileSync(join(devDir, 'original-segment.dat'), 'original valid shard content');

  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-unrecoverable-'));

  let renameCallCount = 0;
  const renameSyncFake = (oldPath: string, newPath: string) => {
    renameCallCount += 1;
    if (renameCallCount === 1) {
      renameSync(oldPath, newPath); // devDir -> stale: succeeds
      return;
    }
    // BOTH the promotion rename (#2) and the restore rename (#3) fail —
    // simulates a persistently broken filesystem, not a one-shot EXDEV.
    const err = new Error('simulated persistent rename failure') as NodeJS.ErrnoException;
    err.code = 'EXDEV';
    throw err;
  };

  let thrown: unknown;
  try {
    unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir, renameSync: renameSyncFake });
  } catch (err) {
    thrown = err;
  }

  assert.ok(thrown, 'an unrecoverable promotion+restore failure must throw — it must not return normally');
  assert.ok(
    thrown instanceof SealedShardUnrecoverableError,
    `must throw SealedShardUnrecoverableError specifically, not a generic Error; got: ${String(thrown)}`,
  );
  const message = (thrown as Error).message;
  assert.ok(message.includes(devDir), `error message must name devDir (${devDir}); got: ${message}`);
  assert.ok(message.includes('stale'), `error message must name the stale backup path; got: ${message}`);
});

test('gate round 2: stale-dir cleanup failure is logged (not swallowed) and retried on the next successful load', async () => {
  const devDir = join(mkdtempSync(join(sandbox, 'stale-cleanup-devdir-')), 'stale-cleanup-devdir');
  mkdirSync(devDir, { recursive: true });
  writeFileSync(join(devDir, 'v1.dat'), 'v1 content');
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-stalecleanup-'));

  // Manually seed an orphaned `.stale-*` directory matching the exact
  // naming convention (gate round 3: cleanup is registry-driven, so it must
  // ALSO be registered — a bare directory that merely looks right is no
  // longer sufficient, see the "unregistered sibling" test below), and make
  // it UNREMOVABLE (revoke write permission on the directory itself — Linux
  // requires write on the PARENT to unlink an entry, so rmSync cannot
  // delete anything inside it even with force:true). This deterministically
  // forces a cleanup failure without needing an injection seam for rmSync.
  const orphan = `${devDir}.stale-00000000-0000-0000-0000-000000000000`;
  mkdirSync(orphan, { recursive: true });
  writeFileSync(join(orphan, 'orphaned-plaintext.dat'), 'leftover from a previous failed cleanup');
  writeRegistry(devDir, [{ path: orphan }]);
  chmodSync(orphan, 0o500); // r-x------: cannot add/remove entries inside it

  let result1: unknown;
  const stderr1 = await captureStderr(() => {
    result1 = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  });

  assert.equal(result1, okShard, 'a successful promotion must still succeed even when orphan cleanup fails');
  assert.ok(existsSync(orphan), 'the unremovable orphan must still exist — cleanup genuinely failed');
  assert.ok(
    stderr1.includes('sealed_shard_stale_cleanup_failed'),
    `cleanup failure must be logged (not silently swallowed); stderr was: ${stderr1}`,
  );
  assert.ok(stderr1.includes(orphan), `the log line must name the exact orphaned path; stderr was: ${stderr1}`);
  assert.ok(
    readRegistry(devDir).some((e) => e.path === orphan),
    'a failed cleanup must KEEP the entry registered so it is retried, not silently dropped',
  );

  // Make it removable again (simulates the transient condition clearing —
  // e.g. a momentarily busy mount) and run another successful promotion:
  // the retry must now succeed and the orphan must be gone.
  chmodSync(orphan, 0o700);
  const result2 = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  assert.equal(result2, okShard);
  assert.equal(
    existsSync(orphan),
    false,
    'RETRY: once the blocker clears, the next successful load must remove the previously-orphaned backup',
  );
  assert.ok(
    !readRegistry(devDir).some((e) => e.path === orphan),
    'once actually removed, the entry must be dropped from the registry',
  );
});

// ── gate round 3 (2026-09-04): registry-only cleanup, never a directory scan ──

test('gate round 3: an UNREGISTERED sibling matching the stale-dir name pattern is never touched', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'unregistered-sibling-devdir-')), 'unregistered-sibling-devdir');
  mkdirSync(devDir, { recursive: true });
  writeFileSync(join(devDir, 'v1.dat'), 'v1 content');

  // A directory that LOOKS like one of ours (right prefix, right UUID
  // shape) but was never recorded in the registry — e.g. belongs to
  // another local user/process, or predates this installation adopting
  // the registry mechanism. A directory-SCAN approach would delete this;
  // the registry-only approach must not even consider it.
  const unrelated = `${devDir}.stale-ffffffff-ffff-4fff-8fff-ffffffffffff`;
  mkdirSync(unrelated, { recursive: true });
  writeFileSync(join(unrelated, 'unrelated-data.dat'), 'belongs to someone else');

  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-unregistered-'));
  const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  assert.equal(result, okShard);

  assert.ok(existsSync(unrelated), 'an unregistered look-alike sibling must NEVER be deleted');
  assert.equal(
    readFileSync(join(unrelated, 'unrelated-data.dat'), 'utf8'),
    'belongs to someone else',
    'its content must be completely untouched',
  );
});

test('gate round 3: a registered entry replaced by a symlink is refused, not followed, and logged', async () => {
  const devDir = join(mkdtempSync(join(sandbox, 'registry-symlink-devdir-')), 'registry-symlink-devdir');
  mkdirSync(devDir, { recursive: true });
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-regsymlink-'));

  const evilTarget = join(sandbox, 'registry-symlink-target');
  mkdirSync(evilTarget, { recursive: true });
  writeFileSync(join(evilTarget, 'do-not-delete.dat'), 'attacker-controlled directory');

  const fakeStaleName = `${devDir}.stale-11111111-1111-4111-8111-111111111111`;
  symlinkSync(evilTarget, fakeStaleName);
  writeRegistry(devDir, [{ path: fakeStaleName }]);

  const stderr = await captureStderr(() => {
    const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
    assert.equal(result, okShard, 'promotion itself must still succeed');
  });

  assert.ok(
    stderr.includes('sealed_shard_stale_registry_mismatch'),
    `a registered path that is a symlink must be logged as a mismatch; stderr was: ${stderr}`,
  );
  assert.ok(stderr.includes(fakeStaleName), `the log must name the exact path; stderr was: ${stderr}`);
  assert.ok(existsSync(fakeStaleName), 'the symlink itself must not be deleted');
  assert.ok(existsSync(evilTarget), 'the symlink TARGET must survive — it must never be followed');
  assert.ok(
    existsSync(join(evilTarget, 'do-not-delete.dat')),
    'content inside the symlink target must be completely untouched',
  );
  assert.ok(
    !readRegistry(devDir).some((e) => e.path === fakeStaleName),
    'the mismatched entry must be dropped from the registry (never retried as a real backup)',
  );
});

test('gate round 3: a registered entry whose directory was removed out-of-band is dropped cleanly (no error log)', async () => {
  const devDir = join(mkdtempSync(join(sandbox, 'registry-missing-devdir-')), 'registry-missing-devdir');
  mkdirSync(devDir, { recursive: true });
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-regmissing-'));

  const ghostPath = `${devDir}.stale-22222222-2222-4222-8222-222222222222`;
  // Deliberately do NOT create ghostPath on disk — the registry references
  // a path that (for whatever out-of-band reason, e.g. manual operator
  // cleanup) no longer exists.
  writeRegistry(devDir, [{ path: ghostPath }]);

  const stderr = await captureStderr(() => {
    const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
    assert.equal(result, okShard);
  });

  assert.ok(
    !stderr.includes('sealed_shard_stale_registry_mismatch'),
    `a missing (already-gone) registered path must NOT be logged as a mismatch — it is a normal ` +
      `outcome, not a validation failure; stderr was: ${stderr}`,
  );
  assert.ok(
    !readRegistry(devDir).some((e) => e.path === ghostPath),
    'the entry for the already-gone directory must be dropped from the registry',
  );
});

test("gate round 3: a registry entry naming a path OUTSIDE devDir's parent is refused, logged, and dropped", async () => {
  const devDir = join(mkdtempSync(join(sandbox, 'registry-outside-devdir-')), 'registry-outside-devdir');
  mkdirSync(devDir, { recursive: true });
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-regoutside-'));

  const outsideDir = mkdtempSync(join(tmpdir(), 'chariot-outside-target-'));
  writeFileSync(join(outsideDir, 'sensitive.dat'), 'must never be touched by devDir cleanup');
  writeRegistry(devDir, [{ path: outsideDir }]);

  const stderr = await captureStderr(() => {
    const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
    assert.equal(result, okShard);
  });

  assert.ok(
    stderr.includes('sealed_shard_stale_registry_mismatch'),
    `an out-of-parent registered path must be logged as a mismatch; stderr was: ${stderr}`,
  );
  assert.ok(existsSync(outsideDir), "a path outside devDir's parent must NEVER be deleted");
  assert.ok(existsSync(join(outsideDir, 'sensitive.dat')));
  assert.ok(
    !readRegistry(devDir).some((e) => e.path === outsideDir),
    'the out-of-scope entry must be dropped from the registry',
  );
});

test('gate round 3: a registered entry whose name does not match the strict UUID pattern is refused and logged', async () => {
  const devDir = join(mkdtempSync(join(sandbox, 'registry-badname-devdir-')), 'registry-badname-devdir');
  mkdirSync(devDir, { recursive: true });
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-regbadname-'));

  const badName = `${devDir}.stale-not-a-real-uuid`;
  mkdirSync(badName, { recursive: true });
  writeFileSync(join(badName, 'content.dat'), 'must survive');
  writeRegistry(devDir, [{ path: badName }]);

  const stderr = await captureStderr(() => {
    const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
    assert.equal(result, okShard);
  });

  assert.ok(
    stderr.includes('sealed_shard_stale_registry_mismatch'),
    `a malformed-suffix registered path must be logged as a mismatch; stderr was: ${stderr}`,
  );
  assert.ok(existsSync(badName), 'a name that fails the strict UUID pattern must never be deleted');
  assert.ok(
    !readRegistry(devDir).some((e) => e.path === badName),
    'the malformed entry must be dropped from the registry',
  );
});

// ── gate round 4 (2026-09-04): F1 lock, F2 descriptor-based removal seam,
//    F3 meta-dir/registry provenance, F4 root refusal ─────────────────────

function runNodeScript(script: string): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (d) => {
      stderr += String(d);
    });
    child.on('close', (code) => resolve({ code, stderr }));
  });
}

test('gate round 4 F1: two concurrently-spawned processes both land their registry addition (no lost update)', async () => {
  const devDir = join(mkdtempSync(join(sandbox, 'concurrent-registry-devdir-')), 'concurrent-registry-devdir');
  mkdirSync(devDir, { recursive: true });
  const uid = typeof process.getuid === 'function' ? process.getuid() : 1;
  const staleA = `${devDir}.stale-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa`;
  const staleB = `${devDir}.stale-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb`;
  const modulePath = new URL('./ChariotState.js', import.meta.url).href;

  const scriptFor = (staleDir: string) => `
(async () => {
  const mod = await import(${JSON.stringify(modulePath)});
  mod.__testOnlyAddStaleRegistryEntry(${JSON.stringify(devDir)}, ${JSON.stringify(staleDir)}, ${uid});
})().catch((e) => { console.error(e); process.exit(1); });
`;

  const [r1, r2] = await Promise.all([runNodeScript(scriptFor(staleA)), runNodeScript(scriptFor(staleB))]);
  assert.equal(r1.code, 0, `worker A must exit 0; stderr: ${r1.stderr}`);
  assert.equal(r2.code, 0, `worker B must exit 0; stderr: ${r2.stderr}`);

  const entries = __testOnlyReadStaleRegistry(devDir, uid) as RegistryEntry[];
  const paths = entries.map((e) => e.path);
  assert.ok(paths.includes(staleA), `worker A's entry must be present; registry: ${JSON.stringify(entries)}`);
  assert.ok(paths.includes(staleB), `worker B's entry must be present; registry: ${JSON.stringify(entries)}`);
});

test('gate round 4 F2: removeStaleDirValidated absent → entry stays registered, unavailability logged exactly once', async () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f2-unavailable-devdir-')), 'f2-unavailable-devdir');
  mkdirSync(devDir, { recursive: true });
  writeFileSync(join(devDir, 'v1.dat'), 'v1 content');
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f2unavail-'));

  // A native binding that does NOT expose removeStaleDirValidated — models
  // the runtime binary staying whatever was last signed before this native
  // export shipped.
  const nativeWithoutRemoval = baseNative();
  delete (nativeWithoutRemoval as { removeStaleDirValidated?: unknown }).removeStaleDirValidated;

  const stderr1 = await captureStderr(() => {
    const result = unsealSealedShardIntoDevDir(nativeWithoutRemoval, makeCfg(), devDir, { mkStagingDir });
    assert.equal(result, okShard, 'promotion must still succeed even though cleanup is unavailable');
  });
  assert.ok(
    stderr1.includes('sealed_shard_stale_cleanup_unavailable'),
    `first occurrence must be logged; stderr was: ${stderr1}`,
  );

  const uid = typeof process.getuid === 'function' ? process.getuid() : 1;
  const registryAfterRun1 = __testOnlyReadStaleRegistry(devDir, uid) as RegistryEntry[];
  assert.ok(
    registryAfterRun1.length > 0,
    'the stale backup created by this promotion must remain registered — never dropped just because cleanup is unavailable',
  );

  // Run again: the SAME unavailability must NOT be logged a second time.
  const stderr2 = await captureStderr(() => {
    const result = unsealSealedShardIntoDevDir(nativeWithoutRemoval, makeCfg(), devDir, { mkStagingDir });
    assert.equal(result, okShard);
  });
  assert.ok(
    !stderr2.includes('sealed_shard_stale_cleanup_unavailable'),
    `the unavailability log must fire exactly once per process, not on every retry; second stderr was: ${stderr2}`,
  );
});

test('gate round 4 F2: a REMOVE_VALIDATION_FAILED throw from native is treated as a registry mismatch (dropped, not retried)', async () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f2-validation-failed-devdir-')), 'f2-validation-failed-devdir');
  mkdirSync(devDir, { recursive: true });
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f2valfail-'));
  const nativeThatRejectsValidation = baseNative({
    removeStaleDirValidated: () => {
      throw new Error('REMOVE_VALIDATION_FAILED: simulated — not a real directory');
    },
  });

  const stderr = await captureStderr(() => {
    const result = unsealSealedShardIntoDevDir(nativeThatRejectsValidation, makeCfg(), devDir, { mkStagingDir });
    assert.equal(result, okShard);
  });
  assert.ok(
    stderr.includes('sealed_shard_stale_registry_mismatch'),
    `a REMOVE_VALIDATION_FAILED throw must be logged as a registry mismatch, not a cleanup failure; stderr: ${stderr}`,
  );
  const uid = typeof process.getuid === 'function' ? process.getuid() : 1;
  const remaining = __testOnlyReadStaleRegistry(devDir, uid) as RegistryEntry[];
  assert.equal(remaining.length, 0, 'a validation-failed entry must be DROPPED, not kept for retry');
});

test('gate round 4 F2: a REMOVE_IO_FAILED throw from native is treated as an ordinary cleanup failure (kept for retry)', async () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f2-io-failed-devdir-')), 'f2-io-failed-devdir');
  mkdirSync(devDir, { recursive: true });
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f2iofail-'));
  const nativeThatFailsIo = baseNative({
    removeStaleDirValidated: () => {
      throw new Error('REMOVE_IO_FAILED: simulated — disk full mid-removal');
    },
  });

  const stderr = await captureStderr(() => {
    const result = unsealSealedShardIntoDevDir(nativeThatFailsIo, makeCfg(), devDir, { mkStagingDir });
    assert.equal(result, okShard);
  });
  assert.ok(
    stderr.includes('sealed_shard_stale_cleanup_failed'),
    `a REMOVE_IO_FAILED throw must be logged as an ordinary cleanup failure; stderr: ${stderr}`,
  );
  const uid = typeof process.getuid === 'function' ? process.getuid() : 1;
  const remaining = __testOnlyReadStaleRegistry(devDir, uid) as RegistryEntry[];
  assert.ok(remaining.length > 0, 'an I/O-failed entry must be KEPT for retry, not dropped');
});

test('gate round 4 F3: an untrusted meta directory (wrong mode) fails the sealed load closed', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f3-meta-untrusted-devdir-')), 'f3-meta-untrusted-devdir');
  mkdirSync(devDir, { recursive: true });
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f3meta-'));

  const meta = metaDirFor(devDir);
  mkdirSync(meta, { recursive: true, mode: 0o755 }); // WRONG mode: world-readable, not 0700
  chmodSync(meta, 0o755);

  let thrown: unknown;
  try {
    unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  } catch (err) {
    thrown = err;
  }
  assert.ok(thrown instanceof SealedShardUnrecoverableError, `must throw SealedShardUnrecoverableError; got: ${String(thrown)}`);
  assert.ok(
    String((thrown as Error).message).includes(meta),
    `error must name the untrusted meta directory; got: ${(thrown as Error).message}`,
  );
});

test('gate round 4 F3: an untrusted registry file (wrong mode) fails the sealed load closed', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f3-registry-untrusted-devdir-')), 'f3-registry-untrusted-devdir');
  mkdirSync(devDir, { recursive: true });
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f3reg-'));

  const meta = metaDirFor(devDir);
  mkdirSync(meta, { recursive: true, mode: 0o700 });
  chmodSync(meta, 0o700);
  const registryPath = registryPathFor(devDir);
  writeFileSync(registryPath, '[]', { mode: 0o644 }); // WRONG mode: not 0600
  chmodSync(registryPath, 0o644);

  let thrown: unknown;
  try {
    unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir });
  } catch (err) {
    thrown = err;
  }
  assert.ok(thrown instanceof SealedShardUnrecoverableError, `must throw SealedShardUnrecoverableError; got: ${String(thrown)}`);
  assert.ok(
    String((thrown as Error).message).includes(registryPath),
    `error must name the untrusted registry file; got: ${(thrown as Error).message}`,
  );
});

test('gate round 4 F4: running as root (uid 0) refuses the entire sealed-shard path, not just cleanup', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f4-root-devdir-')), 'f4-root-devdir');
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f4root-'));
  const uidOverride = () => 0;

  const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir, uidOverride });
  assert.equal(result, null, 'running as uid 0 must refuse the whole sealed-shard path');
  assert.equal(existsSync(devDir), false, 'nothing may be created when refusing to run as root');
});

test('gate round 4 F4: an unavailable process.getuid() refuses the entire sealed-shard path', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'f4-nogetuid-devdir-')), 'f4-nogetuid-devdir');
  const mkStagingDir = () => mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-f4nouid-'));
  const uidOverride = () => undefined;

  const result = unsealSealedShardIntoDevDir(baseNative(), makeCfg(), devDir, { mkStagingDir, uidOverride });
  assert.equal(result, null, 'an unavailable getuid() must refuse the whole sealed-shard path');
  assert.equal(existsSync(devDir), false);
});

// ── gate round 5 (2026-09-04): crash-safe lock creation ────────────────────

function testUid(): number {
  return typeof process.getuid === 'function' ? process.getuid() : 1;
}

test('gate round 5: a pre-created EMPTY lock older than the stale threshold is taken over', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'r5-empty-old-lock-devdir-')), 'r5-empty-old-lock-devdir');
  mkdirSync(devDir, { recursive: true });
  const uid = testUid();
  const lockPath = __testOnlyRegistryLockPath(devDir, uid);

  // Pre-create an EMPTY lock file (models the exact crash window gate round
  // 5 closes: O_EXCL create succeeded, the owner-record write never
  // happened) and backdate its mtime well past the real 60s threshold.
  writeFileSync(lockPath, '', { mode: 0o600 });
  const old = new Date(Date.now() - 120_000);
  utimesSync(lockPath, old, old);

  const release = __testOnlyAcquireRegistryLock(devDir, uid);
  assert.equal(typeof release, 'function', 'acquisition must succeed after taking over the stale empty lock');
  release();

  const staleSiblings = readdirSync(dirname(lockPath)).filter((f) => f.includes('.registry.lock.stale-'));
  assert.deepEqual(staleSiblings, [], 'the renamed-aside takeover artifact must be cleaned up');
  assert.equal(existsSync(lockPath), false, 'the lock must be released (removed) after use');
});

test('gate round 5: a FRESH empty lock (< stale threshold) is NEVER taken over — mutual exclusion preserved', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'r5-empty-fresh-lock-devdir-')), 'r5-empty-fresh-lock-devdir');
  mkdirSync(devDir, { recursive: true });
  const uid = testUid();
  const lockPath = __testOnlyRegistryLockPath(devDir, uid);

  // A FRESH empty lock — current mtime, well under the real 60s threshold.
  writeFileSync(lockPath, '', { mode: 0o600 });

  let thrown: unknown;
  try {
    // Small bounded retry/interval so the test fails fast rather than
    // waiting out the real 100×50ms budget; staleMs is left at its
    // production default so this proves the REAL threshold blocks takeover.
    __testOnlyAcquireRegistryLock(devDir, uid, { retryCount: 3, retryMs: 5 });
  } catch (err) {
    thrown = err;
  }
  assert.ok(
    thrown,
    'acquisition must exhaust its retries and throw — a fresh empty lock must never be taken over',
  );
  assert.ok(existsSync(lockPath), 'the fresh lock must still be present, completely untouched');
  const content = readFileSync(lockPath, 'utf8');
  assert.equal(content, '', 'the fresh lock content must be unchanged (still empty, never overwritten)');
});

test('gate round 5: a live-holder lock (old createdAt, but pid alive) is NEVER taken over', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'r5-live-holder-devdir-')), 'r5-live-holder-devdir');
  mkdirSync(devDir, { recursive: true });
  const uid = testUid();
  const lockPath = __testOnlyRegistryLockPath(devDir, uid);

  // A WELL-FORMED lock claiming a very old createdAt (past the 60s
  // threshold) but naming OUR OWN pid — i.e. a definitely-alive holder.
  // Liveness must block the takeover regardless of age.
  writeFileSync(
    lockPath,
    JSON.stringify({ pid: process.pid, createdAt: new Date(Date.now() - 120_000).toISOString() }),
    { mode: 0o600 },
  );

  let thrown: unknown;
  try {
    __testOnlyAcquireRegistryLock(devDir, uid, { retryCount: 3, retryMs: 5 });
  } catch (err) {
    thrown = err;
  }
  assert.ok(thrown, 'acquisition must exhaust and throw — an old-but-LIVE holder must never be taken over');
  assert.ok(existsSync(lockPath), 'the live holder\'s lock must still be present');
  const parsed = JSON.parse(readFileSync(lockPath, 'utf8')) as { pid: number };
  assert.equal(parsed.pid, process.pid, 'the live holder\'s lock content must be unchanged');
});

// ── CHARIOT §5.7 file-reference form (AMENDED 2026-10-14) ─────────────────
//
// When the descriptor names a ciphertext FILE, the staging directory and
// its same-filesystem preflight must exist BEFORE the native file-to-file
// unseal (which writes the plaintext archive into it); the inline unseal is
// never used; the native receipt reaches edgeUnpackSnapshot; every existing
// staging/promotion/cleanup guarantee still holds. The fake below mirrors
// the native contract (`unseal_and_verify_snapshot_to_file`): it creates
// `outPath` exclusively (`wx` ≙ O_CREAT|O_EXCL; Node's `wx` also refuses a
// symlink at the final component), mode 0600, and returns `{ receipt }`.
// The native O_NOFOLLOW/O_EXCL/fsync hardening itself is proven by the
// edge_snapshot.rs `file_unseal_*` tests.

function makeFileCfg(ciphertextPath = '/fixture/catalog.edgeshard.sealed.ciphertext'): SealedShardConfig {
  return {
    descriptor: { ciphertextPath, ciphertextSha256: 'a'.repeat(64), ivB64: 'iv', signatureB64: 'sig', salt: 's', aad: 's|epoch=1' },
    publicKeyPem: 'pem',
    secretRootB64: 'root',
    licenseJwt: 'header.payload.signature',
  };
}

function fileUnseal(onCall?: (args: unknown[]) => void) {
  return (...args: unknown[]) => {
    onCall?.(args);
    writeFileSync(args[1] as string, 'plaintext-bytes', { flag: 'wx', mode: 0o600 });
    return { receipt: 'file-receipt' };
  };
}

function fileNative(overrides: Partial<NativeEdgeBinding> = {}): NativeEdgeBinding {
  return baseNative({
    unsealAndVerifySnapshot: () => {
      throw new Error('the inline unseal must not be used for a file-reference descriptor');
    },
    unsealAndVerifySnapshotToFile: fileUnseal(),
    ...overrides,
  } as Partial<NativeEdgeBinding>);
}

test('file form: staging + preflight precede the to-file unseal; receipt reaches unpack; promotion and cleanup as inline', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'file-happy-devdir-')), 'file-happy-devdir');
  mkdirSync(devDir, { recursive: true });
  writeFileSync(join(devDir, 'old-segment.dat'), 'old shard bytes');
  let capturedStagingDir = '';
  const events: string[] = [];
  const mkStagingDir = () => {
    events.push('mkStagingDir');
    capturedStagingDir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-file-happy-'));
    return capturedStagingDir;
  };
  const statDev = (path: string) => {
    events.push('statDev');
    return lstatSync(path).dev;
  };
  let unsealArgs: unknown[] = [];
  let unpackArgs: unknown[] = [];
  const native = fileNative({
    unsealAndVerifySnapshotToFile: fileUnseal((args) => {
      events.push('unseal');
      unsealArgs = args;
      assert.ok(existsSync(capturedStagingDir), 'the staging directory must exist before the native call writes into it');
    }),
    edgeUnpackSnapshot: (snapshotPath: string, targetPath: string, receipt: string) => {
      unpackArgs = [snapshotPath, targetPath, receipt];
      unpackThatWritesThenMaybeThrows(false)(snapshotPath, targetPath, receipt);
    },
  } as Partial<NativeEdgeBinding>);

  const result = unsealSealedShardIntoDevDir(native, makeFileCfg(), devDir, { mkStagingDir, statDev });
  assert.equal(result, okShard);
  assert.deepEqual(events, ['mkStagingDir', 'statDev', 'statDev', 'unseal'], 'staging and both preflight stats precede the unseal');
  assert.equal(unsealArgs.length, 10, 'sealedPath, outPath, iv, sig, pem, root, salt, aad, licenseJwt, watermarkDir');
  assert.deepEqual(unsealArgs, [
    '/fixture/catalog.edgeshard.sealed.ciphertext',
    join(capturedStagingDir, 'plaintext.archive'),
    'iv', 'sig', 'pem', 'root', 's', 's|epoch=1', 'header.payload.signature', devDir,
  ]);
  assert.deepEqual(unpackArgs, [join(capturedStagingDir, 'plaintext.archive'), join(capturedStagingDir, 'unpacked'), 'file-receipt']);
  assert.ok(existsSync(join(devDir, 'segment-0.dat')), 'unpacked content promoted');
  assert.equal(existsSync(join(devDir, 'old-segment.dat')), false, 'old devDir replaced, not merged');
  assert.equal(existsSync(capturedStagingDir), false, 'staging (holding the plaintext archive) removed after success');
  const siblings = readdirSync(dirname(devDir)).filter((f) => f.startsWith('file-happy-devdir.stale-'));
  assert.deepEqual(siblings, [], 'no .stale-* backup left behind');
});

test('file form: preflight device mismatch aborts BEFORE the unseal; staging removed; devDir untouched', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'file-preflight-devdir-')), 'file-preflight-devdir');
  let capturedStagingDir = '';
  const mkStagingDir = () => {
    capturedStagingDir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-file-preflight-'));
    return capturedStagingDir;
  };
  const statDev = (path: string) => (path === capturedStagingDir ? 111 : 222);
  let unsealCalls = 0;
  const native = fileNative({ unsealAndVerifySnapshotToFile: fileUnseal(() => { unsealCalls += 1; }) } as Partial<NativeEdgeBinding>);
  const result = unsealSealedShardIntoDevDir(native, makeFileCfg(), devDir, { mkStagingDir, statDev });
  assert.equal(result, null);
  assert.equal(unsealCalls, 0, 'no plaintext may be produced into a staging dir that failed the preflight');
  assert.equal(existsSync(capturedStagingDir), false);
  assert.equal(existsSync(devDir), false);
});

test('file form: the to-file unseal throws → null, staging removed, existing devDir intact', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'file-unseal-throws-devdir-')), 'file-unseal-throws-devdir');
  mkdirSync(devDir, { recursive: true });
  writeFileSync(join(devDir, 'existing-valid-segment.dat'), 'previously valid shard content');
  let capturedStagingDir = '';
  const mkStagingDir = () => {
    capturedStagingDir = mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-file-throws-'));
    return capturedStagingDir;
  };
  const native = fileNative({
    unsealAndVerifySnapshotToFile: () => {
      throw new Error('Snapshot signature verification failed (fixture)');
    },
  } as Partial<NativeEdgeBinding>);
  assert.equal(unsealSealedShardIntoDevDir(native, makeFileCfg(), devDir, { mkStagingDir }), null);
  assert.equal(existsSync(capturedStagingDir), false, 'staging removed on unseal failure');
  assert.ok(existsSync(join(devDir, 'existing-valid-segment.dat')), 'prior valid shard untouched');
});

test('file form F2: a pre-existing file or symlink at the staging archive path is refused by the exclusive create', () => {
  for (const seed of ['file', 'symlink'] as const) {
    const devDir = join(mkdtempSync(join(sandbox, `file-f2-${seed}-devdir-`)), `file-f2-${seed}-devdir`);
    const evilTarget = join(sandbox, `file-f2-${seed}-target-${process.hrtime.bigint()}.txt`);
    writeFileSync(evilTarget, 'attacker-controlled target file');
    let capturedStagingDir = '';
    const mkStagingDir = () => {
      capturedStagingDir = mkdtempSync(join(tmpdir(), `chariot-sealed-staging-test-file-f2-${seed}-`));
      const at = join(capturedStagingDir, 'plaintext.archive');
      if (seed === 'file') writeFileSync(at, 'stale-content');
      else symlinkSync(evilTarget, at);
      return capturedStagingDir;
    };
    const result = unsealSealedShardIntoDevDir(fileNative(), makeFileCfg(), devDir, { mkStagingDir });
    assert.equal(result, null, `${seed}: must be refused`);
    assert.equal(readFileSync(evilTarget, 'utf8'), 'attacker-controlled target file', `${seed}: never written through`);
    assert.equal(existsSync(capturedStagingDir), false, `${seed}: staging removed`);
    assert.equal(existsSync(devDir), false, `${seed}: devDir not created`);
  }
});

test('file form: a binary without unsealAndVerifySnapshotToFile fails closed before any staging', () => {
  const devDir = join(mkdtempSync(join(sandbox, 'file-no-surface-devdir-')), 'file-no-surface-devdir');
  let stagingFactoryCalls = 0;
  const mkStagingDir = () => {
    stagingFactoryCalls += 1;
    return mkdtempSync(join(tmpdir(), 'chariot-sealed-staging-test-file-no-surface-'));
  };
  const native = fileNative({ unsealAndVerifySnapshotToFile: undefined } as Partial<NativeEdgeBinding>);
  assert.equal(unsealSealedShardIntoDevDir(native, makeFileCfg(), devDir, { mkStagingDir }), null);
  assert.equal(stagingFactoryCalls, 0);
  assert.equal(existsSync(devDir), false);
});
