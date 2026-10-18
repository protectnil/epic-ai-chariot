/**
 * CHARIOT::§5.7 — `makeDiskArtifactSource.loadShard` sealed-shard wiring.
 *
 * Proves the fail-closed contract `sealedShardConfig.ts` and
 * `ChariotState.ts` document: once `CHARIOT_EDGE_SEALED_SHARD_DESCRIPTOR_PATH`
 * is set, `loadShard()` MUST go through the sealed path and MUST NOT fall
 * back to a plaintext `devDir` on any failure — even when that directory
 * exists and would otherwise load successfully via the legacy plaintext
 * branch. This is the regression guard for the clause's own framing: "the
 * sealed-snapshot consumer path is not wired into
 * `ChariotState.makeDiskArtifactSource`" must no longer be true, AND the new
 * wiring must not silently degrade to the unsealed path it replaces.
 *
 * `process.env.HOME` is redirected to a sandbox — see
 * `sealedShardConfig.test.ts`'s doc comment for why (`os.homedir()` reads
 * `$HOME` on POSIX; `src/license/loader.ts` has no override of its own).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { NativeEdgeBinding, NativeEdgeShard } from '../retrieval/nativeEdge.js';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

const realHome = process.env.HOME;
const sandbox = mkdtempSync(join(tmpdir(), 'chariot-sealed-shard-wiring-test-'));
process.env.EPIC_AI_DIR_OVERRIDE = sandbox;

const { makeDiskArtifactSource } = await import('./ChariotState.js');
const { SEALED_SHARD_DESCRIPTOR_ENV } = await import('../retrieval/sealedShardConfig.js');

function freshHomeSandbox(): string {
  const home = mkdtempSync(join(tmpdir(), 'chariot-sealed-shard-wiring-home-'));
  process.env.HOME = home;
  return home;
}

function writeLicenseEnvelope(home: string, jwt: string): void {
  const dir = join(home, '.epic-ai');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'chariot.license'), JSON.stringify({ jwt, renewal_secret: 'unused-in-this-test' }));
}

function clearEnv(): void {
  delete process.env[SEALED_SHARD_DESCRIPTOR_ENV];
  delete process.env.ENTERPRISE_MASTER_KEY;
  delete process.env.CHARIOT_EDGE_SHARD_DIR;
  process.env.HOME = realHome;
}

/** A fake shard the plaintext branch would successfully return — proves
 * (by NOT being returned) that the sealed branch really took over. */
const plaintextSentinelShard = { pointsCount: () => -999 } as unknown as NativeEdgeShard;

test('sealed descriptor configured but broken → loadShard fails closed, ignoring an existing plaintext devDir', () => {
  clearEnv();
  const devDir = join(sandbox, 'plaintext-shard-that-must-be-ignored');
  mkdirSync(devDir, { recursive: true });
  process.env.CHARIOT_EDGE_SHARD_DIR = devDir;
  // Descriptor path points at a file that does not exist — a "configured but
  // broken" sealed setup, per sealedShardConfig's contract.
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = join(sandbox, 'missing-descriptor.json');

  const fakeNative = {
    EdgeShardHandle: {
      create: () => {
        throw new Error('must not be called');
      },
      load: () => plaintextSentinelShard,
    },
  } as unknown as NativeEdgeBinding;

  const source = makeDiskArtifactSource(fakeNative);
  const result = source.loadShard();
  assert.equal(result, null, 'a broken sealed configuration must fail closed, never fall back to plaintext');

  clearEnv();
});

test('sealed descriptor unset → legacy plaintext devDir path still works unchanged', () => {
  clearEnv();
  const devDir = join(sandbox, 'plaintext-shard-legacy');
  mkdirSync(devDir, { recursive: true });
  process.env.CHARIOT_EDGE_SHARD_DIR = devDir;

  const fakeNative = {
    EdgeShardHandle: {
      create: () => {
        throw new Error('must not be called');
      },
      load: (path: string) => {
        assert.equal(path, devDir);
        return plaintextSentinelShard;
      },
    },
  } as unknown as NativeEdgeBinding;

  const source = makeDiskArtifactSource(fakeNative);
  const result = source.loadShard();
  assert.equal(result, plaintextSentinelShard, 'unconfigured sealed path must preserve the legacy plaintext load');

  clearEnv();
});

test('sealed descriptor fully configured but native surface absent → fails closed', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelope(home, 'fake-header.fake-payload.fake-signature');

  const devDir = join(sandbox, 'plaintext-shard-2');
  mkdirSync(devDir, { recursive: true });
  process.env.CHARIOT_EDGE_SHARD_DIR = devDir;

  const descriptorPath = join(sandbox, 'descriptor.json');
  writeFileSync(
    descriptorPath,
    JSON.stringify({ ciphertextB64: 'eA==', ivB64: 'y', signatureB64: 'z', salt: 'tenant-x', aad: 'tenant-x|epoch=1' }),
  );
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = descriptorPath;
  process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 1).toString('base64');

  // Native binding present but WITHOUT the §5.7 unseal surface.
  const fakeNative = {
    EdgeShardHandle: {
      create: () => {
        throw new Error('must not be called');
      },
      load: () => plaintextSentinelShard,
    },
  } as unknown as NativeEdgeBinding;

  const source = makeDiskArtifactSource(fakeNative);
  const result = source.loadShard();
  assert.equal(result, null, 'missing native unseal surface must fail closed, never fall back to plaintext');

  clearEnv();
});

test('sealed descriptor configured, license envelope resolves, unseal itself throws → fails closed', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelope(home, 'fake-header.fake-payload.fake-signature');

  const devDir = join(sandbox, 'plaintext-shard-3');
  mkdirSync(devDir, { recursive: true });
  process.env.CHARIOT_EDGE_SHARD_DIR = devDir;

  const descriptorPath = join(sandbox, 'descriptor2.json');
  writeFileSync(
    descriptorPath,
    JSON.stringify({ ciphertextB64: 'eA==', ivB64: 'y', signatureB64: 'z', salt: 'tenant-x', aad: 'tenant-x|epoch=1' }),
  );
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = descriptorPath;
  process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 1).toString('base64');

  let unsealCalledWith: unknown[] | null = null;
  const fakeNative = {
    EdgeShardHandle: {
      create: () => {
        throw new Error('must not be called');
      },
      load: () => plaintextSentinelShard,
    },
    unsealAndVerifySnapshot: (...args: unknown[]) => {
      unsealCalledWith = args;
      throw new Error('license JWT signature verification failed (fixture)');
    },
    edgeUnpackSnapshot: () => {
      throw new Error('must not be called — unseal already failed');
    },
  } as unknown as NativeEdgeBinding;

  const source = makeDiskArtifactSource(fakeNative);
  const result = source.loadShard();
  assert.equal(result, null, 'a throwing unseal call must fail closed, never fall back to plaintext');
  assert.ok(unsealCalledWith, 'unsealAndVerifySnapshot must have been reached (config resolved successfully)');
  // Positional args: ciphertextB64, ivB64, signatureB64, publicKeyPem,
  // secretRootB64, salt, aad, licenseJwt, watermarkDir (CH-56 — 9 args, no
  // bare minEpoch scalar).
  assert.equal((unsealCalledWith as unknown[]).length, 9);
  assert.equal((unsealCalledWith as unknown[])[7], 'fake-header.fake-payload.fake-signature');

  clearEnv();
});

// ── Dogfood-ready 4.0: the DEFAULT descriptor location selects the sealed
// branch exactly like the env var (same predicate), and the licence
// seal_secret is the secret root handed to native unseal. ──────────────────

function writeDefaultDescriptor(): string {
  const dir = join(sandbox, 'edgeshard');
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'catalog.edgeshard.sealed');
  writeFileSync(
    p,
    JSON.stringify({ ciphertextB64: 'eA==', ivB64: 'y', signatureB64: 'z', salt: '2026.10.14', aad: '2026.10.14|epoch=1' }),
  );
  return p;
}

function writeLicenseEnvelopeWithSeal(home: string, sealSecret: unknown): void {
  const dir = join(home, '.epic-ai');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'chariot.license'),
    JSON.stringify({ jwt: 'fake-header.fake-payload.fake-signature', renewal_secret: 'unused', seal_secret: sealSecret }),
  );
}

test('env unset + default <EPIC_AI_DIR>/edgeshard/catalog.edgeshard.sealed present → sealed branch, seal_secret is the root', () => {
  clearEnv();
  const home = freshHomeSandbox();
  const seal = Buffer.alloc(32, 0x42).toString('base64');
  writeLicenseEnvelopeWithSeal(home, seal);
  const devDir = join(sandbox, 'plaintext-shard-default-descriptor');
  mkdirSync(devDir, { recursive: true });
  process.env.CHARIOT_EDGE_SHARD_DIR = devDir;
  writeDefaultDescriptor();
  // ENTERPRISE_MASTER_KEY deliberately unset: the licence seal_secret alone
  // must be enough.
  let unsealArgs: unknown[] | null = null;
  const fakeNative = {
    EdgeShardHandle: {
      create: () => {
        throw new Error('must not be called');
      },
      load: () => plaintextSentinelShard,
    },
    unsealAndVerifySnapshot: (...args: unknown[]) => {
      unsealArgs = args;
      throw new Error('fixture: stop after argument capture');
    },
    edgeUnpackSnapshot: () => {
      throw new Error('must not be called');
    },
  } as unknown as NativeEdgeBinding;
  try {
    const result = makeDiskArtifactSource(fakeNative).loadShard();
    assert.equal(result, null, 'the plaintext devDir must not be used once a default descriptor exists');
    assert.ok(unsealArgs, 'the default descriptor must select the sealed branch');
    assert.equal((unsealArgs as unknown[])[4], seal, 'secretRootB64 must be the licence seal_secret');
    assert.equal((unsealArgs as unknown[])[5], '2026.10.14');
  } finally {
    rmSync(join(sandbox, 'edgeshard'), { recursive: true, force: true });
    clearEnv();
  }
});

test('env unset + default descriptor present + MALFORMED seal_secret → fails closed (no EMK fallback, no plaintext)', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelopeWithSeal(home, 'not-a-valid-seal-secret');
  const devDir = join(sandbox, 'plaintext-shard-default-descriptor-bad-seal');
  mkdirSync(devDir, { recursive: true });
  process.env.CHARIOT_EDGE_SHARD_DIR = devDir;
  process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 1).toString('base64');
  writeDefaultDescriptor();
  const fakeNative = {
    EdgeShardHandle: {
      create: () => {
        throw new Error('must not be called');
      },
      load: () => plaintextSentinelShard,
    },
    unsealAndVerifySnapshot: () => {
      throw new Error('must not be called — config must fail first');
    },
    edgeUnpackSnapshot: () => {
      throw new Error('must not be called');
    },
  } as unknown as NativeEdgeBinding;
  try {
    assert.equal(makeDiskArtifactSource(fakeNative).loadShard(), null);
  } finally {
    rmSync(join(sandbox, 'edgeshard'), { recursive: true, force: true });
    clearEnv();
  }
});

// ── CHARIOT §5.7 file-reference form (AMENDED 2026-10-14) through loadShard ─
// A descriptor whose `ciphertext` is `{ file, sha256 }` must reach the
// native FILE-to-file unseal with the resolved ciphertext path and a
// staging-archive output path under devDir's parent — never the inline
// base64 unseal — and fail closed when the binary lacks that entry point.

function writeFileFormDescriptor(dirName: string): { descriptorPath: string; ciphertextPath: string } {
  const dir = join(sandbox, dirName);
  mkdirSync(dir, { recursive: true });
  const ciphertextPath = join(dir, 'catalog.edgeshard.sealed.ciphertext');
  const bytes = Buffer.from('fixture ciphertext bytes (transport only)');
  writeFileSync(ciphertextPath, bytes);
  const descriptorPath = join(dir, 'catalog.edgeshard.sealed');
  writeFileSync(
    descriptorPath,
    JSON.stringify({
      ciphertext: { file: 'catalog.edgeshard.sealed.ciphertext', sha256: createHash('sha256').update(bytes).digest('hex') },
      iv: 'y', signature: 'z', ivB64: 'y', signatureB64: 'z', salt: '2026.10.14', aad: '2026.10.14|epoch=1',
    }),
  );
  return { descriptorPath, ciphertextPath };
}

test('file-form descriptor → loadShard calls unsealAndVerifySnapshotToFile (never the inline unseal), fails closed on its error', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelope(home, 'fake-header.fake-payload.fake-signature');
  const devDir = join(sandbox, 'plaintext-shard-file-form');
  mkdirSync(devDir, { recursive: true });
  process.env.CHARIOT_EDGE_SHARD_DIR = devDir;
  const { descriptorPath, ciphertextPath } = writeFileFormDescriptor('file-form-descriptor');
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = descriptorPath;
  process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 1).toString('base64');

  let toFileArgs: unknown[] | null = null;
  let stagingExistedDuringCall = false;
  let inlineCalled = false;
  const fakeNative = {
    EdgeShardHandle: {
      create: () => {
        throw new Error('must not be called');
      },
      load: () => plaintextSentinelShard,
    },
    unsealAndVerifySnapshot: () => {
      inlineCalled = true;
      throw new Error('the inline unseal must not be called for a file-reference descriptor');
    },
    unsealAndVerifySnapshotToFile: (...args: unknown[]) => {
      toFileArgs = args;
      stagingExistedDuringCall = existsSync(dirname(args[1] as string));
      throw new Error('fixture: stop after argument capture');
    },
    edgeUnpackSnapshot: () => {
      throw new Error('must not be called — unseal already failed');
    },
  } as unknown as NativeEdgeBinding;
  try {
    assert.equal(makeDiskArtifactSource(fakeNative).loadShard(), null, 'a throwing file unseal must fail closed');
    assert.ok(toFileArgs, 'unsealAndVerifySnapshotToFile must have been reached');
    const args = toFileArgs as unknown[];
    assert.equal(args.length, 10);
    assert.equal(args[0], ciphertextPath, 'sealedPath is the descriptor-relative ciphertext file');
    assert.match(args[1] as string, /\/\.chariot-sealed-staging-[^/]+\/plaintext\.archive$/);
    assert.equal(dirname(dirname(args[1] as string)), dirname(devDir), 'staging lives beside devDir (same filesystem)');
    assert.ok(stagingExistedDuringCall, 'staging exists before the native call writes into it');
    assert.equal(existsSync(dirname(args[1] as string)), false, 'staging removed after the failure');
    // (sealedPath, outPath, iv, signature, publicKeyPem, secretRoot, salt, aad, licenseJwt, watermarkDir)
    assert.equal(args[8], 'fake-header.fake-payload.fake-signature');
    assert.equal(args[9], devDir, 'watermarkDir is devDir, as for the inline path');
    assert.equal(inlineCalled, false, 'the inline unseal is never used for a file-reference descriptor');
  } finally {
    clearEnv();
  }
});

test('file-form descriptor + binary WITHOUT unsealAndVerifySnapshotToFile → fails closed, inline unseal never used', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelope(home, 'fake-header.fake-payload.fake-signature');
  const devDir = join(sandbox, 'plaintext-shard-file-form-no-surface');
  mkdirSync(devDir, { recursive: true });
  process.env.CHARIOT_EDGE_SHARD_DIR = devDir;
  const { descriptorPath } = writeFileFormDescriptor('file-form-descriptor-no-surface');
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = descriptorPath;
  process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 1).toString('base64');
  let inlineCalled = false;
  const fakeNative = {
    EdgeShardHandle: {
      create: () => {
        throw new Error('must not be called');
      },
      load: () => plaintextSentinelShard,
    },
    unsealAndVerifySnapshot: () => {
      inlineCalled = true;
      throw new Error('the inline unseal must not be called for a file-reference descriptor');
    },
    edgeUnpackSnapshot: () => {
      throw new Error('must not be called');
    },
  } as unknown as NativeEdgeBinding;
  try {
    assert.equal(makeDiskArtifactSource(fakeNative).loadShard(), null);
    assert.equal(inlineCalled, false, 'a file-reference descriptor must never fall back to the inline unseal');
  } finally {
    clearEnv();
  }
});
