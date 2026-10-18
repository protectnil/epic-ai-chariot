import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { buildSnapshot, snapshotRecords, validateSealScope, assertPinnedSigningSeed } from './build-edgeshard-snapshot.js';
import { COMPILED_SERIALIZER_HASH, DEFAULT_RETRIEVAL_CONTRACT } from '../retrieval/VectorIndexVerifier.js';
import type { NativeEdgeBinding, NativeEdgeShard, NativeSealedShardFile } from '../retrieval/nativeEdge.js';
import { loadSealedShardDescriptor, SEALED_SHARD_DESCRIPTOR_ENV } from '../retrieval/sealedShardConfig.js';
import { CompositeEdgeShard } from '../retrieval/overlay/CompositeEdgeShard.js';

// These tests exercise the TS producer/config/composite seams with fixture
// encoders/storage. Rust's producer_archive_load_roundtrip uses REAL Edge,
// HKDF/AES/Ed25519/license verification, receipt unpack, and native load;
// the file seal/unseal pair is covered by edge_snapshot.rs file_* tests.
const bundle = { epoch: 123, catalogVersion: 7,
  manifest: { version: '4.0.0', encoder: DEFAULT_RETRIEVAL_CONTRACT, serializer_hash: COMPILED_SERIALIZER_HASH, recordCount: 2, tool_record_count: 2, capability_record_count: 0, recordCountPreOverlay: 2 },
  catalog: [{ id: 'fixture', tools: [
  { name: 'alpha', description: 'Find alpha', inputSchema: { properties: { query: {} }, required: ['query'] } },
  { name: 'beta', description: 'Find beta', inputSchema: {} },
] }], registry: [{ id: 'fixture' }] };
const root = Buffer.alloc(32, 41).toString('base64');
const segmentId = '00000000-0000-5000-8000-000000000001';

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** File-to-file seal fixture: a transport fixture, NOT a crypto
 * implementation (native Rust tests own the authenticated seal). Mirrors the
 * native contract that matters to the producer: reads the plaintext FILE,
 * creates the ciphertext file exclusively (refusing an existing path), and
 * reports the SHA-256 of exactly the bytes it wrote. */
function fakeSealFile(onPlaintext?: (bytes: Buffer, plaintextPath: string, ciphertextPath: string) => void) {
  return (plaintextPath: string, ciphertextPath: string, _root: string, salt: string, context: string, epoch: number): NativeSealedShardFile => {
    const bytes = readFileSync(plaintextPath);
    onPlaintext?.(bytes, plaintextPath, ciphertextPath);
    writeFileSync(ciphertextPath, bytes, { flag: 'wx', mode: 0o600 });
    return { ivB64: Buffer.alloc(12).toString('base64'), signatureB64: Buffer.alloc(64).toString('base64'), salt, aad: `${context}|epoch=${epoch}`, ciphertextSha256Hex: sha256Hex(bytes) };
  };
}

function fixtureShard(points: Array<{ id: string; payload: { toolId: string } }>): NativeEdgeShard {
  return {
    upsert(json) { points.push(...JSON.parse(json)); },
    flush() {}, close() {}, pointsCount: () => points.length,
    query: () => points.map((p, i) => ({ id: p.id, score: 2 - i, version: 1, payloadJson: JSON.stringify(p.payload) })),
    snapshotManifestJson: () => '{}',
  };
}

function fixtureNative(shard: NativeEdgeShard, extra: Record<string, unknown> = {}): NativeEdgeBinding {
  return {
    EdgeShardHandle: { create(path: string) {
      mkdirSync(join(path, 'segments', segmentId), { recursive: true });
      writeFileSync(join(path, 'segments', segmentId, 'segment.json'), '{}');
      writeFileSync(join(path, 'edge_config.json'), '{}');
      return shard;
    } },
    frozenSerializerHash: () => COMPILED_SERIALIZER_HASH,
    serializeTool: (_base: string, json: string) => json,
    sealEdgeSnapshotFile: fakeSealFile(),
    ...extra,
  } as unknown as NativeEdgeBinding;
}

const encoders = {
  dense: { embed: (docs: string[]) => docs.map(() => Array(768).fill(0.5)) },
  sparse: { embed: (docs: string[]) => docs.map(() => ({ indices: [1], values: [1] })) },
};

test('producer -> real sealedShardConfig -> real CompositeEdgeShard preserves tool identity', () => {
  const dir = mkdtempSync(join(tmpdir(), 'snapshot-fixture-'));
  const env = { ...process.env };
  const points: Array<{ id: string; payload: { toolId: string } }> = [];
  const shard = fixtureShard(points);
  let packed: Buffer | undefined;
  const native = fixtureNative(shard, { sealEdgeSnapshotFile: fakeSealFile(bytes => { packed = bytes; }) });
  try {
    const out = join(dir, 'catalog.edgeshard.sealed');
    const result = buildSnapshot({ bundle, native, ...encoders, secretRootB64: root, signingSeedB64: '', securityEpoch: 5, out, batchSize: 1 });
    assert.equal(result.recordCount, 2);
    assert.equal(result.descriptor.salt, '7');
    assert.equal(result.descriptor.aad, '7|epoch=5');
    assert.equal(result.descriptorPath, out);
    assert.equal(result.ciphertextPath, join(dir, 'catalog.edgeshard.sealed.ciphertext'));
    const bundlePath = join(dir, 'bundle.json');
    writeFileSync(bundlePath, JSON.stringify(bundle));
    execFileSync('node', ['scripts/verify-edgeshard-descriptor.mjs', out, bundlePath]);
    const wrongScope = join(dir, 'wrong-scope.sealed');
    writeFileSync(wrongScope, JSON.stringify({ ...result.descriptor, salt: '8' }));
    assert.throws(() => execFileSync('node', ['scripts/verify-edgeshard-descriptor.mjs', wrongScope, bundlePath], { stdio: 'pipe' }));
    const archive = join(dir, 'archive.tar');
    writeFileSync(archive, packed!);
    const entries = execFileSync('tar', ['-tf', archive], { encoding: 'utf8' });
    assert.ok(entries.includes(`segments/${segmentId}/files/segment.json`));
    const licenseDir = join(dir, '.epic-ai');
    mkdirSync(licenseDir);
    writeFileSync(join(licenseDir, 'chariot.license'), JSON.stringify({ jwt: 'fixture.license.jwt', renewal_secret: 'unused' }));
    process.env.HOME = dir;
    process.env.ENTERPRISE_MASTER_KEY = root;
    process.env[SEALED_SHARD_DESCRIPTOR_ENV] = out;
    const config = loadSealedShardDescriptor();
    assert.ok(config);
    assert.deepEqual(config.descriptor, {
      ciphertextPath: result.ciphertextPath,
      ciphertextSha256: result.descriptor.ciphertext.sha256,
      ivB64: result.descriptor.ivB64,
      signatureB64: result.descriptor.signatureB64,
      salt: result.descriptor.salt,
      aad: result.descriptor.aad,
    });
    const composite = new CompositeEdgeShard(shard, () => null, () => null);
    assert.deepEqual(composite.query({ prefetches: [], limit: 2 }).map(p => JSON.parse(p.payloadJson!).toolId), ['fixture:alpha', 'fixture:beta']);
    assert.throws(() => composite.upsert('[]'), /read-only/);
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in env)) delete process.env[key];
    Object.assign(process.env, env);
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── CHARIOT §5.7 file-reference form (AMENDED 2026-10-14) ─────────────────
// Failure classes: inline ciphertext leaking into the descriptor; descriptor
// visible before its ciphertext; a failed ciphertext publish leaving a
// descriptor or staging residue; the archive crossing JS as a string; a
// binary without the file sealer; read-back not using the file unseal.

test('descriptor is the file-reference form: no inline ciphertext, sha256 of the published ciphertext file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'snapshot-file-form-'));
  let sealArgs: { plaintextPath: string; ciphertextPath: string } | undefined;
  const native = fixtureNative(fixtureShard([]), { sealEdgeSnapshotFile: fakeSealFile((_b, plaintextPath, ciphertextPath) => { sealArgs = { plaintextPath, ciphertextPath }; }) });
  try {
    const out = join(dir, 'catalog.edgeshard.sealed');
    const result = buildSnapshot({ bundle, native, ...encoders, secretRootB64: root, signingSeedB64: '', securityEpoch: 5, out, batchSize: 2 });
    const onDisk = JSON.parse(readFileSync(out, 'utf8')) as Record<string, unknown>;
    assert.deepEqual(Object.keys(onDisk).sort(), ['aad', 'ciphertext', 'iv', 'ivB64', 'salt', 'signature', 'signatureB64']);
    assert.equal('ciphertextB64' in onDisk, false, 'no inline ciphertext alias');
    assert.deepEqual(onDisk.ciphertext, { file: 'catalog.edgeshard.sealed.ciphertext', sha256: result.descriptor.ciphertext.sha256 });
    assert.equal(onDisk.iv, onDisk.ivB64);
    assert.equal(onDisk.signature, onDisk.signatureB64);
    assert.equal(sha256Hex(readFileSync(result.ciphertextPath)), result.descriptor.ciphertext.sha256);
    // The sealer received FILE PATHS: the archive inside the private work
    // dir, and a staged ciphertext inside the OUTPUT directory (same
    // filesystem as the published path, so the publish rename is atomic).
    assert.ok(sealArgs);
    assert.equal(basename(sealArgs.plaintextPath), 'catalog.snapshot');
    assert.equal(dirname(dirname(sealArgs.ciphertextPath)), dir);
    assert.match(basename(dirname(sealArgs.ciphertextPath)), /^\.snapshot-output-/);
    // Only the two published files remain in the output directory.
    assert.deepEqual(readdirSync(dir).sort(), ['catalog.edgeshard.sealed', 'catalog.edgeshard.sealed.ciphertext']);
    assert.equal(existsSync(sealArgs.plaintextPath), false, 'the plaintext work archive is removed');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('ciphertext is published before the descriptor; a failed ciphertext publish publishes nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'snapshot-publish-order-'));
  const out = join(dir, 'catalog.edgeshard.sealed');
  try {
    const order: string[] = [];
    const record = (from: string, to: string) => {
      // At each rename, the descriptor must not yet be visible unless the
      // ciphertext it names already is.
      if (to === out) assert.ok(existsSync(`${out}.ciphertext`), 'ciphertext must be in place before the descriptor');
      order.push(basename(to));
      renameSync(from, to);
    };
    buildSnapshot({ bundle, native: fixtureNative(fixtureShard([])), ...encoders, secretRootB64: root, signingSeedB64: '', securityEpoch: 5, out, batchSize: 2, publishRename: record });
    assert.deepEqual(order, ['catalog.edgeshard.sealed.ciphertext', 'catalog.edgeshard.sealed']);

    const dir2 = mkdtempSync(join(tmpdir(), 'snapshot-publish-fail-'));
    const out2 = join(dir2, 'catalog.edgeshard.sealed');
    try {
      const failing = (_from: string, to: string) => {
        if (to.endsWith('.ciphertext')) throw new Error('simulated ciphertext publish failure');
        throw new Error('descriptor publish must not be attempted');
      };
      assert.throws(
        () => buildSnapshot({ bundle, native: fixtureNative(fixtureShard([])), ...encoders, secretRootB64: root, signingSeedB64: '', securityEpoch: 5, out: out2, batchSize: 2, publishRename: failing }),
        /simulated ciphertext publish failure/,
      );
      assert.deepEqual(readdirSync(dir2), [], 'no descriptor, no ciphertext, no staging residue');
    } finally { rmSync(dir2, { recursive: true, force: true }); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a sealer whose reported SHA-256 differs from the staged file is refused before publication', () => {
  const dir = mkdtempSync(join(tmpdir(), 'snapshot-sha-mismatch-'));
  const lying = (plaintextPath: string, ciphertextPath: string, r: string, salt: string, context: string, epoch: number) => ({
    ...fakeSealFile()(plaintextPath, ciphertextPath, r, salt, context, epoch),
    ciphertextSha256Hex: '0'.repeat(64),
  });
  try {
    assert.throws(
      () => buildSnapshot({ bundle, native: fixtureNative(fixtureShard([]), { sealEdgeSnapshotFile: lying }), ...encoders, secretRootB64: root, signingSeedB64: '', securityEpoch: 5, out: join(dir, 'catalog.edgeshard.sealed'), batchSize: 2 }),
      /does not match the sealer-reported SHA-256/,
    );
    assert.deepEqual(readdirSync(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a native binary without sealEdgeSnapshotFile (inline-only) is refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'snapshot-no-file-sealer-'));
  try {
    const native = fixtureNative(fixtureShard([]), { sealEdgeSnapshotFile: undefined, sealEdgeSnapshot: () => { throw new Error('inline sealer must not be used'); } });
    assert.throws(
      () => buildSnapshot({ bundle, native, ...encoders, secretRootB64: root, signingSeedB64: '', securityEpoch: 5, out: join(dir, 'catalog.edgeshard.sealed'), batchSize: 2 }),
      /lacks sealEdgeSnapshotFile/,
    );
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('read-back unseals the staged ciphertext FILE to a work file and unpacks with its receipt', () => {
  const dir = mkdtempSync(join(tmpdir(), 'snapshot-readback-'));
  const points: Array<{ id: string; payload: { toolId: string } }> = [];
  const shard = fixtureShard(points);
  let unsealCall: unknown[] | undefined;
  let unpackCall: unknown[] | undefined;
  const native = fixtureNative(shard, {
    unsealAndVerifySnapshotToFile: (...args: unknown[]) => {
      unsealCall = args;
      const [sealedPath, outPath] = args as [string, string];
      // The descriptor must not be published yet while read-back runs.
      assert.equal(existsSync(join(dir, 'catalog.edgeshard.sealed')), false);
      writeFileSync(outPath, readFileSync(sealedPath), { flag: 'wx', mode: 0o600 });
      return { receipt: 'fixture-receipt' };
    },
    unsealAndVerifySnapshot: () => { throw new Error('the inline unseal must not be used for read-back'); },
    edgeUnpackSnapshot: (...args: unknown[]) => { unpackCall = args; },
  });
  (native.EdgeShardHandle as unknown as { load: (p: string) => NativeEdgeShard }).load = () => ({ ...shard, pointsCount: () => 2, close() {} });
  try {
    const out = join(dir, 'catalog.edgeshard.sealed');
    const result = buildSnapshot({ bundle, native, ...encoders, secretRootB64: root, signingSeedB64: '', securityEpoch: 5, out, batchSize: 2, licenseJwt: 'fixture.license.jwt', watermarkDir: join(dir, 'wm') });
    assert.ok(unsealCall && unpackCall);
    const [sealedPath, outPath, ivB64, signatureB64, , , salt, aad, licenseJwt, watermarkDir] = unsealCall as string[];
    assert.equal(basename(sealedPath), 'catalog.edgeshard.sealed.ciphertext');
    assert.match(basename(dirname(sealedPath)), /^\.snapshot-output-/, 'read-back reads the STAGED ciphertext');
    assert.equal(basename(outPath), 'readback.snapshot');
    assert.deepEqual([ivB64, signatureB64, salt, aad, licenseJwt, watermarkDir], [result.descriptor.ivB64, result.descriptor.signatureB64, '7', '7|epoch=5', 'fixture.license.jwt', join(dir, 'wm')]);
    assert.equal((unpackCall as string[])[0], outPath);
    assert.equal((unpackCall as string[])[2], 'fixture-receipt');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('seal scope rejects short root, empty salt, context mismatch and malformed epochs', () => {
  assert.throws(() => validateSealScope(Buffer.alloc(31).toString('base64'), '7', '7|epoch=1'), /32 bytes/);
  assert.throws(() => validateSealScope(root, '', '|epoch=1'), /empty/);
  assert.throws(() => validateSealScope(root, '7', '8|epoch=1'), /mismatch/);
  for (const aad of ['', '7', '7|epoch=2|epoch=1', '7|epoch=-1', '7|epoch=4294967296']) assert.throws(() => validateSealScope(root, '7', aad));
});

test('no registry double-count, no tool-name invention, inactive exclusion, count/identity drift fail closed', () => {
  assert.equal(snapshotRecords(bundle).length, 2);
  assert.equal(snapshotRecords({ ...bundle, catalog: [...bundle.catalog, { id: 'inactive', active: false, tools: [{ name: 'hidden' }] }] }).length, 2);
  // An ACTIVE zero-tool adapter is a CH-62 capability record, never an invented
  // tool; without its grounded profile it fails closed exactly as admission does.
  assert.throws(() => snapshotRecords({ ...bundle, catalog: [...bundle.catalog, { id: 'no-tools', toolNames: ['invented'] }] }), /descriptionForRetrieval/);
  const residual = { id: 'no-tools', type: 'mcp', toolNames: ['invented'], descriptionForRetrieval: 'Residual profile', searchQueries: ['residual'] };
  const widened = snapshotRecords({ ...bundle, manifest: { ...bundle.manifest, recordCount: 3 }, catalog: [...bundle.catalog, residual] });
  assert.deepEqual(widened.map(r => [r.toolId, r.kind]), [['fixture:alpha', 'tool'], ['fixture:beta', 'tool'], ['no-tools', 'adapter_capability']]);
  assert.throws(() => snapshotRecords({ ...bundle, manifest: { recordCount: 3, serializer_hash: COMPILED_SERIALIZER_HASH } }), /manifest/);
  assert.throws(() => snapshotRecords({ ...bundle, manifest: undefined }), /manifest/);
  assert.throws(() => snapshotRecords({ ...bundle, catalog: [...bundle.catalog, ...bundle.catalog] }), /duplicate/);
  assert.throws(() => assertPinnedSigningSeed(Buffer.alloc(32, 42).toString('base64')), /pinned/);
});
