/**
 * CHARIOT::§3.1::5 — "The system SHALL stage locally the retrieval
 * artifacts (ONNX encoder, tokenizer, serializer corpus, manifest) under
 * ~/.epic-ai/models/ (customer-owned, optional)." (CHARIOT-SPEC.md:188).
 * CHARIOT::§3.1::6 — "The system SHALL use ~/.epic-ai/qdrant/
 * (customer-owned) as the bundled local Qdrant data directory, optional
 * but required for persistence." (CHARIOT-SPEC.md:189).
 *
 * `makeDiskArtifactSource`'s four accessors (loadDenseEncoder,
 * loadSparseEncoder, loadRerankScorer, loadShard) each gate on
 * `existsSync(dir)` BEFORE ever touching the injected `native` binding —
 * this lets the directory-resolution contract (env var wins; otherwise the
 * MODELS_DIR/QDRANT_DATA_DIR default; EPIC_AI_DIR_OVERRIDE honored) be
 * tested with a minimal fake `native` object, with no working native
 * binary required. A distinct stderr log line (or its absence) is used as
 * the observable proxy for "did the accessor proceed past the existsSync
 * gate" without needing the native calls to actually succeed.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { NativeEdgeBinding } from '../retrieval/nativeEdge.js';

const sandbox = mkdtempSync(join(tmpdir(), 'chariot-artifact-dirs-test-'));
process.env.EPIC_AI_DIR_OVERRIDE = sandbox;

const { makeDiskArtifactSource } = await import('./ChariotState.js');
const { MODELS_DIR, QDRANT_DATA_DIR } = await import('../../cli/paths.js');

/** A fake native binding whose methods, if ever called, prove the accessor
 * reached past the directory-existence gate (they throw synchronously). */
const fakeNative = {} as NativeEdgeBinding;

async function captureStderr(fn: () => void | Promise<void>): Promise<string> {
  let out = '';
  const original = process.stderr.write.bind(process.stderr);
  (process.stderr as any).write = (chunk: any) => {
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

test('loadDenseEncoder: absent directory (no env var, default MODELS_DIR/dense missing) returns null silently', async () => {
  delete process.env.CHARIOT_DENSE_MODEL_DIR;
  const source = makeDiskArtifactSource(fakeNative);
  const stderr = await captureStderr(() => {
    const result = source.loadDenseEncoder();
    assert.equal(result, null);
  });
  assert.equal(stderr, '', 'a genuinely absent directory must short-circuit before any warn log');
});

test('loadDenseEncoder: default MODELS_DIR/dense directory (created on disk, no env override) is used', async () => {
  delete process.env.CHARIOT_DENSE_MODEL_DIR;
  delete process.env.CHARIOT_DENSE_MAX_LENGTH;
  const denseDir = join(MODELS_DIR, 'dense');
  mkdirSync(denseDir, { recursive: true });
  const source = makeDiskArtifactSource(fakeNative);
  const stderr = await captureStderr(() => {
    const result = source.loadDenseEncoder();
    assert.equal(result, null); // still null (no CHARIOT_DENSE_MAX_LENGTH) — but for a DIFFERENT reason
  });
  assert.ok(
    stderr.includes('retrieval.dense_max_length_invalid'),
    `expected the accessor to have found ${denseDir} and proceeded to the max-length gate; stderr: ${stderr}`,
  );
});

test('loadDenseEncoder: CHARIOT_DENSE_MODEL_DIR env var overrides the MODELS_DIR default', async () => {
  const envDir = mkdtempSync(join(tmpdir(), 'chariot-dense-env-override-'));
  process.env.CHARIOT_DENSE_MODEL_DIR = envDir;
  delete process.env.CHARIOT_DENSE_MAX_LENGTH;
  // Deliberately do NOT create MODELS_DIR/dense — if the code fell back to
  // the default instead of honoring the env var, this test would see the
  // "absent directory, silent null" behavior instead.
  const source = makeDiskArtifactSource(fakeNative);
  const stderr = await captureStderr(() => {
    const result = source.loadDenseEncoder();
    assert.equal(result, null);
  });
  assert.ok(
    stderr.includes('retrieval.dense_max_length_invalid'),
    `expected the env-var directory ${envDir} to be used; stderr: ${stderr}`,
  );
  delete process.env.CHARIOT_DENSE_MODEL_DIR;
});

test('loadShard: absent directory (no env var, default QDRANT_DATA_DIR missing) returns null silently', async () => {
  delete process.env.CHARIOT_EDGE_SHARD_DIR;
  delete process.env.CHARIOT_QDRANT_DATA_DIR;
  const source = makeDiskArtifactSource(fakeNative);
  const stderr = await captureStderr(() => {
    const result = source.loadShard();
    assert.equal(result, null);
  });
  assert.equal(stderr, '', 'a genuinely absent qdrant directory must short-circuit before any warn log');
});

test('loadShard: default QDRANT_DATA_DIR (created on disk, no env override) is used', async () => {
  delete process.env.CHARIOT_EDGE_SHARD_DIR;
  delete process.env.CHARIOT_QDRANT_DATA_DIR;
  mkdirSync(QDRANT_DATA_DIR, { recursive: true });
  const source = makeDiskArtifactSource(fakeNative);
  const stderr = await captureStderr(() => {
    const result = source.loadShard();
    assert.equal(result, null); // fakeNative.EdgeShardHandle is undefined -> throws -> caught -> null
  });
  assert.ok(
    stderr.includes('retrieval.shard_load_failed'),
    `expected the accessor to have found ${QDRANT_DATA_DIR} and attempted a load; stderr: ${stderr}`,
  );
});

test('loadShard: CHARIOT_EDGE_SHARD_DIR env var wins over both CHARIOT_QDRANT_DATA_DIR and the default', async () => {
  const edgeShardDir = mkdtempSync(join(tmpdir(), 'chariot-edge-shard-env-'));
  const qdrantEnvDir = mkdtempSync(join(tmpdir(), 'chariot-qdrant-env-not-used-'));
  process.env.CHARIOT_EDGE_SHARD_DIR = edgeShardDir;
  process.env.CHARIOT_QDRANT_DATA_DIR = qdrantEnvDir;
  const source = makeDiskArtifactSource(fakeNative);
  const stderr = await captureStderr(() => {
    source.loadShard();
  });
  assert.ok(stderr.includes('retrieval.shard_load_failed'), 'CHARIOT_EDGE_SHARD_DIR must have been used (it exists)');
  delete process.env.CHARIOT_EDGE_SHARD_DIR;
  delete process.env.CHARIOT_QDRANT_DATA_DIR;
});

test('loadShard: CHARIOT_QDRANT_DATA_DIR is honored when CHARIOT_EDGE_SHARD_DIR is unset (CHANGELOG-documented name)', async () => {
  delete process.env.CHARIOT_EDGE_SHARD_DIR;
  const qdrantEnvDir = mkdtempSync(join(tmpdir(), 'chariot-qdrant-env-used-'));
  process.env.CHARIOT_QDRANT_DATA_DIR = qdrantEnvDir;
  const source = makeDiskArtifactSource(fakeNative);
  const stderr = await captureStderr(() => {
    source.loadShard();
  });
  assert.ok(stderr.includes('retrieval.shard_load_failed'), 'CHARIOT_QDRANT_DATA_DIR must have been used (it exists)');
  delete process.env.CHARIOT_QDRANT_DATA_DIR;
});


// ── Dogfood-ready 4.0: export-derived model parameters + ONNX Runtime default
//
// CHARIOT §23.2::145/146/181: each encoder max length is sourced from the
// export's own config.json / tokenizer_config.json, never assumed.
// Failure classes: env unset → export value used and published; env set and
// equal → accepted; env set and different from the export → refused; env set
// but invalid → refused (never falls back); export files absent, unparseable,
// non-object, missing key, non-integer / zero / negative / string / unsafe /
// boolean / null, or config and tokenizer disagreeing → refused; dense
// pooling env must be mean|cls, unset → spec value 'mean' published; ORT
// default only when ORT_DYLIB_PATH is unset (or empty) AND
// <dir>/lib/libonnxruntime.so is a regular file.

const {
  exportMaxLength,
  resolveModelMaxLength,
  resolveDensePooling,
  applyDefaultOrtDylibPath,
} = await import('./ChariotState.js');

function exportDir(config: unknown, tokenizerConfig: unknown): string {
  const d = mkdtempSync(join(tmpdir(), 'chariot-export-'));
  if (config !== undefined) writeFileSync(join(d, 'config.json'), typeof config === 'string' ? config : JSON.stringify(config));
  if (tokenizerConfig !== undefined) {
    writeFileSync(join(d, 'tokenizer_config.json'), typeof tokenizerConfig === 'string' ? tokenizerConfig : JSON.stringify(tokenizerConfig));
  }
  return d;
}

function withEnv(vars: Record<string, string | undefined>, fn: () => void): void {
  const saved: Record<string, string | undefined> = {};
  for (const k of Object.keys(vars)) {
    saved[k] = process.env[k];
    if (vars[k] === undefined) delete process.env[k];
    else process.env[k] = vars[k];
  }
  try {
    fn();
  } finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

test('exportMaxLength: config and tokenizer must agree on one positive safe integer', () => {
  assert.deepEqual(exportMaxLength(exportDir({ max_position_embeddings: 2048 }, { model_max_length: 2048 })), { ok: true, value: 2048 });
  assert.deepEqual(exportMaxLength(exportDir({ max_position_embeddings: 1 }, { model_max_length: 1 })), { ok: true, value: 1 });
  const bad: Array<[string, unknown, unknown]> = [
    ['disagree', { max_position_embeddings: 2048 }, { model_max_length: 512 }],
    ['config absent', undefined, { model_max_length: 512 }],
    ['tokenizer absent', { max_position_embeddings: 512 }, undefined],
    ['config unparseable', '{bad', { model_max_length: 512 }],
    ['config array', [512], { model_max_length: 512 }],
    ['config null', 'null', { model_max_length: 512 }],
    ['missing key', {}, { model_max_length: 512 }],
    ['non-integer', { max_position_embeddings: 512.5 }, { model_max_length: 512.5 }],
    ['zero', { max_position_embeddings: 0 }, { model_max_length: 0 }],
    ['negative', { max_position_embeddings: -512 }, { model_max_length: -512 }],
    ['string', { max_position_embeddings: '512' }, { model_max_length: '512' }],
    ['unsafe', { max_position_embeddings: 2 ** 53 }, { model_max_length: 2 ** 53 }],
    ['boolean', { max_position_embeddings: true }, { model_max_length: true }],
    ['null value', { max_position_embeddings: null }, { model_max_length: null }],
  ];
  for (const [label, c, t] of bad) assert.equal(exportMaxLength(exportDir(c, t)).ok, false, label);
});

test('resolveModelMaxLength: env unset → the export value is used and published to the env var', () => {
  const dir = exportDir({ max_position_embeddings: 512 }, { model_max_length: 512 });
  withEnv({ CHARIOT_SPLADE_MAX_LENGTH: undefined }, () => {
    assert.deepEqual(resolveModelMaxLength('CHARIOT_SPLADE_MAX_LENGTH', dir), { ok: true, value: 512, source: 'artifact' });
    assert.equal(process.env.CHARIOT_SPLADE_MAX_LENGTH, '512');
  });
});

test('resolveModelMaxLength: env equal to the export is accepted; different or invalid is refused', () => {
  const dir = exportDir({ max_position_embeddings: 2048 }, { model_max_length: 2048 });
  withEnv({ CHARIOT_DENSE_MAX_LENGTH: '2048' }, () => {
    assert.deepEqual(resolveModelMaxLength('CHARIOT_DENSE_MAX_LENGTH', dir), { ok: true, value: 2048, source: 'env' });
  });
  withEnv({ CHARIOT_DENSE_MAX_LENGTH: '512' }, () => {
    const r = resolveModelMaxLength('CHARIOT_DENSE_MAX_LENGTH', dir);
    assert.equal(r.ok, false, 'a value disagreeing with the export silently changes scores');
    assert.match(r.ok ? '' : r.reason, /declares 2048/);
  });
  for (const bad of ['', '0', '-1', '1.5', 'abc']) {
    withEnv({ CHARIOT_DENSE_MAX_LENGTH: bad }, () => {
      assert.equal(resolveModelMaxLength('CHARIOT_DENSE_MAX_LENGTH', dir).ok, false, `env=${JSON.stringify(bad)} must not fall back`);
      assert.equal(process.env.CHARIOT_DENSE_MAX_LENGTH, bad, 'an invalid operator value is never overwritten');
    });
  }
});

test('resolveModelMaxLength: env set but export unreadable or inconsistent → refused (value not traceable to the artifact)', () => {
  for (const dir of [exportDir(undefined, undefined), exportDir({ max_position_embeddings: 512 }, { model_max_length: 256 })]) {
    withEnv({ CHARIOT_RERANKER_MAX_LENGTH: '512' }, () => {
      assert.equal(resolveModelMaxLength('CHARIOT_RERANKER_MAX_LENGTH', dir).ok, false);
    });
  }
});

test('resolveModelMaxLength: env unset and export unusable → unavailable, nothing published', () => {
  const dir = exportDir({ max_position_embeddings: 2048 }, { model_max_length: 512 });
  withEnv({ CHARIOT_RERANKER_MAX_LENGTH: undefined }, () => {
    const r = resolveModelMaxLength('CHARIOT_RERANKER_MAX_LENGTH', dir);
    assert.equal(r.ok, false);
    assert.match(r.ok ? '' : r.reason, /CHARIOT_RERANKER_MAX_LENGTH/);
    assert.equal(process.env.CHARIOT_RERANKER_MAX_LENGTH, undefined);
  });
});

test('resolveDensePooling: only mean is accepted (CHARIOT §23.2::182); unset → mean published', () => {
  withEnv({ CHARIOT_DENSE_POOLING: undefined }, () => {
    assert.deepEqual(resolveDensePooling(), { ok: true, value: 'mean', source: 'spec' });
    assert.equal(process.env.CHARIOT_DENSE_POOLING, 'mean');
  });
  withEnv({ CHARIOT_DENSE_POOLING: 'mean' }, () => {
    assert.deepEqual(resolveDensePooling(), { ok: true, value: 'mean', source: 'env' });
  });
  for (const bad of ['cls', 'avg', 'MEAN', '']) {
    withEnv({ CHARIOT_DENSE_POOLING: bad }, () => {
      assert.equal(resolveDensePooling().ok, false, `pooling ${JSON.stringify(bad)} must be refused`);
    });
  }
});

test('applyDefaultOrtDylibPath: sets ORT_DYLIB_PATH only when unset and <dir>/lib/libonnxruntime.so is a file', () => {
  const base = mkdtempSync(join(tmpdir(), 'chariot-ort-default-'));
  const lib = join(base, 'lib', 'libonnxruntime.so');
  withEnv({ ORT_DYLIB_PATH: undefined }, () => {
    assert.equal(applyDefaultOrtDylibPath(base), null, 'file absent → no-op');
    assert.equal(process.env.ORT_DYLIB_PATH, undefined);
    mkdirSync(lib, { recursive: true }); // a DIRECTORY at the path
    assert.equal(applyDefaultOrtDylibPath(base), null, 'directory is not a file → no-op');
    assert.equal(process.env.ORT_DYLIB_PATH, undefined);
    rmSync(lib, { recursive: true });
    writeFileSync(lib, 'not-really-a-shared-object');
    assert.equal(applyDefaultOrtDylibPath(base), lib);
    assert.equal(process.env.ORT_DYLIB_PATH, lib);
  });
  withEnv({ ORT_DYLIB_PATH: '/operator/chosen/libonnxruntime.so' }, () => {
    assert.equal(applyDefaultOrtDylibPath(base), null, 'operator value wins');
    assert.equal(process.env.ORT_DYLIB_PATH, '/operator/chosen/libonnxruntime.so');
  });
  withEnv({ ORT_DYLIB_PATH: '' }, () => {
    assert.equal(applyDefaultOrtDylibPath(base), lib, 'empty is treated as unset (matches native ort_dylib.rs)');
    assert.equal(process.env.ORT_DYLIB_PATH, lib);
  });
});

test('applyDefaultOrtDylibPath: a symlink to a real file is accepted; a dangling symlink is not', () => {
  const base = mkdtempSync(join(tmpdir(), 'chariot-ort-symlink-'));
  mkdirSync(join(base, 'lib'), { recursive: true });
  const real = join(base, 'lib', 'libonnxruntime.so.1.22.0');
  const link = join(base, 'lib', 'libonnxruntime.so');
  symlinkSync(real, link); // dangling first
  withEnv({ ORT_DYLIB_PATH: undefined }, () => {
    assert.equal(applyDefaultOrtDylibPath(base), null);
    writeFileSync(real, 'x');
    assert.equal(applyDefaultOrtDylibPath(base), link);
  });
});

test('makeDiskArtifactSource: dense leg derives its length from the export in the default dir (gates passed → reaches model read)', async () => {
  delete process.env.CHARIOT_DENSE_MODEL_DIR;
  const denseDir = join(MODELS_DIR, 'dense');
  mkdirSync(denseDir, { recursive: true });
  writeFileSync(join(denseDir, 'config.json'), JSON.stringify({ max_position_embeddings: 2048 }));
  writeFileSync(join(denseDir, 'tokenizer_config.json'), JSON.stringify({ model_max_length: 2048 }));
  delete process.env.CHARIOT_DENSE_MAX_LENGTH;
  delete process.env.CHARIOT_DENSE_POOLING;
  try {
    const source = makeDiskArtifactSource(fakeNative);
    const stderr = await captureStderr(() => {
      assert.equal(source.loadDenseEncoder(), null); // model.onnx absent → load fails after the gates
    });
    assert.ok(!stderr.includes('retrieval.dense_max_length_invalid'), `export length must be used; stderr: ${stderr}`);
    assert.ok(!stderr.includes('retrieval.dense_pooling_invalid'), `spec pooling must be used; stderr: ${stderr}`);
    assert.ok(stderr.includes('retrieval.dense_load_failed'), `expected to reach the model read; stderr: ${stderr}`);
    assert.equal(process.env.CHARIOT_DENSE_MAX_LENGTH, '2048');
  } finally {
    delete process.env.CHARIOT_DENSE_MAX_LENGTH;
    delete process.env.CHARIOT_DENSE_POOLING;
    rmSync(join(denseDir, 'config.json'), { force: true });
    rmSync(join(denseDir, 'tokenizer_config.json'), { force: true });
  }
});

test('makeDiskArtifactSource: export lengths disagreeing → dense leg disabled at the gate, model never read', async () => {
  delete process.env.CHARIOT_DENSE_MODEL_DIR;
  delete process.env.CHARIOT_DENSE_MAX_LENGTH;
  const denseDir = join(MODELS_DIR, 'dense');
  mkdirSync(denseDir, { recursive: true });
  writeFileSync(join(denseDir, 'config.json'), JSON.stringify({ max_position_embeddings: 2048 }));
  writeFileSync(join(denseDir, 'tokenizer_config.json'), JSON.stringify({ model_max_length: 512 }));
  try {
    const source = makeDiskArtifactSource(fakeNative);
    const stderr = await captureStderr(() => {
      assert.equal(source.loadDenseEncoder(), null);
    });
    assert.ok(stderr.includes('retrieval.dense_max_length_invalid'), `stderr: ${stderr}`);
    assert.ok(!stderr.includes('retrieval.dense_load_failed'), 'must stop at the gate, never read the model');
  } finally {
    rmSync(join(denseDir, 'config.json'), { force: true });
    rmSync(join(denseDir, 'tokenizer_config.json'), { force: true });
  }
});
