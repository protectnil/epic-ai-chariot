import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { assertModelIdentity, denseMaxLengthFromExport, PRODUCER_SHARD_CONFIG_JSON } from './build-edgeshard-snapshot.js';
import { loadNativeEdge } from '../retrieval/nativeEdge.js';

// CHARIOT::§23.2::181: the dense max length is the export's own
// max_position_embeddings, never assumed. BIEN::§3::9 / BIEN::§9::4: one
// byte-identical model on the document and query sides.

type Model = Parameters<typeof denseMaxLengthFromExport>[0];

function model(config: unknown, tokenizerConfig: unknown): Model {
  const buf = (v: unknown): Buffer => Buffer.from(JSON.stringify(v));
  return {
    onnx: Buffer.alloc(0),
    tokenizerFiles: { tokenizerFile: Buffer.alloc(0), configFile: buf(config), specialTokensMapFile: Buffer.alloc(0), tokenizerConfigFile: buf(tokenizerConfig) },
  } as Model;
}

test('dense max length is read from the export config and agrees across both files', () => {
  assert.equal(denseMaxLengthFromExport(model({ max_position_embeddings: 2048 }, { model_max_length: 2048 })), 2048);
});

test('dense max length fails closed when the files disagree, are missing, or are not a positive integer', () => {
  const bad: Array<[unknown, unknown]> = [
    [{ max_position_embeddings: 2048 }, { model_max_length: 512 }],
    [{ max_position_embeddings: 2048 }, {}],
    [{}, { model_max_length: 2048 }],
    [{ max_position_embeddings: '2048' }, { model_max_length: '2048' }],
    [{ max_position_embeddings: 0 }, { model_max_length: 0 }],
    [{ max_position_embeddings: -1 }, { model_max_length: -1 }],
    [{ max_position_embeddings: 20.5 }, { model_max_length: 20.5 }],
    [{ max_position_embeddings: null }, { model_max_length: null }],
  ];
  for (const [c, t] of bad) assert.throws(() => denseMaxLengthFromExport(model(c, t)), /max length/);
});

const EXPORTS = '/opt/bien/artifacts/m8-landing-20260730';
const MINED = join(EXPORTS, 'bien-m8-export-mined-v2');
const CANON = join(EXPORTS, 'bien-m8-export');
const present = existsSync(join(MINED, 'dim_768/model.onnx')) && existsSync(join(CANON, 'dim_768/model.onnx'));

function load(onnx: string, dir: string): Model {
  const f = (n: string): Buffer => readFileSync(join(dir, n));
  return { onnx: readFileSync(onnx), tokenizerFiles: { tokenizerFile: f('tokenizer.json'), configFile: f('config.json'), specialTokensMapFile: f('special_tokens_map.json'), tokenizerConfigFile: f('tokenizer_config.json') } } as Model;
}

test('the gated mined-v2 export is accepted and yields 2048; the ungated canonical export is rejected', { skip: !present }, () => {
  const mined = load(join(MINED, 'dim_768/model.onnx'), join(MINED, 'tokenizer'));
  assert.doesNotThrow(() => assertModelIdentity(mined, 'dense'));
  assert.equal(denseMaxLengthFromExport(mined), 2048);
  const canon = load(join(CANON, 'dim_768/model.onnx'), CANON);
  assert.throws(() => assertModelIdentity(canon, 'dense'), /dense encoder artifact identity mismatch/);
});

// The producer's shard config must be accepted by the REAL native addon's
// EdgeConfig parser (qdrant-edge 0.7.2), not only by fake bindings.
test('producer shard config creates a real Edge shard', { skip: !loadNativeEdge() }, () => {
  const native = loadNativeEdge()!;
  // Same as buildSnapshot: the shard directory exists (0700) before create.
  const dir = mkdtempSync(join(tmpdir(), 'producer-shard-config-'));
  const shard = native.EdgeShardHandle.create(dir, PRODUCER_SHARD_CONFIG_JSON);
  try {
    assert.equal(shard.pointsCount(), 0);
  } finally {
    shard.close?.();
  }
});
