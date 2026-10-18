import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertModelIdentity } from './build-edgeshard-snapshot.js';
import { loadNativeEdge, type NativeTokenizerFiles } from '../retrieval/nativeEdge.js';

// CHARIOT §5.6 delegates the byte-level sparse artifact pin to the shared
// shared/splade/artifact-pin.ts. Keep the release test pointed at that exact
// verified snapshot; a different export with the same model identity is not a
// substitute.
const GOVERNED = process.env.CHARIOT_SPLADE_ARTIFACT_DIR
  ?? '/opt/bien/artifacts/fe-cache/models--Qdrant--Splade_PP_en_v1/snapshots/efcd182bc7eb351e81a9445752d4388c2bab500b';
const REJECTED = '/opt/bien/artifacts/m8-landing-20260730/splade-pin';
const REQUIRED_FILES = ['model.onnx', 'tokenizer.json', 'config.json', 'special_tokens_map.json', 'tokenizer_config.json'] as const;
const artifactsPresent = [GOVERNED, REJECTED].every(dir => REQUIRED_FILES.every(file => existsSync(join(dir, file))));
const releaseGateRequired = process.env.CHARIOT_REQUIRE_SPLADE_ARTIFACT === '1';

type SparseModel = Parameters<typeof assertModelIdentity>[0];

function loadModel(dir: string): SparseModel {
  const read = (name: string): Buffer => readFileSync(join(dir, name));
  const tokenizerFiles: NativeTokenizerFiles = {
    tokenizerFile: read('tokenizer.json'),
    configFile: read('config.json'),
    specialTokensMapFile: read('special_tokens_map.json'),
    tokenizerConfigFile: read('tokenizer_config.json'),
  };
  return { onnx: read('model.onnx'), tokenizerFiles } as SparseModel;
}

test('release sparse artifact pin loads and embeds; the non-conforming export is rejected', {
  skip: !artifactsPresent && !releaseGateRequired ? 'real SPLADE artifacts are absent; release gate sets CHARIOT_REQUIRE_SPLADE_ARTIFACT=1' : false,
  timeout: 180_000,
}, () => {
  assert.ok(artifactsPresent, 'CHARIOT_REQUIRE_SPLADE_ARTIFACT=1 requires both governed and negative-control artifacts');

  const governed = loadModel(GOVERNED);
  const rejected = loadModel(REJECTED);
  assert.doesNotThrow(() => assertModelIdentity(governed, 'sparse'));
  assert.throws(() => assertModelIdentity(rejected, 'sparse'), /sparse encoder artifact identity mismatch/);

  const native = loadNativeEdge();
  assert.ok(native?.SpladeEncoder, 'release gate requires the current native SpladeEncoder');
  // The 2026-10-15 defect: the 0934583a export loaded and failed only at the
  // first embed ("Invalid input name: attention_mask"). The rebuilt native
  // must refuse it inside load() — before any inference.
  assert.throws(
    () => native.SpladeEncoder!.load(rejected.onnx, rejected.tokenizerFiles, 512),
    /SPLADE graph signature mismatch/,
    'native must refuse the non-conforming graph at load, not at the first embed',
  );
  const encoder = native.SpladeEncoder.load(governed.onnx, governed.tokenizerFiles, 512);
  const text = 'search_query: github repository and pull request management';
  const first = encoder.embed([text])[0];
  const second = encoder.embed([text])[0];

  assert.ok(first.indices.length > 0, 'real governed artifact must produce a non-empty sparse vector');
  assert.equal(first.indices.length, first.values.length);
  assert.ok(first.values.every(Number.isFinite));
  assert.deepEqual(first.indices, [...first.indices].sort((a, b) => a - b));
  assert.deepEqual(second, first, 'real governed artifact must be deterministic across calls');
});
