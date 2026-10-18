#!/usr/bin/env node

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertModelIdentity } from '../dist/engine/bin/build-edgeshard-snapshot.js';
import { loadNativeEdge } from '../dist/engine/retrieval/nativeEdge.js';

const dir = process.env.CHARIOT_SPLADE_ARTIFACT_DIR;
if (!dir) throw new Error('CHARIOT_SPLADE_ARTIFACT_DIR is required for the SPLADE release-artifact gate');

const read = name => {
  const path = join(dir, name);
  if (!existsSync(path)) throw new Error(`governed SPLADE artifact file is missing: ${name}`);
  return readFileSync(path);
};
const model = {
  onnx: read('model.onnx'),
  tokenizerFiles: {
    tokenizerFile: read('tokenizer.json'),
    configFile: read('config.json'),
    specialTokensMapFile: read('special_tokens_map.json'),
    tokenizerConfigFile: read('tokenizer_config.json'),
  },
};

assertModelIdentity(model, 'sparse');
const native = loadNativeEdge();
assert.ok(native?.SpladeEncoder, 'current verified native binary must expose SpladeEncoder');
const encoder = native.SpladeEncoder.load(model.onnx, model.tokenizerFiles, 512);
const text = 'search_query: github repository and pull request management';
const first = encoder.embed([text])[0];
const second = encoder.embed([text])[0];
assert.ok(first.indices.length > 0, 'governed SPLADE artifact produced an empty sparse vector');
assert.equal(first.indices.length, first.values.length, 'SPLADE indices/values length mismatch');
assert.ok(first.values.every(Number.isFinite), 'SPLADE vector contains a non-finite value');
assert.deepEqual(first.indices, [...first.indices].sort((a, b) => a - b), 'SPLADE indices are not ascending');
assert.deepEqual(second, first, 'SPLADE embedding is not deterministic across calls');
console.log('SPLADE_RELEASE_ARTIFACT_OK');
