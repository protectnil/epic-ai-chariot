/**
 * CH-10-adjacent (not vault) — BIEN dense-encoder pooling-MODE INERTNESS.
 *
 * `ChariotState.ts` (`loadDenseEncoder`, CHARIOT §8.6 step 2) requires the
 * operator to set `CHARIOT_DENSE_POOLING` to `'mean'` or `'cls'`, warning:
 * "§17 bakes mean-pooling + L2 into the exported ONNX graph so the graph
 * output IS the final embedding, but fastembed's ... pooling mode ... picking
 * the wrong one silently produces a different vector space from the freeze
 * side." `native/src/encoder.rs::validate_dense_vector` (encoder.rs:107-133)
 * independently asserts the emitted vector is unit-L2-normalized (tolerance
 * 1e-3) and REJECTS (throws, does not silently accept) any vector that is
 * not — "a non-unit norm means the wrong pooling mode or the wrong export."
 *
 * Rulings item 108 (verification round 2, 2026-09-04 17:05): this test ran
 * against the canonical `bien-m8-export` artifact and BOTH pooling modes
 * produced a unit-norm 768-d vector — `{"mean":{"passed":true,"dims":768},
 * "cls":{"passed":true,"dims":768}}`. Because the ONNX graph already emits
 * the pooled, normalized embedding (BIEN's own export step bakes
 * mean-pooling + L2-normalization into the graph), fastembed's own pooling
 * mode has nothing left to pool over on a single already-pooled output
 * vector — it degenerates to a pass-through regardless of which mode is
 * selected, so it is INERT on this export, not a live double-pool hazard.
 * `CHARIOT_DENSE_POOLING=mean` is pinned in the Dockerfile on the strength
 * of this proof (matches the export's own baked mode; any other value would
 * be equally correct on THIS artifact, but `mean` is the one that also
 * matches the export's actual algorithm, so it is not an arbitrary choice
 * between equals).
 *
 * This test's job is now REGRESSION coverage of that inertness claim, not
 * discovery: it asserts BOTH modes still (a) pass `validate_dense_vector`
 * (unit-norm) and (b) produce numerically IDENTICAL vectors (element-wise,
 * within 1e-6) for the same fixed input. A future export that is NOT
 * pre-pooled would make the two modes diverge (mean pools token embeddings,
 * cls does not) — THAT divergence, not merely one mode's failure, is the
 * condition this test exists to catch, since divergence-without-failure is
 * exactly the silent-corruption case `loadDenseEncoder()`'s own warning
 * describes and `validate_dense_vector`'s unit-norm check alone cannot
 * detect (two different unit vectors both pass that check).
 *
 * REQUIRES the real, licensed BIEN dense-encoder export on disk — a
 * proprietary model artifact, never checked into this public repo. Every
 * path is read from environment variables; the test SKIPS itself (does not
 * fail) when they are unset, so it is inert in ordinary CI. To run it for
 * real: point `BIEN_DENSE_TEST_ONNX_PATH` at the exported `model.onnx` and
 * `BIEN_DENSE_TEST_TOKENIZER_DIR` at the directory holding `tokenizer.json`,
 * `config.json`, `special_tokens_map.json`, `tokenizer_config.json` (the BIEN
 * export's tokenizer files live alongside the export root, NOT inside the
 * per-width `dim_768/` subdirectory that holds only the `.onnx` files —
 * these two env vars let the test point at each without requiring a
 * pre-staged flat directory).
 *
 * Run (after `npm run build` and `tsc`; the lead runs this, not a builder —
 * see COMMON.md host budget):
 *   BIEN_DENSE_TEST_ONNX_PATH=<...>/dim_768/model.onnx \
 *   BIEN_DENSE_TEST_TOKENIZER_DIR=<...> \
 *   node --test dist/engine/retrieval/denseEncoder.pooling-mode.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const { loadNativeEdge } = await import('./nativeEdge.js');

function readTokenizerFiles(dir: string) {
  const read = (name: string) => readFileSync(join(dir, name));
  return {
    tokenizerFile: read('tokenizer.json'),
    configFile: read('config.json'),
    specialTokensMapFile: read('special_tokens_map.json'),
    tokenizerConfigFile: read('tokenizer_config.json'),
  };
}

test('BIEN dense encoder: fastembed pooling mode is inert on the shipped (pre-pooled) export — both modes agree', async (t) => {
  const onnxPath = process.env.BIEN_DENSE_TEST_ONNX_PATH;
  const tokenizerDir = process.env.BIEN_DENSE_TEST_TOKENIZER_DIR;
  if (!onnxPath || !tokenizerDir || !existsSync(onnxPath) || !existsSync(tokenizerDir)) {
    t.skip(
      'BIEN_DENSE_TEST_ONNX_PATH / BIEN_DENSE_TEST_TOKENIZER_DIR not set or not found — ' +
      'this test requires the real, licensed BIEN dense-encoder export, which is never ' +
      'checked into this repo. Set both env vars to the export paths to run it for real.',
    );
    return;
  }

  const native = loadNativeEdge();
  if (!native || typeof native.DenseEncoder?.load !== 'function') {
    t.skip('native chariot-native.node binding with DenseEncoder is not loadable in this environment.');
    return;
  }

  const onnxFile = readFileSync(onnxPath);
  const tokenizerFiles = readTokenizerFiles(tokenizerDir);
  // BIEN SPEC.md §9's tokenizer_config.json / config.json pin
  // `max_position_embeddings` / `max_length` = 2048 for the shipped export
  // (read directly from the artifact's own tokenizer_config.json at the time
  // this test was written) — kept here as a literal so the test fails loudly
  // if the wrong export is pointed at, rather than silently truncating
  // differently than the freeze side did.
  const EXPECTED_MAX_LENGTH = 2048;
  const FIXED_INPUT = 'search_document: chariot vault credential rotation tool';

  const attempt = (meanPool: boolean): { ok: true; vector: number[] } | { ok: false; error: string } => {
    try {
      const encoder = native.DenseEncoder.load(onnxFile, tokenizerFiles, meanPool, EXPECTED_MAX_LENGTH);
      const [vector] = encoder.embed([FIXED_INPUT]);
      return { ok: true, vector: vector! };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  };

  const meanResult = attempt(true);
  const clsResult = attempt(false);

  // Report BOTH outcomes regardless of what they are — the point of this
  // test is to prove/regress the INERTNESS claim, and a partial report
  // (only one mode) could not do that.
  const report = {
    mean: meanResult.ok
      ? { passed: true, dims: meanResult.vector.length }
      : { passed: false, error: meanResult.error },
    cls: clsResult.ok
      ? { passed: true, dims: clsResult.vector.length }
      : { passed: false, error: clsResult.error },
  };
  console.log('BIEN dense pooling-mode inertness result:', JSON.stringify(report, null, 2));

  // Rulings item 108: BOTH modes must pass validate_dense_vector's
  // unit-norm check (encoder.rs:107-133) — the export is pre-pooled, so
  // there is nothing for fastembed's OWN pooling mode to reject either
  // way. A mode that throws here means the export is NOT pre-pooled the
  // way this test (and the CHARIOT_DENSE_POOLING=mean Dockerfile pin) both
  // assume, which is itself a finding worth surfacing loudly, not masking.
  assert.ok(meanResult.ok, `mean pooling must pass validate_dense_vector on a pre-pooled export; got: ${!meanResult.ok ? meanResult.error : 'n/a'}`);
  assert.ok(clsResult.ok, `cls pooling must pass validate_dense_vector on a pre-pooled export; got: ${!clsResult.ok ? clsResult.error : 'n/a'}`);
  assert.equal(meanResult.vector.length, 768, 'CHARIOT-SPEC §5.6 encoder.denseDims pin');
  assert.equal(clsResult.vector.length, 768, 'CHARIOT-SPEC §5.6 encoder.denseDims pin');

  // THE inertness assertion. On a genuinely pre-pooled export, both modes
  // read the SAME already-pooled graph output straight through, so their
  // vectors must be numerically identical (not merely both unit-norm — two
  // DIFFERENT unit vectors would both pass the norm check and still be the
  // wrong-vector-space bug this whole test exists to catch). A NON-pre-pooled
  // export would make mean (pools token embeddings) and cls (does not)
  // diverge element-wise while both still individually satisfy the norm
  // check — that divergence, not a thrown error, is the failure mode this
  // assertion is built to detect.
  const maxAbsDiff = meanResult.vector.reduce(
    (max, v, i) => Math.max(max, Math.abs(v - clsResult.vector[i]!)),
    0,
  );
  assert.ok(
    maxAbsDiff <= 1e-6,
    `expected mean and cls pooling to produce numerically identical vectors (max abs diff <= 1e-6) ` +
    `on a pre-pooled export — got max abs diff ${maxAbsDiff}. Both modes individually passed the ` +
    `unit-norm check, so this is NOT the "wrong pooling mode throws" failure — it is the export at ` +
    `${onnxPath} NOT being pre-pooled the way CHARIOT_DENSE_POOLING=mean (Dockerfile) assumes: mean ` +
    `and cls are computing genuinely different pooled vectors over token embeddings, meaning fastembed's ` +
    `pooling mode is live (not inert) on this export and the WRONG choice silently produces a different, ` +
    `still-unit-norm vector space from the freeze side — exactly the failure mode loadDenseEncoder()'s ` +
    `own warning describes.`,
  );
});
