/**
 * Prove-on-revert for CHARIOT §4.1::4 — "The cross-encoder model specified in
 * BIEN §7 SHALL be LOCKED and SHALL NOT be substituted with any alternative
 * model."
 *
 * BIEN lock, BIEN SPEC.md §7 (verbatim):
 *   "locks `cross-encoder/ms-marco-MiniLM-L6-v2` as the shipped reranker base
 *    and `cross-encoder/ms-marco-MiniLM-L12-v2` as the build-time distillation
 *    teacher."
 *
 * Defect this catches: loadRerankScorer() loaded whatever ONNX + tokenizer
 * files happened to sit at the operator-supplied CHARIOT_RERANKER_DIR, with no
 * model-identity check against a compiled-in constant — exactly the
 * "configuration path accepting a substitute cross-encoder" the node forbids.
 *
 * Note the distillation TEACHER (L12) must be rejected as hard as any unrelated
 * model: it is a build-time artifact, never the shipped runtime reranker.
 *
 * Uses only a config.json buffer, so it needs none of the ~90MB model artifacts.
 *
 * Run (after tsc): node --test dist/engine/server/ChariotState.reranker-lock.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { assertShippedRerankerModel, SHIPPED_RERANKER_MODEL } from './ChariotState.js';

const config = (value: unknown): Buffer => Buffer.from(JSON.stringify(value), 'utf8');

test('§4.1::4: the locked model constant is the BIEN §7 shipped reranker base', () => {
  assert.equal(SHIPPED_RERANKER_MODEL, 'cross-encoder/ms-marco-MiniLM-L6-v2');
});

test('§4.1::4: the shipped reranker identity is accepted', () => {
  assert.doesNotThrow(() =>
    assertShippedRerankerModel(config({ _name_or_path: 'cross-encoder/ms-marco-MiniLM-L6-v2' })),
  );
});

test('§4.1::4: the build-time distillation teacher (L12) is REJECTED', () => {
  assert.throws(
    () => assertShippedRerankerModel(config({ _name_or_path: 'cross-encoder/ms-marco-MiniLM-L12-v2' })),
    /model identity mismatch/,
  );
});

test('§4.1::4: an unrelated cross-encoder is rejected', () => {
  assert.throws(
    () => assertShippedRerankerModel(config({ _name_or_path: 'BAAI/bge-reranker-base' })),
    /model identity mismatch/,
  );
});

test('§4.1::4: a missing model identity fails closed', () => {
  assert.throws(() => assertShippedRerankerModel(config({})), /model identity mismatch/);
});

test('§4.1::4: malformed config.json fails closed', () => {
  assert.throws(() => assertShippedRerankerModel(Buffer.from('{', 'utf8')), /not valid UTF-8 JSON/);
});
