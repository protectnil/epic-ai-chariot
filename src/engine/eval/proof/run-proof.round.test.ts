/**
 * Epic AI® Chariot — run-proof.ts `roundPerQuery` serialization unit test
 *
 * Gate finding (thread 01a07352): `roundPerQuery` rounded recallAtK/
 * precisionAtK/reciprocalRank but NOT the newly-added `ndcgAtK`, so a
 * serialized proof-artifact row could carry an unrounded ndcgAtK while every
 * sibling metric was rounded to 4 decimals. This pins that `ndcgAtK` is
 * rounded identically to the other per-query metrics.
 *
 * `run-proof.ts`'s `main()` is guarded to run only when the module is the
 * process entrypoint (see the `isMainModule` check at the bottom of that
 * file), so importing it here for `roundPerQuery` does not trigger the full
 * production-catalog + gold-set pipeline.
 *
 * Run: node --test dist/engine/eval/proof/run-proof.round.test.js
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { roundPerQuery } from './run-proof.js';
import { round } from './metrics.js';
import type { PerQueryResult } from './types.js';

const pqr = (over: Partial<PerQueryResult>): PerQueryResult => ({
  id: 'r',
  query: 'q',
  domain: 'x',
  style: 'natural-intent',
  relevantToolIds: ['a'],
  returnedToolIds: [],
  hitToolIds: [],
  recallAtK: 0,
  precisionAtK: 0,
  ndcgAtK: 0,
  firstRelevantRank: null,
  reciprocalRank: 0,
  candidateSetSha256: 'x',
  ...over,
});

test('roundPerQuery rounds ndcgAtK to 4 decimals, matching recallAtK/precisionAtK/reciprocalRank', () => {
  const unrounded = pqr({
    recallAtK: 0.123456789,
    precisionAtK: 0.987654321,
    ndcgAtK: 0.333333333,
    reciprocalRank: 0.166666666,
  });
  const rounded = roundPerQuery(unrounded);
  assert.equal(rounded.recallAtK, round(0.123456789));
  assert.equal(rounded.precisionAtK, round(0.987654321));
  assert.equal(rounded.ndcgAtK, round(0.333333333));
  assert.equal(rounded.ndcgAtK, 0.3333);
  assert.equal(rounded.reciprocalRank, round(0.166666666));
});

test('roundPerQuery preserves every other field unchanged (identity fields, ids, flags)', () => {
  const input = pqr({ id: 'GS-042', bugRef: 'biomedical-misroute-repro', pendingP4: true, ndcgAtK: 1 });
  const out = roundPerQuery(input);
  assert.equal(out.id, 'GS-042');
  assert.equal(out.bugRef, 'biomedical-misroute-repro');
  assert.equal(out.pendingP4, true);
  assert.equal(out.ndcgAtK, 1);
});
