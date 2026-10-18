/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: first-call + calibration tests
 *
 * Pins the CH-37 first-call-success decomposition and the confidence-calibration
 * reliability machinery against fixed fixtures. Run:
 *   node --test dist/engine/eval/proof/firstcall.test.js
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessArgsValid, assessFirstCall, summarizeFirstCall } from './firstcall.js';
import type { SchemaResolver } from './firstcall.js';
import { reliabilityBins, expectedCalibrationError } from './calibration.js';
import type { CalibrationSample } from './calibration.js';
import type { PerQueryResult } from './types.js';

const close = (a: number, b: number, eps = 1e-9): boolean => Math.abs(a - b) < eps;

const noSchema: SchemaResolver = () => ({ hasInputSchema: false, reason: 'catalog-tool-has-no-input-schema' });
const hasSchema: SchemaResolver = () => ({ hasInputSchema: true });
const routedSchema: SchemaResolver = (toolId: string) =>
  toolId === 'svc:routed'
    ? { hasInputSchema: true }
    : { hasInputSchema: false, reason: 'catalog-tool-has-no-input-schema' };

const pqr = (over: Partial<PerQueryResult>): PerQueryResult => ({
  id: 'r',
  query: 'q',
  domain: 'x',
  style: 'natural-intent',
  relevantToolIds: ['svc:a'],
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

test('assessArgsValid: unknown with typed reason when no catalog schema', () => {
  const r = assessArgsValid('svc:a', noSchema);
  assert.equal(r.verdict, 'unknown');
  assert.equal(r.reason, 'catalog-tool-has-no-input-schema');
});

test('assessArgsValid: schema present but no generated args (LLM-free) → unknown, distinct reason', () => {
  const r = assessArgsValid('svc:a', hasSchema);
  assert.equal(r.verdict, 'unknown');
  assert.equal(r.reason, 'no-arg-generation-in-llm-free-selection-harness');
});

test('assessArgsValid: empty routed tool → unknown/no-routed-tool', () => {
  const r = assessArgsValid(undefined, noSchema);
  assert.equal(r.verdict, 'unknown');
  assert.equal(r.reason, 'no-routed-tool');
});

test('assessFirstCall: validates the routed tool, not the labeled tool', () => {
  const r = assessFirstCall(
    pqr({
      recallAtK: 1,
      relevantToolIds: ['svc:labeled'],
      returnedToolIds: ['svc:routed'],
    }),
    routedSchema,
  );
  assert.equal(r.routeCorrect, true);
  assert.equal(r.argsValid, 'unknown');
  assert.equal(r.argsValidReason, 'no-arg-generation-in-llm-free-selection-harness');
});

test('assessFirstCall: routeCorrect from full coverage; dispatch pending; firstCallSuccess null', () => {
  const correct = assessFirstCall(pqr({ recallAtK: 1 }), noSchema);
  assert.equal(correct.routeCorrect, true);
  assert.equal(correct.argsValid, 'unknown');
  assert.equal(correct.dispatchSucceeded, 'pending');
  assert.equal(correct.firstCallSuccess, null); // not determinable

  const partial = assessFirstCall(pqr({ recallAtK: 0.5 }), noSchema);
  assert.equal(partial.routeCorrect, false);
});

test('assessFirstCall: propagates bugRef + pendingP4', () => {
  const r = assessFirstCall(pqr({ recallAtK: 1, bugRef: 'biomedical-misroute-repro', pendingP4: true }), noSchema);
  assert.equal(r.bugRef, 'biomedical-misroute-repro');
  assert.equal(r.pendingP4, true);
});

test('summarizeFirstCall: routeCorrect rate + breakdowns + not-determinable', () => {
  const results = [
    pqr({ id: 'a', recallAtK: 1, returnedToolIds: ['svc:a'] }),
    pqr({ id: 'b', recallAtK: 1, returnedToolIds: ['svc:b'] }),
    pqr({ id: 'c', recallAtK: 0, returnedToolIds: ['svc:c'] }),
  ];
  const rep = summarizeFirstCall(results, 8, noSchema);
  assert.equal(rep.queryCount, 3);
  assert.equal(rep.routeCorrectCount, 2);
  assert.ok(close(rep.routeCorrectRate, 2 / 3));
  assert.equal(rep.argsValidBreakdown.unknown, 3);
  assert.equal(rep.argsValidBreakdown.valid, 0);
  assert.equal(rep.dispatchBreakdown.pending, 3);
  assert.equal(rep.firstCallSuccessDeterminable, false);
  assert.equal(rep.firstCallSuccessRate, null);
  assert.ok(rep.pendingReasons.includes('catalog-tool-has-no-input-schema'));
  assert.ok(rep.pendingReasons.includes('needs-phase4-hybrid-retriever-and-safe-dispatcher-fixture'));
});

// ─── calibration ─────────────────────────────────────────────────────────────

test('reliabilityBins: bins confidence vs route-correctness, exposes over-confidence', () => {
  const samples: CalibrationSample[] = [
    { confidence: 0.95, routeCorrect: false }, // bin9 — high conf, wrong (the 3.1.2 finding)
    { confidence: 0.91, routeCorrect: false }, // bin9
    { confidence: 0.85, routeCorrect: true },  // bin8
    { confidence: 0.2, routeCorrect: true },   // bin2
  ];
  const bins = reliabilityBins(samples, 10);
  assert.equal(bins.length, 10);
  const b9 = bins[9];
  assert.equal(b9.count, 2);
  assert.ok(close(b9.meanConfidence, 0.93));
  assert.equal(b9.routeCorrectRate, 0); // both wrong despite ~0.93 confidence
  assert.ok(close(b9.gap, 0.93));
  const b8 = bins[8];
  assert.equal(b8.count, 1);
  assert.equal(b8.routeCorrectRate, 1);
  assert.ok(close(b8.gap, 0.15));
  const b2 = bins[2];
  assert.equal(b2.count, 1);
  assert.ok(close(b2.gap, 0.8));
  // empty bins are zeroed
  assert.equal(bins[0].count, 0);
  assert.equal(bins[0].gap, 0);
});

test('reliabilityBins: top bin includes 1.0; non-finite confidence ignored; bad binCount throws', () => {
  const bins = reliabilityBins([{ confidence: 1, routeCorrect: true }], 10);
  assert.equal(bins[9].count, 1);
  const withNaN = reliabilityBins(
    [{ confidence: Number.NaN, routeCorrect: true }, { confidence: 0.55, routeCorrect: true }],
    10,
  );
  assert.equal(withNaN.reduce((a, b) => a + b.count, 0), 1); // NaN excluded
  assert.throws(() => reliabilityBins([], 0), RangeError);
});

test('expectedCalibrationError: count-weighted mean gap; 0 for empty', () => {
  const samples: CalibrationSample[] = [
    { confidence: 0.95, routeCorrect: false },
    { confidence: 0.91, routeCorrect: false },
    { confidence: 0.85, routeCorrect: true },
    { confidence: 0.2, routeCorrect: true },
  ];
  const ece = expectedCalibrationError(reliabilityBins(samples, 10));
  // (2/4)*0.93 + (1/4)*0.15 + (1/4)*0.8 = 0.7025
  assert.ok(close(ece, 0.7025));
  assert.equal(expectedCalibrationError(reliabilityBins([], 10)), 0);
});
