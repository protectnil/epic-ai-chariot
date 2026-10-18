/**
 * Epic AI® Chariot — requiresCustomerAuth segment unit tests (CHARIOT-SPEC §4.5)
 *
 * Derived from the clause's own failure enumeration, not from the
 * implementation's mental model:
 *   1. catalog has ZERO requiresCustomerAuth adapters → LOUD, explicit
 *      'no-adapters-present' with a catalog-population reason (never a
 *      silently-omitted section, never a fabricated 0/0 "measured").
 *   2. catalog HAS such adapters but the gold set labels none of their
 *      tools → LOUD, explicit 'no-adapters-present' with a DIFFERENT,
 *      gold-set-coverage reason (distinguishable from case 1).
 *   3. catalog has such adapters AND the gold set labels ≥1 → 'measured',
 *      with Recall@8 computed ONLY over that subset (pooled headline must
 *      not leak in queries outside the class).
 *
 * Run: node --test dist/engine/eval/proof/auth-segment.test.js
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildRequiresCustomerAuthSegment } from './auth-segment.js';
import type { PerQueryResult } from './types.js';

function fakeResult(id: string, relevantToolIds: string[], hitToolIds: string[]): PerQueryResult {
  return {
    id,
    query: `query ${id}`,
    domain: 'test',
    style: 'natural-intent',
    relevantToolIds,
    returnedToolIds: hitToolIds,
    hitToolIds,
    recallAtK: hitToolIds.length > 0 ? 1 : 0,
    precisionAtK: hitToolIds.length > 0 ? 1 / 8 : 0,
    ndcgAtK: hitToolIds.length > 0 ? 1 : 0,
    firstRelevantRank: hitToolIds.length > 0 ? 1 : null,
    reciprocalRank: hitToolIds.length > 0 ? 1 : 0,
    candidateSetSha256: 'deadbeef',
  };
}

test('§4.5 failure class 1: zero requiresCustomerAuth adapters in the catalog → LOUD catalog-population gap', () => {
  const perQuery = [fakeResult('GS-001', ['stripe:create_refund'], ['stripe:create_refund'])];
  const report = buildRequiresCustomerAuthSegment(perQuery, new Set(), 0, 8, 0.95);
  assert.equal(report.status, 'no-adapters-present');
  assert.equal(report.adapterCount, 0);
  assert.equal(report.queryCount, 0);
  assert.equal(report.metrics, undefined);
  assert.match(report.reason ?? '', /ZERO adapters flagged requiresCustomerAuth/);
  assert.match(report.reason ?? '', /CATALOG-POPULATION gap/);
});

test('§4.5 failure class 2: adapters present but gold set labels none of their tools → LOUD gold-set-coverage gap (distinct reason)', () => {
  // relevantToolIds never intersects the requiresCustomerAuth set.
  const perQuery = [fakeResult('GS-001', ['stripe:create_refund'], ['stripe:create_refund'])];
  const authToolIds = new Set(['authwalled-vendor:privileged_action']);
  const report = buildRequiresCustomerAuthSegment(perQuery, authToolIds, 3, 8, 0.95);
  assert.equal(report.status, 'no-adapters-present');
  assert.equal(report.adapterCount, 3);
  assert.equal(report.queryCount, 0);
  assert.equal(report.metrics, undefined);
  assert.match(report.reason ?? '', /GOLD-SET-COVERAGE gap/);
  // Must be a DIFFERENT reason than the zero-adapter case, so operators
  // can tell "nothing to label" apart from "labeled nothing".
  assert.doesNotMatch(report.reason ?? '', /ZERO adapters flagged/);
});

test('§4.5 measured case: Recall@8 computed ONLY over the requiresCustomerAuth subset, not the pooled set', () => {
  const authToolIds = new Set(['authwalled-vendor:privileged_action']);
  const perQuery = [
    fakeResult('GS-001', ['stripe:create_refund'], ['stripe:create_refund']), // NOT in the auth class
    fakeResult('GS-002', ['authwalled-vendor:privileged_action'], []), // IN the auth class, a MISS
    fakeResult('GS-003', ['authwalled-vendor:privileged_action'], ['authwalled-vendor:privileged_action']), // IN the auth class, a HIT
  ];
  const report = buildRequiresCustomerAuthSegment(perQuery, authToolIds, 1, 8, 0.95);
  assert.equal(report.status, 'measured');
  assert.equal(report.adapterCount, 1);
  assert.equal(report.queryCount, 2, 'only GS-002/GS-003 are in the requiresCustomerAuth class');
  assert.ok(report.metrics);
  // Macro recall over the 2-query subset: one hit (1.0), one miss (0.0) → 0.5.
  // The pooled 3-query set (with GS-001's unrelated hit) must NOT leak in and
  // inflate this to a higher number.
  assert.equal(report.metrics?.macroRecallAtK, 0.5);
  assert.equal(report.metrics?.queryCount, 2);
});

test('boundary: a query with mixed relevantToolIds (some in-class, some not) is counted IN the subset', () => {
  const authToolIds = new Set(['authwalled-vendor:privileged_action']);
  const perQuery = [
    fakeResult(
      'GS-CROSS',
      ['stripe:create_refund', 'authwalled-vendor:privileged_action'],
      ['authwalled-vendor:privileged_action'],
    ),
  ];
  const report = buildRequiresCustomerAuthSegment(perQuery, authToolIds, 1, 8, 0.95);
  assert.equal(report.status, 'measured');
  assert.equal(report.queryCount, 1);
});
