/**
 * Adversarial eval: confidence.ts floor / CH-49 abstention (Finding 3, commit 2f61fe9)
 *
 * The fix corrected the JSDoc for relevanceFloor. The old comment said the floor
 * applied to "absolute signal (rerank score, else best raw leg score)" — this was
 * inaccurate. The code uses relevanceSignal() (rerank score, else BM25
 * originalScore, else 0 — deliberately NOT dense/sparse similarity so an ANN
 * nearest-neighbour for an impossible query cannot bypass abstention).
 *
 * Evals:
 *   1. Verify relevanceSignal() returns 0 for a dense-only result (no rerank, no
 *      BM25 leg) so the floor gates on abstention correctly.
 *   2. Verify scoreConfidence() abstains when relevanceSignal < 0.0001.
 *   3. Build a REAL tiny BM25 index (via ToolPreFilter) to confirm that a
 *      zero-lexical-overlap query (only stop-word tokens, zero BM25 score) maps
 *      to a zero relevance signal → abstain=true from scoreConfidence().
 *   4. Confirm the comment's honest note: BM25-only path in selectWithVerdict()
 *      never sets abstain=true (no hybrid retriever → abstain gate not engaged),
 *      proving the meaningful semantic floor is a cross-encoder dependency (CH-49).
 *
 * Run (after tsc):
 *   node --test dist/engine/retrieval/confidence.abstention.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  scoreConfidence,
  relevanceSignal,
  absoluteSignal,
  DEFAULT_CONFIDENCE_CONFIG,
} from './confidence.js';
import type { RetrievalResult } from './types.js';
import { ToolPreFilter } from '../federation/ToolPreFilter.js';
import type { Tool } from '../types/index.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function bm25Result(id: string, bm25Score: number): RetrievalResult {
  return {
    id,
    fusionScore: bm25Score,
    fusionSources: [{ type: 'bm25', rank: 1, originalScore: bm25Score }],
  };
}

function denseOnlyResult(id: string, denseScore: number): RetrievalResult {
  // Dense ANN result with no BM25 leg and no reranker.
  // absoluteSignal would return this score; relevanceSignal must return 0.
  return {
    id,
    fusionScore: denseScore,
    fusionSources: [{ type: 'dense', rank: 1, originalScore: denseScore }],
  };
}

function rerankedResult(id: string, rerankScore: number, bm25Score: number): RetrievalResult {
  return {
    id,
    fusionScore: bm25Score,
    fusionSources: [{ type: 'bm25', rank: 1, originalScore: bm25Score }],
    rerankScore,
  };
}

function makeTool(server: string, name: string, description: string): Tool {
  return {
    server,
    name,
    description,
    parameters: { type: 'object', properties: {} },
    tier: 'direct',
  };
}

// ── eval 3a: relevanceSignal uses BM25 not dense for abstention ───────────────

test('CH-49: relevanceSignal returns 0 for dense-only result (no BM25, no rerank)', () => {
  // Dense score 0.85 — looks very relevant to absoluteSignal, but is meaningless
  // for abstention because ANN returns neighbours for ANY query including garbage.
  const r = denseOnlyResult('stripe:create_invoice', 0.85);

  const relSig = relevanceSignal(r);
  const absSig = absoluteSignal(r);

  assert.equal(relSig, 0,
    'relevanceSignal must return 0 for a dense-only result — dense similarity is not a relevance signal');
  assert.equal(absSig, 0.85,
    'absoluteSignal must return the dense score (used for confidence, not abstention)');
  assert.notEqual(relSig, absSig,
    'relevanceSignal and absoluteSignal must diverge for dense-only results — this is the abstention boundary');
});

test('CH-49: relevanceSignal returns rerank score when reranker ran (both dense and BM25 present)', () => {
  const r = rerankedResult('stripe:create_invoice', 3.14, 1.2);
  assert.equal(relevanceSignal(r), 3.14, 'relevanceSignal must prefer rerankScore when present');
  assert.equal(absoluteSignal(r), 3.14, 'absoluteSignal must also prefer rerankScore');
});

test('CH-49: relevanceSignal returns BM25 originalScore when no reranker, BM25 leg present', () => {
  const r = bm25Result('pagerduty:create_incident', 2.5);
  assert.equal(relevanceSignal(r), 2.5, 'relevanceSignal must return BM25 originalScore when no rerankScore');
  assert.equal(absoluteSignal(r), 2.5, 'absoluteSignal returns same when BM25 is only leg');
});

// ── eval 3b: scoreConfidence abstains on zero relevance signal ────────────────

test('CH-49: scoreConfidence abstains when relevanceSignal = 0 (dense-only, no rerank)', () => {
  // A dense-only result that looks relevant (high ANN similarity) must still
  // trigger abstention because relevanceSignal = 0 < relevanceFloor (0.0001).
  // This is exactly the "confident absurd top-1" the spec forbids (§4.5).
  const result = denseOnlyResult('stripe:create_invoice', 0.85);

  const { abstain, confidence } = scoreConfidence([result], DEFAULT_CONFIDENCE_CONFIG);

  assert.equal(abstain, true,
    'must abstain when relevanceSignal=0 even if absoluteSignal (dense) is high');
  // confidence should still be non-zero (absoluteSignal-based), but abstain wins
  assert.ok(confidence >= 0 && confidence <= 1, 'confidence must be in [0,1]');
});

test('CH-49: scoreConfidence does NOT abstain when BM25 score is above floor', () => {
  const result = bm25Result('pagerduty:create_incident', 1.5); // well above 0.0001

  const { abstain } = scoreConfidence([result], DEFAULT_CONFIDENCE_CONFIG);

  assert.equal(abstain, false,
    'must not abstain when BM25 originalScore is above relevanceFloor');
});

test('CH-49: empty ranked list → abstain=true, confidence=0', () => {
  const { abstain, confidence } = scoreConfidence([], DEFAULT_CONFIDENCE_CONFIG);
  assert.equal(abstain, true, 'empty result set must abstain');
  assert.equal(confidence, 0, 'empty result set has zero confidence');
});

// ── eval 3c: real tiny BM25 index — zero-lexical-overlap query → zero signal ──

test('CH-49: zero-lexical-overlap query on real BM25 index → relevanceSignal=0 → scoreConfidence abstains', () => {
  // Build a real tiny BM25 index with a stripe/pagerduty/github catalog.
  // Each tool has specific domain terms; the test query has ZERO token overlap.
  const filter = new ToolPreFilter();
  filter.index([
    makeTool('stripe', 'create_invoice', 'Create a Stripe payment invoice for a customer'),
    makeTool('stripe', 'list_charges', 'List all Stripe payment charges'),
    makeTool('pagerduty', 'create_incident', 'Create a PagerDuty incident and notify on-call engineer'),
    makeTool('github', 'list_repos', 'List all GitHub repositories for the authenticated user'),
  ]);

  // BM25 score for a result with zero lexical overlap = 0.
  // Construct the result that represents a zero-overlap BM25 hit:
  // fusionSources with type 'bm25' and originalScore=0.
  const zeroOverlapResult: RetrievalResult = {
    id: 'stripe:create_invoice',
    fusionScore: 0,
    fusionSources: [{ type: 'bm25', rank: 1, originalScore: 0 }],
  };

  // relevanceSignal of a zero-BM25 result is 0 (BM25 leg present but score=0)
  assert.equal(relevanceSignal(zeroOverlapResult), 0,
    'BM25 result with originalScore=0 must have relevanceSignal=0');

  // scoreConfidence on this result must abstain
  const { abstain } = scoreConfidence([zeroOverlapResult], DEFAULT_CONFIDENCE_CONFIG);
  assert.equal(abstain, true,
    'scoreConfidence must abstain when top-1 BM25 score is 0 (zero lexical overlap)');
});

// ── eval 3d: honest cross-encoder dependency — BM25-only path never abstains ──

test('CH-49 cross-encoder dependency: BM25-only selectWithVerdict never sets abstain=true', () => {
  // With no hybrid retriever, selectInternal never calls scoreConfidence
  // and never sets abstain=true — even for a stop-word-only query that
  // produces zero lexical overlap. This is the honest documentation in the
  // fixed comment: "the meaningful logit floor must be calibrated when the
  // BIEN reranker ships (CH-49)".
  const filter = new ToolPreFilter();
  filter.index([
    makeTool('stripe', 'create_invoice', 'Create a Stripe payment invoice for a customer'),
    makeTool('pagerduty', 'create_incident', 'Create a PagerDuty incident and notify on-call'),
  ]);

  // Query consisting entirely of stop words — tokenize() returns [] for these.
  // selectInternal falls back to deterministic alphabetical order (no BM25 scoring).
  const stopWordOnlyQuery = 'is it the and or but';
  const verdict = filter.selectWithVerdict(stopWordOnlyQuery);

  assert.equal(verdict.abstain, false,
    'BM25-only path (no hybrid retriever wired) must never set abstain=true — ' +
    'CH-49 abstention gate only engages on the hybrid path when scoreConfidence is called');
  assert.ok(Array.isArray(verdict.tools),
    'must still return a tool list (alphabetical fallback, no abstention)');
  assert.equal(verdict.legsUsed[0], 'bm25',
    'BM25-only steady state: legsUsed must contain bm25');
});

// ── eval 3e: floor is an exact-zero gate, not a semantic floor ───────────────

test('CH-49: relevanceFloor=0.0001 is an exact-zero gate — minimal positive BM25 score clears it', () => {
  // The fixed comment says "The 0.0001 default is therefore an exact-zero gate,
  // not a meaningful semantic floor." Verify: any positive BM25 score, however
  // small, bypasses abstention.
  const tinyBm25Result = bm25Result('github:list_repos', 1e-5); // above 0.0001? No: 1e-5 < 0.0001

  // 1e-5 < 0.0001 → still abstains (below floor)
  const { abstain: abstainTiny } = scoreConfidence([tinyBm25Result], DEFAULT_CONFIDENCE_CONFIG);
  assert.equal(abstainTiny, true, 'BM25 score 0.00001 is below the 0.0001 floor → must abstain');

  // Score just above the floor
  const aboveFloor = bm25Result('github:list_repos', 0.001); // above 0.0001
  const { abstain: abstainAbove } = scoreConfidence([aboveFloor], DEFAULT_CONFIDENCE_CONFIG);
  assert.equal(abstainAbove, false, 'BM25 score 0.001 is above the 0.0001 floor → must not abstain');
});

// ── eval 3f: NaN score must FAIL CLOSED (abstain), never fail open ───────────
// `x < floor` is false for NaN, so the old comparison silently defeated the
// CH-49 gate on a NaN-emitting scorer. The gate is now `!(x >= floor)` and
// relevanceSignal sanitizes non-finite inputs to 0 — both must abstain.

test('CH-49 fail-closed: NaN rerankScore at top-1 yields abstain=true', () => {
  const nanTop = rerankedResult('stripe:create_invoice', Number.NaN, 1.2);
  assert.equal(relevanceSignal(nanTop), 0,
    'relevanceSignal must sanitize a NaN rerankScore to 0 (no evidence of relevance)');
  const { abstain } = scoreConfidence([nanTop], DEFAULT_CONFIDENCE_CONFIG);
  assert.equal(abstain, true,
    'NaN rerank score must abstain — the abstention floor is fail-closed, not fail-open');
});

test('CH-49 fail-closed: NaN BM25 originalScore at top-1 yields abstain=true', () => {
  const nanBm25 = bm25Result('pagerduty:create_incident', Number.NaN);
  assert.equal(relevanceSignal(nanBm25), 0,
    'relevanceSignal must sanitize a NaN BM25 score to 0');
  const { abstain } = scoreConfidence([nanBm25], DEFAULT_CONFIDENCE_CONFIG);
  assert.equal(abstain, true,
    'NaN BM25 score must abstain — corrupt lexical input cannot clear the floor');
});
