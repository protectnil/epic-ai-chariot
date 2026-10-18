/**
 * Adversarial eval: HybridRetriever point-payload integrity (§4.4 fail-closed)
 *
 * A shard point whose payload carries no usable `toolId` (missing payloadJson,
 * corrupt JSON, or absent/non-string toolId) must be surfaced as a
 * leg-integrity event — recorded into `RetrievalOutcome.legFailures`,
 * `degraded: true`, the malformed points DROPPED — never silently absorbed by
 * substituting the raw Qdrant point id (which can never match the caller's
 * toolIdMap and only pollutes RRF fusion, the rerank head, and the confidence
 * input while the outcome presents as fully healthy).
 *
 * CHARIOT::§4.1::14 / CHARIOT-SPEC.md §4.1: "the pre-filter falls back to
 * BM25-only and emits a WARN-level log entry once per query" — `search()`
 * itself never calls `logger.warn()`; it is `ToolPreFilter` that owns the
 * single per-query WARN, built from `legFailures`. This file asserts the
 * retriever's half of that contract: zero direct logger calls, and every
 * failure surfaced as structured `legFailures` detail instead.
 *
 * Run (after tsc):
 *   node --test dist/engine/retrieval/HybridRetriever.payload-integrity.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { HybridRetriever, type RetrieverLogger } from './HybridRetriever.js';
import type { NativeEdgeShard, NativeScoredPoint } from './nativeEdge.js';
import type { ScoredResult } from './types.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeShard(points: NativeScoredPoint[]): NativeEdgeShard {
  return {
    upsert() {},
    flush() {},
    pointsCount() {
      return points.length;
    },
    snapshotManifestJson() {
      return '{}';
    },
    query() {
      return points;
    },
  };
}

/** Fails the test the moment `search()` calls the logger directly — that
 * responsibility moved to `ToolPreFilter` (CHARIOT::§4.1::14). */
function poisonedLogger(): RetrieverLogger {
  return {
    warn(msg) {
      assert.fail(`HybridRetriever.search() must never call logger.warn() itself (got "${msg}") — the pre-filter owns the once-per-query WARN (CHARIOT::§4.1::14)`);
    },
    debug() {},
    error() {},
  };
}

function retrieverFor(points: NativeScoredPoint[], logger: RetrieverLogger): HybridRetriever {
  return new HybridRetriever({
    shard: makeShard(points),
    serializeQuery: (q: string) => q,
    denseEncoder: { embed: (xs: string[]) => xs.map(() => [1, 2, 3]) },
    sparseEncoder: null,
    reranker: null,
    logger,
  });
}

const BM25_LEG: ScoredResult[] = [
  { id: 'stripe:create_invoice', score: 2.5 },
  { id: 'pagerduty:create_incident', score: 1.1 },
];

// ── eval: malformed payloads → legFailures + degraded, dropped, no direct WARN ──

test('payload-integrity: points without toolId are dropped, recorded in legFailures, and flag degraded', () => {
  const points: NativeScoredPoint[] = [
    // valid tool-granular point
    { id: 'uuid-1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) },
    // missing payload entirely
    { id: 'uuid-2', score: 0.8, version: 1 },
    // corrupt JSON
    { id: 'uuid-3', score: 0.7, version: 1, payloadJson: '{not json' },
    // payload without toolId
    { id: 'uuid-4', score: 0.6, version: 1, payloadJson: JSON.stringify({ other: true }) },
  ];
  const outcome = retrieverFor(points, poisonedLogger()).search('create invoice', BM25_LEG);

  assert.equal(outcome.degraded, true,
    'a leg with malformed point payloads must mark the pass degraded — never presents as healthy');
  const payloadFailures = outcome.legFailures.filter((f) => f.reason === 'point_payload_missing_toolid');
  assert.equal(payloadFailures.length, 1, 'exactly one legFailures entry per affected leg per query');
  assert.deepEqual(payloadFailures[0], { leg: 'dense', reason: 'point_payload_missing_toolid', detail: { malformed: 3, total: 4 } });

  // No raw point ids may leak into the ranked output.
  for (const id of outcome.rankedIds) {
    assert.ok(!id.startsWith('uuid-'), `raw point id ${id} must never appear in rankedIds`);
  }
  // The valid dense point and the BM25 leg both survive, and the leg is still used.
  assert.ok(outcome.rankedIds.includes('stripe:create_invoice'));
  assert.ok(outcome.rankedIds.includes('pagerduty:create_incident'));
  assert.ok(outcome.legsUsed.includes('dense'), 'a partially-valid leg is still fused');
  assert.ok(outcome.legsUsed.includes('bm25'));
});

// ── eval: 100% malformed leg is treated as failed (§4.4), BM25 order intact ──

test('payload-integrity: fully malformed dense leg is omitted like a thrown leg; BM25 ordering preserved', () => {
  const points: NativeScoredPoint[] = [
    { id: 'uuid-a', score: 0.9, version: 1 },
    { id: 'uuid-b', score: 0.8, version: 1, payloadJson: 'garbage' },
  ];
  const outcome = retrieverFor(points, poisonedLogger()).search('create invoice', BM25_LEG);

  assert.equal(outcome.degraded, true, 'fully-malformed leg must mark the pass degraded');
  assert.ok(!outcome.legsUsed.includes('dense'),
    'a leg whose points ALL lack toolId contributes nothing and must not be advertised in legsUsed');
  assert.deepEqual(outcome.rankedIds, ['stripe:create_invoice', 'pagerduty:create_incident'],
    'BM25 ordering must be preserved with zero raw point ids injected');
  assert.equal(
    outcome.legFailures.filter((f) => f.reason === 'point_payload_missing_toolid').length,
    1,
  );
});

// ── eval: healthy leg stays non-degraded (no false alarms) ───────────────────

test('payload-integrity: fully valid dense leg stays degraded=false with no legFailures', () => {
  const points: NativeScoredPoint[] = [
    { id: 'uuid-1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) },
    { id: 'uuid-2', score: 0.5, version: 1, payloadJson: JSON.stringify({ toolId: 'github:list_repos' }) },
  ];
  const outcome = retrieverFor(points, poisonedLogger()).search('create invoice', BM25_LEG);

  assert.equal(outcome.degraded, false, 'healthy pass must not be flagged degraded');
  assert.equal(outcome.legFailures.length, 0, 'no legFailures on a healthy pass');
  assert.ok(outcome.legsUsed.includes('dense'));
  assert.ok(outcome.rankedIds.includes('github:list_repos'));
});

// ── eval: multiple leg failures in one query coalesce to ONE WARN at ToolPreFilter ──

test('payload-integrity: a query with both dense and sparse failures produces multiple legFailures entries, still zero direct WARN calls', () => {
  const points: NativeScoredPoint[] = [
    { id: 'uuid-1', score: 0.9, version: 1 }, // malformed
  ];
  const shard = makeShard(points);
  const retriever = new HybridRetriever({
    shard,
    serializeQuery: (q: string) => q,
    denseEncoder: { embed: (xs: string[]) => xs.map(() => [1, 2, 3]) },
    sparseEncoder: {
      embedSparse: () => {
        throw new Error('sparse encoder unavailable');
      },
    },
    reranker: null,
    logger: poisonedLogger(),
  });

  const outcome = retriever.search('create invoice', BM25_LEG);

  assert.equal(outcome.degraded, true);
  // One entry for the malformed dense leg, one for the thrown sparse leg —
  // both surfaced as data, neither as a direct logger.warn() call.
  assert.equal(outcome.legFailures.length, 2, 'both leg failures from this single query are collected');
  assert.ok(outcome.legFailures.some((f) => f.leg === 'dense' && f.reason === 'point_payload_missing_toolid'));
  assert.ok(outcome.legFailures.some((f) => f.leg === 'sparse' && f.reason === 'sparse_leg_failed'));
});
