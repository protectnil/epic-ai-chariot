/**
 * Adversarial eval: ToolPreFilter emits exactly ONE WARN per query on a
 * degraded hybrid pass (CHARIOT::§4.1::14).
 *
 * CHARIOT-SPEC.md §4.1: "the pre-filter falls back to BM25-only and emits a
 * WARN-level log entry once per query." A single query can trip multiple
 * independent leg failures inside `HybridRetriever.search()` (a malformed
 * dense-leg payload AND a thrown sparse leg, say) — the node under test
 * requires that a query which fails N legs still produces exactly ONE
 * WARN-level log record, with the per-leg detail nested inside that one
 * record, not N separate WARN calls.
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/ToolPreFilter.warn-coalesce.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ToolPreFilter } from './ToolPreFilter.js';
import { HybridRetriever, type RetrieverLogger } from '../retrieval/HybridRetriever.js';
import type { NativeEdgeShard, NativeScoredPoint } from '../retrieval/nativeEdge.js';
import type { Tool } from '../types/index.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeTool(server: string, name: string, description: string): Tool {
  return {
    server,
    name,
    description,
    parameters: { type: 'object', properties: {} },
    tier: 'direct',
  };
}

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

function captureLogger(): { logger: RetrieverLogger; warns: { msg: string; meta?: Record<string, unknown> }[] } {
  const warns: { msg: string; meta?: Record<string, unknown> }[] = [];
  return {
    warns,
    logger: {
      warn(msg, meta) {
        warns.push(meta !== undefined ? { msg, meta } : { msg });
      },
      debug() {},
      error() {},
    },
  };
}

test('ToolPreFilter: a query that fails BOTH the dense and sparse legs still emits exactly one WARN', () => {
  // Dense leg: shard returns one malformed point (no toolId) → leg-integrity
  // event. Sparse leg: encoder throws outright. Two independent leg failures
  // from the SAME query.
  const shard = makeShard([{ id: 'uuid-1', score: 0.9, version: 1 }]);
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
  });

  const filter = new ToolPreFilter();
  filter.index([
    makeTool('stripe', 'create_invoice', 'create a stripe invoice for a customer'),
    makeTool('pagerduty', 'create_incident', 'create a pagerduty incident'),
  ]);
  filter.setHybridRetriever(retriever);

  const { logger, warns } = captureLogger();
  filter.setLogger(logger);

  const verdict = filter.selectWithVerdict('create invoice');

  assert.equal(verdict.degraded, true, 'a pass with a failed leg must report degraded');

  const degradedWarns = warns.filter((w) => w.msg === 'retrieval.degraded');
  assert.equal(degradedWarns.length, 1,
    `exactly one WARN-level log entry per query (CHARIOT::§4.1::14) — got ${degradedWarns.length}`);

  // The per-leg detail is nested INSIDE that single record, not lost.
  const failures = degradedWarns[0].meta?.failures as Array<{ leg: string; reason: string }>;
  assert.ok(Array.isArray(failures) && failures.length === 2,
    'both leg failures from this one query must be present inside the single WARN record');
  assert.ok(failures.some((f) => f.leg === 'dense' && f.reason === 'point_payload_missing_toolid'));
  assert.ok(failures.some((f) => f.leg === 'sparse' && f.reason === 'sparse_leg_failed'));

  // Overall log volume for the query: exactly one WARN, not two, three, or four.
  assert.equal(warns.length, 1, 'no other WARN-level call fired for this query');
});

test('ToolPreFilter: a fully healthy hybrid pass emits zero WARNs', () => {
  const shard = makeShard([
    { id: 'uuid-1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) },
  ]);
  const retriever = new HybridRetriever({
    shard,
    serializeQuery: (q: string) => q,
    denseEncoder: { embed: (xs: string[]) => xs.map(() => [1, 2, 3]) },
    sparseEncoder: null,
    reranker: null,
  });

  const filter = new ToolPreFilter();
  filter.index([makeTool('stripe', 'create_invoice', 'create a stripe invoice for a customer')]);
  filter.setHybridRetriever(retriever);

  const { logger, warns } = captureLogger();
  filter.setLogger(logger);

  const verdict = filter.selectWithVerdict('create invoice');

  assert.equal(verdict.degraded, false);
  assert.equal(warns.length, 0, 'a healthy pass emits no WARN');
});

test('ToolPreFilter: with no logger wired, a degraded pass never throws (silent degrade, matching the unset-hybridRetriever default)', () => {
  const shard = makeShard([{ id: 'uuid-1', score: 0.9, version: 1 }]); // malformed
  const retriever = new HybridRetriever({
    shard,
    serializeQuery: (q: string) => q,
    denseEncoder: { embed: (xs: string[]) => xs.map(() => [1, 2, 3]) },
    sparseEncoder: null,
    reranker: null,
  });

  const filter = new ToolPreFilter();
  filter.index([makeTool('stripe', 'create_invoice', 'create a stripe invoice for a customer')]);
  filter.setHybridRetriever(retriever);
  // No setLogger() call.

  assert.doesNotThrow(() => filter.selectWithVerdict('create invoice'));
});
