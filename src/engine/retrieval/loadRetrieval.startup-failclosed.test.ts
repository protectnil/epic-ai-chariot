/**
 * Adversarial eval: §4.4 row 2 / §4.1 startup-vs-runtime encoder-failure
 * boundary (AMENDED 2026-07-16b).
 *
 * Governing clause (CHARIOT-SPEC.md §4.4, row 2, verbatim):
 *   "Encoder artifact missing or fails to LOAD (startup) | Fail-closed load
 *    error for the bundle (§4.1) — startup is blocked; there is NO BM25
 *    fallback for a bundle whose encoder artifact cannot load (AMENDED
 *    2026-07-16: disambiguates the prior row, which contradicted §4.1's
 *    fail-closed rule) | ERROR at startup"
 *
 * §4.1 (verbatim, in part): "...a missing or load-failing encoder artifact is
 * a STARTUP fail-closed load error per the next sentence and §4.4, never a
 * BM25 fallback... A manifest mismatch, missing encoder artifact, or Qdrant
 * startup failure is a fail-closed load error for the bundle, not a silent
 * fallback to a different model."
 *
 * Row 3 of the same table (RUNTIME, unchanged by the amendment):
 *   "Dense or sparse search throws during select() (RUNTIME, on a
 *    successfully-loaded bundle) | BM25 results returned alone, capped at
 *    maxTools/maxPerServer | WARN per query"
 * — "during select()" names `ToolPreFilter.select()`, not `HybridRetriever
 * .search()`: the WARN-emission site the row's log-level column governs is
 * the pre-filter (also stated explicitly in §4.1: "the pre-filter falls back
 * to BM25-only and emits a WARN-level log entry once per query").
 *
 * These three evals pin that boundary directly against every surface:
 *   (a) wireHybridRetrieval (the STARTUP load path, loadRetrieval.ts) — a
 *       missing/failing dense encoder AFTER manifest admission must return
 *       `fail-closed`, never `bm25-only`.
 *   (b) HybridRetriever.search (the RUNTIME path) — a dense encoder that
 *       throws on an ALREADY-LOADED bundle must still degrade to BM25,
 *       proving the runtime path was not collapsed by the startup fix. Per
 *       CHARIOT::§4.1::14, `search()` itself never calls `logger.warn()` —
 *       it surfaces the failure as a `LegFailure` entry in
 *       `RetrievalOutcome.legFailures` for the caller to log.
 *   (c) ToolPreFilter.select (§4.4 row 3's actual "during select()" site) —
 *       driving the identical dense-leg throw through the pre-filter with a
 *       captured logger must produce exactly ONE WARN-level log entry for
 *       the query (CHARIOT::§4.1::14), not zero (case (b) proved the
 *       retriever no longer logs it directly) and not more than one.
 *
 * Run (after tsc):
 *   node --test dist/engine/retrieval/loadRetrieval.startup-failclosed.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { wireHybridRetrieval } from './loadRetrieval.js';
import { HybridRetriever, type RetrieverLogger } from './HybridRetriever.js';
import { ToolPreFilter } from '../federation/ToolPreFilter.js';
import {
  DEFAULT_RETRIEVAL_CONTRACT,
  COMPILED_SERIALIZER_HASH,
} from './VectorIndexVerifier.js';
import type { NativeEdgeBinding } from './nativeEdge.js';
import type { NativeEdgeShard, NativeScoredPoint } from './nativeEdge.js';
import type { ScoredResult } from './types.js';
import type { Tool } from '../types/index.js';

// ── shared fixtures ──────────────────────────────────────────────────────────

function validManifest() {
  const c = DEFAULT_RETRIEVAL_CONTRACT;
  return {
    version: c.version,
    encoder: {
      denseModelId: c.denseModelId,
      denseModelVersion: c.denseModelVersion,
      denseDims: c.denseDims,
      sparseModelId: c.sparseModelId,
      bm25Method: c.bm25Method,
      idfPolicy: c.idfPolicy,
    },
    recordCount: 1,
    tool_record_count: 1,
    capability_record_count: 0,
    recordCountPreOverlay: 1,
    serializer_hash: COMPILED_SERIALIZER_HASH,
  };
}

function validEnvelope() {
  return {
    catalog: [
      {
        id: 'pagerduty',
        descriptionForRetrieval: 'incident management and on-call alerting',
        searchQueries: ['page on-call', 'create incident'],
        industries: ['software'],
        departments: ['sre'],
        tools: [{ name: 'create_incident', description: 'Create a new incident', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp'] }],
      },
    ],
    registry: [],
    manifest: validManifest(),
    epoch: 10,
    catalogVersion: 2,
  };
}

function captureLogger(): { logger: RetrieverLogger; errors: string[]; warns: string[] } {
  const errors: string[] = [];
  const warns: string[] = [];
  return {
    errors,
    warns,
    logger: {
      warn(msg) { warns.push(msg); },
      debug() {},
      error(msg) { errors.push(msg); },
    },
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

// ── eval (a): STARTUP — encoder missing/load-fails after manifest admission ─
// ── must FAIL CLOSED, never bm25-only ────────────────────────────────────────

test('§4.4 row 2 (startup): dense encoder fails to load AFTER a valid, admitted manifest → wireHybridRetrieval FAILS CLOSED, not bm25-only', () => {
  const { logger, errors } = captureLogger();
  let persistCalled = false;

  const fakeNative = { frozenSerializerHash: () => COMPILED_SERIALIZER_HASH } as unknown as NativeEdgeBinding;
  const fakeShard = {
    upsert() {},
    flush() {},
    pointsCount() { return 1; },
    snapshotManifestJson() { return '{}'; },
    query() { return []; },
  };

  const result = wireHybridRetrieval({
    envelope: validEnvelope(),
    signatureVerified: true,
    persisted: null,
    persist: () => { persistCalled = true; },
    native: fakeNative,
    // Manifest admits cleanly; shard loads; the DENSE ENCODER is the artifact
    // that fails to load at startup — the exact defect scenario.
    artifacts: {
      loadShard: () => fakeShard,
      loadDenseEncoder: () => null, // encoder artifact fails to load
      loadSparseEncoder: () => null,
      loadRerankScorer: () => null,
      querySerializer: () => (q: string) => q,
    },
    logger,
  });

  assert.equal(result.mode, 'fail-closed',
    'a dense-encoder load failure AFTER manifest admission must fail closed (§4.4 row 2 / §4.1, amended 2026-07-16b) — bm25-only is a defect regression');
  assert.equal(
    (result as { mode: 'fail-closed'; code: string }).code,
    'encoder_load_failed',
  );
  assert.ok(errors.length > 0, 'an ERROR must be logged at startup, per §4.4 row 2 log-level column');
  assert.equal(persistCalled, false,
    'the §5.6 epoch mark must NOT advance on a fail-closed startup — no routing began');
});

// ── eval (b): RUNTIME — search() throws on an ALREADY-LOADED bundle ─────────
// ── must still DEGRADE to BM25 (§4.4 row 3 / §4.1::13, unchanged) ───────────
// ── search() itself surfaces the failure as data, never a direct WARN ───────
// ── (CHARIOT::§4.1::14 — logging moved to the pre-filter; see eval (c)) ─────

function throwingDenseShard(): NativeEdgeShard {
  return {
    upsert() {},
    flush() {},
    pointsCount() { return 2; },
    snapshotManifestJson() { return '{}'; },
    query(): NativeScoredPoint[] {
      // Only reached by a healthy leg; the dense leg throws before this runs.
      return [];
    },
  };
}

function throwingDenseEncoder() {
  return {
    embed(): number[][] {
      throw new Error('simulated runtime dense-encoder failure');
    },
  };
}

test('§4.4 row 3 (runtime, unchanged): dense leg throws during search() on a successfully-loaded bundle → degrades to BM25, records legFailures, never throws, never fail-closed', () => {
  const { logger, warns } = captureLogger();

  const retriever = new HybridRetriever({
    shard: throwingDenseShard(),
    serializeQuery: (q: string) => q,
    // The bundle is fully "loaded" (constructor succeeded, encoder present) —
    // the failure happens later, at query time, inside embed().
    denseEncoder: throwingDenseEncoder(),
    sparseEncoder: null,
    reranker: null,
    logger,
  });

  const bm25Leg: ScoredResult[] = [
    { id: 'stripe:create_invoice', score: 2.5 },
    { id: 'pagerduty:create_incident', score: 1.1 },
  ];

  // search() must NOT throw — it must degrade to the surviving (BM25) leg.
  const outcome = retriever.search('create an incident', bm25Leg);

  assert.equal(outcome.degraded, true,
    'a runtime dense-leg throw on an already-loaded bundle must degrade, not fail closed');
  assert.ok(outcome.rankedIds.length > 0,
    'BM25 candidates must still be returned (bounded, capped shortlist — never empty, never unbounded)');
  assert.ok(
    outcome.rankedIds.every((id) => bm25Leg.some((b) => b.id === id)),
    'surviving candidates must come only from the BM25 leg once the dense leg has failed',
  );
  assert.deepEqual(outcome.legsUsed, ['bm25'],
    'only the bm25 leg contributed — the dense leg failed and was excluded, not silently substituted');

  // CHARIOT::§4.1::14 — the retriever records the failure as data...
  const denseFailures = outcome.legFailures.filter((f) => f.leg === 'dense' && f.reason === 'dense_leg_failed');
  assert.equal(denseFailures.length, 1,
    'the thrown dense leg must be recorded exactly once in legFailures, per §4.4 row 3');

  // ...and never calls the retriever's own logger for it — the WARN moved to
  // ToolPreFilter (CHARIOT-SPEC.md §4.1: "the pre-filter ... emits a
  // WARN-level log entry"; eval (c) below proves the pre-filter side).
  assert.equal(warns.length, 0,
    'HybridRetriever.search() must not call logger.warn() itself — that responsibility moved to ToolPreFilter (CHARIOT::§4.1::14)');
});

// ── eval (c): §4.4 row 3's actual "during select()" site — ToolPreFilter ────
// ── driving the identical failure through select() must emit exactly ONE ───
// ── WARN for the query (CHARIOT::§4.1::14), never zero, never more than one ─

test('§4.4 row 3 (during select()): the same dense-leg throw, driven through ToolPreFilter.select with a captured logger, emits exactly one WARN', async () => {
  const { logger, warns } = captureLogger();

  const retriever = new HybridRetriever({
    shard: throwingDenseShard(),
    serializeQuery: (q: string) => q,
    denseEncoder: throwingDenseEncoder(),
    sparseEncoder: null,
    reranker: null,
    // No logger wired here: this eval isolates WARN emission to the
    // pre-filter side; eval (b) already proved the retriever emits none.
  });

  const filter = new ToolPreFilter();
  filter.index([
    makeTool('stripe', 'create_invoice', 'create a stripe invoice for a customer'),
    makeTool('pagerduty', 'create_incident', 'create a pagerduty incident'),
  ]);
  filter.setHybridRetriever(retriever);
  filter.setLogger(logger);

  // §4.4 row 3's own wording: "during select()" — drive the failure through
  // exactly that call.
  const tools = await filter.select('create an incident');

  assert.ok(tools.length > 0,
    'BM25 candidates must still be returned through select() — never fail-closed, never an empty pass-through');

  assert.equal(warns.length, 1,
    `§4.4 row 3 / CHARIOT::§4.1::14 requires exactly one WARN-level log entry per query — got ${warns.length}`);
  assert.equal(warns[0], 'retrieval.degraded');
});
