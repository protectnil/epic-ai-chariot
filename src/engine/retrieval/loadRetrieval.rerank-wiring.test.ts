/**
 * Regression eval: the rerank stage is actually WIRED (the tracked defect, §8.6 step 7)
 *
 * This shipped because nothing asserted that Tier-1 ever constructs the
 * cross-encoder stage. `CrossEncoderReranker` was fully implemented and fully
 * unit-tested in isolation, `ArtifactSource.loadRerankScorer()` returned a
 * hard-coded null, and no test connected the two — so a complete, green suite
 * coexisted with a retrieval path that could never rerank anything. Every
 * assertion here is on the seam that was missing: given a scorer, does the load
 * path build the stage, and given none, does it correctly leave it off.
 *
 * These evals exercise the REAL wireHybridRetrieval with real return values —
 * the only stand-ins are the injected artifacts, which is the seam's purpose.
 *
 * Run (after tsc):
 *   node --test dist/engine/retrieval/loadRetrieval.rerank-wiring.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { wireHybridRetrieval } from './loadRetrieval.js';
import { CrossEncoderReranker } from './CrossEncoderReranker.js';
import {
  DEFAULT_RETRIEVAL_CONTRACT,
  COMPILED_SERIALIZER_HASH,
} from './VectorIndexVerifier.js';
import type { NativeEdgeBinding } from './nativeEdge.js';
import type { RerankScorer } from './types.js';

// ── fixtures ─────────────────────────────────────────────────────────────────

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

function envelope(epoch: number, catalogVersion = 2) {
  return {
    catalog: [
      {
        id: 'pagerduty',
        descriptionForRetrieval: 'incident management and on-call alerting',
        searchQueries: ['page on-call', 'create incident'],
        industries: ['software'],
        departments: ['sre'],
        tools: [
          {
            name: 'create_incident',
            description: 'Create a new incident',
            inputSchema: { type: 'object' },
            dispatchMechanisms: ['mcp'],
          },
        ],
      },
    ],
    registry: [],
    manifest: validManifest(),
    epoch,
    catalogVersion,
  };
}

const fakeNative = {
  frozenSerializerHash: () => COMPILED_SERIALIZER_HASH,
} as unknown as NativeEdgeBinding;

function artifacts(scorer: RerankScorer | null) {
  const fakeShard = {
    upsert() {},
    flush() {},
    pointsCount() {
      return 1;
    },
    snapshotManifestJson() {
      return '{}';
    },
    query() {
      return [];
    },
  };
  return {
    loadShard: () => fakeShard,
    loadDenseEncoder: () => ({ embed: (xs: string[]) => xs.map(() => [1, 2, 3]) }),
    loadSparseEncoder: () => null,
    loadRerankScorer: () => scorer,
    querySerializer: () => (q: string) => q,
  };
}

/** Read the retriever's injected reranker. `deps` is TS-private, which is a
 *  compile-time construct only — the runtime field is what ships, and it is
 *  exactly what this regression must observe. */
function wiredReranker(retriever: unknown): unknown {
  return (retriever as { deps: { reranker: unknown } }).deps.reranker;
}

function wire(scorer: RerankScorer | null) {
  return wireHybridRetrieval({
    envelope: envelope(10),
    signatureVerified: true,
    persisted: null,
    persist: () => {},
    native: fakeNative,
    artifacts: artifacts(scorer),
  });
}

// ── the regression this file exists to catch ─────────────────────────────────

test('rerank-wiring: a non-null scorer produces a real CrossEncoderReranker on the retriever', () => {
  const scorer: RerankScorer = { score: (_q, docs) => docs.map((_d, i) => 1 / (i + 1)) };
  const result = wire(scorer);

  assert.equal(result.mode, 'hybrid', 'shard + dense encoder present must yield hybrid');
  assert.ok(result.mode === 'hybrid');
  const reranker = wiredReranker(result.retriever);
  assert.ok(
    reranker instanceof CrossEncoderReranker,
    'a supplied RerankScorer MUST be wrapped into the §8.6 step-7 rerank stage — ' +
      'a null here is the defect: the stage silently never runs',
  );
});

test('rerank-wiring: the wired stage calls the supplied scorer and reorders by its scores', () => {
  // Proves the wiring is live, not merely constructed: the scorer's ranking —
  // not the input order — decides the final ordering.
  const seen: { query: string; docs: string[] }[] = [];
  const scorer: RerankScorer = {
    score: (query, docs) => {
      seen.push({ query, docs: [...docs] });
      // Rank the LAST candidate first, so a no-op stage is distinguishable.
      return docs.map((_d, i) => i);
    },
  };
  const result = wire(scorer);
  assert.ok(result.mode === 'hybrid');
  const reranker = wiredReranker(result.retriever) as CrossEncoderReranker;

  const shortlist = [
    { id: 'a', score: 0.9, content: 'alpha' },
    { id: 'b', score: 0.8, content: 'bravo' },
    { id: 'c', score: 0.7, content: 'charlie' },
  ] as unknown as Parameters<CrossEncoderReranker['rerank']>[1];

  const out = reranker.rerank('page on-call', shortlist);

  assert.equal(seen.length, 1, 'the scorer must be invoked exactly once per rerank');
  assert.deepEqual(
    seen[0]!.docs,
    ['alpha', 'bravo', 'charlie'],
    'the stage must pass candidate CONTENT to the scorer, in shortlist order',
  );
  assert.deepEqual(
    out.map((r) => r.id),
    ['c', 'b', 'a'],
    'final order must follow the scorer, not the incoming fused order',
  );
});

test('rerank-wiring: a null scorer leaves the stage off without failing the hybrid path', () => {
  // The absence of a reranker must NOT be an error — §4.4 keeps the rest of the
  // stack running. What must not happen is a silently-null stage while the
  // system reports itself as fully wired.
  const result = wire(null);
  assert.equal(result.mode, 'hybrid');
  assert.ok(result.mode === 'hybrid');
  assert.equal(
    wiredReranker(result.retriever),
    null,
    'no scorer supplied → reranker must be explicitly null, never undefined',
  );
});
