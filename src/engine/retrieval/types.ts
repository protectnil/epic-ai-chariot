/**
 * @epicai/chariot — Retrieval types
 *
 * Shared types for the 4.0.0 hybrid retrieval subsystem (§4 / §8.6). These were
 * removed at commit 240c415 ("BM25-only excision") together with the old
 * network-Qdrant adapter; they are recreated here scoped to the embedded
 * Qdrant Edge + RRF + cross-encoder rerank stack and are intentionally local to
 * `src/engine/retrieval/` so the shared `engine/types/index.ts` stays free of
 * retrieval-implementation detail.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** One leg's scored candidate. `id` is the tool id (`server:name`). */
export interface ScoredResult {
  id: string;
  score: number;
  /** Optional serialized document text (used by the rerank stage). */
  content?: string;
  metadata?: Record<string, unknown>;
}

/** Which retrieval leg a fused document came from, and at what rank. */
export interface FusionSource {
  type: RetrievalLeg;
  rank: number;
  originalScore: number;
}

/** The three retrieval legs fused by RRF (§8.6 step 6). */
export type RetrievalLeg = 'dense' | 'sparse' | 'bm25';

/** A fused (and optionally reranked) result. */
export interface RetrievalResult {
  id: string;
  content?: string;
  /** Reciprocal-rank-fusion score (rank-based, deterministic). */
  fusionScore: number;
  fusionSources: FusionSource[];
  metadata?: Record<string, unknown>;
  /** Cross-encoder rerank score when the rerank stage ran (§8.6 step 7). */
  rerankScore?: number;
}

/**
 * One retrieval-leg (or query-serializer) failure event within a single
 * `search()` pass. `HybridRetriever` collects these instead of logging them
 * itself — CHARIOT-SPEC.md §4.1 states "the pre-filter falls back to
 * BM25-only and emits a WARN-level log entry once per query", i.e. the WARN
 * is `ToolPreFilter`'s responsibility, not the retriever's. The retriever
 * hands back the per-leg detail so the caller can fold every failure from one
 * query into exactly one coalesced WARN record (CHARIOT::§4.1::14).
 */
export interface LegFailure {
  /** The failing leg, or 'serializer' when `serializeQuery` itself threw
   * (which prevents both vector legs from running). */
  leg: RetrievalLeg | 'serializer';
  /** Stable event key for the failure kind (e.g. 'dense_leg_failed'). */
  reason: string;
  /** Free-form detail (error message / malformed-point counts). */
  detail?: Record<string, unknown>;
}

/**
 * Outcome of a hybrid retrieval pass. `rankedIds` is the deterministic ordered
 * tool-id list the pre-filter consumes; the remaining fields carry the
 * provenance, the calibrated confidence (CH-37), and the abstention verdict
 * (CH-49) so a probable mis-route is flagged rather than silently surfaced.
 */
export interface RetrievalOutcome {
  rankedIds: string[];
  fused: RetrievalResult[];
  /** Legs that actually contributed (BM25 always; dense/sparse when healthy). */
  legsUsed: RetrievalLeg[];
  /** True when a dense/sparse leg failed and the pass fell back (§4.4 WARN). */
  degraded: boolean;
  /** Per-leg failure detail for this query, for the caller's single coalesced
   * WARN (§4.1 / CHARIOT::§4.1::14). Empty on a fully healthy pass. */
  legFailures: LegFailure[];
  /** Calibrated [0,1] confidence in the top-1 (CH-37). */
  confidence: number;
  /** True when the best candidate is below the relevance floor (CH-49). */
  abstain: boolean;
  /** True when the cross-encoder rerank stage ran. */
  reranked: boolean;
  /**
   * §8.6a / §9::14 determinism extension (CHARIOT-SPEC.md:763, verbatim:
   * "Tier-1 selection is byte-identical for an identical request against an
   * identical `(sealed-bundle version, overlay-state snapshot)`"). The
   * content-addressed hash of this process's current per-tenant overlay
   * state (`OverlayEmbedder.overlayStateHash`) at the moment this query ran,
   * when an overlay embedder is wired (`HybridRetrieverDeps.overlayStateHash`)
   * — undefined when no overlay is wired (pre-§8.6a / overlay-less
   * deployments), preserving the pre-overlay determinism scope
   * `(sealed-bundle version)` alone. A caller building the §4.5 golden-trace
   * / byte-identical-selection proof folds this into its comparison key
   * alongside the bundle version exactly as the spec clause requires.
   */
  overlayStateHash?: string;
}

/**
 * Query-side serializer (§8.6 step 1). MUST be byte-identical to the freeze-side
 * `serialize_tool` lockstep contract (CH-23). In production this is the native
 * `serializeQuery` from `chariot-native.node`; tests inject a deterministic stub.
 */
export type QuerySerializer = (query: string) => string;

/** Dense query encoder (BIEN 768-d, §8.6 step 2). */
export interface DenseQueryEncoder {
  /** One dense vector per input text. */
  embed(texts: string[]): number[][];
}

/** One sparse vector in `{indices, values}` form. */
export interface SparseVector {
  indices: number[];
  values: number[];
}

/** Sparse query encoder (SPLADE `Splade_PP_en_v1`, §8.6 step 3). */
export interface SparseQueryEncoder {
  embedSparse(texts: string[]): SparseVector[];
}

/**
 * Cross-encoder rerank scorer (§8.6 step 7 / BIEN §7, LOCKED). Brute-force,
 * LLM-free: returns one relevance score per (query, doc) pair, deterministic
 * for a fixed model. The native fine-tuned cross-encoder lands with BIEN M10;
 * any deterministic scorer satisfies the interface for the rerank stage.
 */
export interface RerankScorer {
  score(query: string, docs: string[]): number[];
}
