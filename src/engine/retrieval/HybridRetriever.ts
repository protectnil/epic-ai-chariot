/**
 * @epicai/chariot — Hybrid Retriever
 *
 * Orchestrates the §8.6 four-signal retrieval stack over the embedded Qdrant
 * Edge `EdgeShard` and the in-process encoders:
 *
 *   1. serialize_query → lockstep query text (CH-23)            [injected serializer]
 *   2. BIEN dense 768-d vector                                  [injected dense encoder]
 *   3. SPLADE sparse vector (`Splade_PP_en_v1`)                 [injected sparse encoder]
 *   4. BM25 lexical leg                                         [passed in by ToolPreFilter]
 *   5. Edge runs in-process dense + sparse retrieval (no server, no port)
 *   6. RankFusion.rrf merges dense + sparse + BM25 (k=60)
 *   7. cross-encoder rerank over the fused shortlist            [injected reranker]
 *   8. top-K cut (done by the caller / ToolPreFilter)
 *
 * The BM25 leg is supplied by `ToolPreFilter` (its tuned real-IDF BM25, kept per
 * §4.2/4.5) rather than Edge-native BM25, so the lexical signal the rest of the
 * router relies on is unchanged; dense + sparse are the new legs this class adds.
 *
 * DETERMINISM (§8.6 / CH-23): every Edge query runs on the EXACT (full-scan)
 * path (`exact: true`) — approximate HNSW is not byte-identical across replicas.
 * RRF is rank-based (no normalization) and the rerank is brute-force, so the
 * candidate set hash-matches across runs/replicas/restart.
 *
 * HEALTH GATE (§4.1 / §4.4): if the dense or sparse leg throws during a search,
 * the pass falls back to the legs that succeeded (BM25 always succeeds — it is
 * computed by the caller) and sets `degraded: true`. No query fails because of
 * a leg failure.
 *
 * WARN OWNERSHIP (CHARIOT::§4.1::14): CHARIOT-SPEC.md §4.1 states "the
 * pre-filter falls back to BM25-only and emits a WARN-level log entry once
 * per query" — the WARN is `ToolPreFilter`'s responsibility, emitted exactly
 * once per query regardless of how many legs failed. This class never calls
 * `logger.warn()` for a leg failure; it collects every failure from the pass
 * into `RetrievalOutcome.legFailures` so the caller can coalesce them into
 * that single record.
 *
 * All collaborators are INJECTED so the unit suite exercises the orchestration
 * with deterministic fakes; the real sealed shard + BIEN ONNX + SPLADE land in
 * P5/P8. A shard/encoder absence is a constructor-time null, handled here.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { RankFusion, DEFAULT_K } from './RankFusion.js';
import { CrossEncoderReranker } from './CrossEncoderReranker.js';
import { scoreConfidence, DEFAULT_CONFIDENCE_CONFIG, type ConfidenceConfig } from './confidence.js';
import type {
  ScoredResult,
  RetrievalResult,
  RetrievalOutcome,
  RetrievalLeg,
  LegFailure,
  QuerySerializer,
  DenseQueryEncoder,
  SparseQueryEncoder,
} from './types.js';
import type { NativeEdgeShard, NativeScoredPoint } from './nativeEdge.js';

/** Logger contract — kept minimal so tests can inject a capture stub. */
export interface RetrieverLogger {
  warn(msg: string, meta?: Record<string, unknown>): void;
  debug(msg: string, meta?: Record<string, unknown>): void;
  /** ERROR at startup for a §4.4 fail-closed load error (row 1/2/5). */
  error(msg: string, meta?: Record<string, unknown>): void;
}

export interface HybridRetrieverConfig {
  /** RRF constant (default 60, §8.6 step 6). */
  rrfK?: number;
  /** Candidate limit per vector leg before fusion. */
  legLimit?: number;
  /** Final fused/reranked shortlist size handed to the caller. */
  shortlistLimit?: number;
  /** Serializer base prefix selector (BIEN locked base → "nomic"). */
  serializerBase?: string;
  /** Confidence + abstention calibration (CH-37 / CH-49). */
  confidence?: ConfidenceConfig;
}

export interface HybridRetrieverDeps {
  /**
   * The query-side shard. When a per-tenant overlay is embedded (§8.6a),
   * the caller passes a `CompositeEdgeShard` fanning out to the sealed
   * catalog shard AND the overlay shard(s) — see `overlay/CompositeEdgeShard.ts`.
   * This class has no overlay-specific logic of its own; it only ever calls
   * `shard.query(...)`, so it is unaffected either way (BIEN::§9::14: "the
   * runtime SHALL fuse ... without a separate index or re-embedding step").
   */
  shard: NativeEdgeShard;
  serializeQuery: QuerySerializer;
  denseEncoder: DenseQueryEncoder | null;
  sparseEncoder: SparseQueryEncoder | null;
  reranker: CrossEncoderReranker | null;
  logger?: RetrieverLogger;
  /**
   * §8.6a determinism extension (CHARIOT-SPEC.md:763/:767) — the REQUESTING
   * TENANT's overlay content hash, when an overlay embedder is wired
   * (`overlay/OverlayEmbedder.ts::overlayStateHash`). Takes `tenantId`
   * explicitly (gate finding D2 — the embedder's own API is per-tenant;
   * a tenant-less accessor here would either leak a different tenant's
   * hash or be meaningless) and returns `undefined` when that tenant has no
   * overlay, so `RetrievalOutcome.overlayStateHash` is absent rather than a
   * misleading value for a tenant that never verified anything.
   */
  overlayStateHash?: (tenantId: string) => string | undefined;
}

/** Compatibility shape retained for the pre-4.0 retrieval seam. */
interface LegacyRetrievalOptions {
  dense: { search(query: string, limit: number): Promise<readonly { toolId: string; score: number }[]> };
  sparse: { search(query: string, limit: number): Promise<readonly { toolId: string; score: number }[]> };
  bm25: { search(query: string, limit: number): Promise<readonly { toolId: string; score: number }[]> };
  reranker?: { rerank(query: string, candidates: readonly any[]): Promise<readonly any[]> };
  maxTools?: number;
  retrievalDepth?: number;
  rrfK?: number;
}

export interface HybridRetrievalResult {
  candidates: Array<{ toolId: string; score: number; ranks?: Record<string, number>; [key: string]: unknown }>;
  degraded: boolean;
  failedLegs: RetrievalLeg[];
  rerankerFailed: boolean;
}

const DEFAULT_LEG_LIMIT = 64;
const DEFAULT_SHORTLIST_LIMIT = 32;

/**
 * Parse the Edge payload to the tool id. The freeze side stamps each point's
 * payload with `{ toolId: "server:name" }` (§5.2/CH-22 tool-granular). Returns
 * null when the payload is absent, unparseable, or carries no string toolId —
 * NEVER the raw point id: a raw Qdrant point id can never match the caller's
 * toolIdMap, so substituting it only pollutes RRF fusion, the rerank head, and
 * the confidence input while presenting as success. A malformed payload is a
 * shard-integrity event and is surfaced as such (WARN + degraded) by the
 * caller instead of being absorbed.
 */
function pointToToolId(p: NativeScoredPoint): string | null {
  if (p.payloadJson) {
    try {
      const payload = JSON.parse(p.payloadJson) as { toolId?: unknown };
      if (typeof payload.toolId === 'string' && payload.toolId.length > 0) {
        return payload.toolId;
      }
    } catch {
      /* malformed payload — counted by pointsToLeg */
    }
  }
  return null;
}

/** A vector leg's decoded points plus payload-integrity accounting. */
interface LegPoints {
  results: ScoredResult[];
  /** Points dropped because their payload carried no usable toolId. */
  malformed: number;
  /** Total points returned by the shard for this leg. */
  total: number;
}

function pointsToLeg(points: NativeScoredPoint[]): LegPoints {
  const results: ScoredResult[] = [];
  let malformed = 0;
  for (const p of points) {
    const toolId = pointToToolId(p);
    if (toolId === null) {
      malformed++;
      continue;
    }
    results.push({ id: toolId, score: p.score });
  }
  return { results, malformed, total: points.length };
}

export class HybridRetriever {
  private readonly legacyOptions: LegacyRetrievalOptions | null;
  private readonly deps!: HybridRetrieverDeps;
  private readonly rrfK!: number;
  private readonly legLimit!: number;
  private readonly shortlistLimit!: number;
  private readonly serializerBase!: string;
  private readonly confidenceConfig!: ConfidenceConfig;

  constructor(
    deps: HybridRetrieverDeps | LegacyRetrievalOptions,
    config: HybridRetrieverConfig = {},
  ) {
    this.legacyOptions = 'shard' in deps ? null : deps;
    if (this.legacyOptions) return;
    this.deps = deps as HybridRetrieverDeps;
    this.rrfK = config.rrfK ?? DEFAULT_K;
    this.legLimit = config.legLimit ?? DEFAULT_LEG_LIMIT;
    this.shortlistLimit = config.shortlistLimit ?? DEFAULT_SHORTLIST_LIMIT;
    this.serializerBase = config.serializerBase ?? 'nomic';
    this.confidenceConfig = config.confidence ?? DEFAULT_CONFIDENCE_CONFIG;
  }

  /** Pre-4.0 compatibility entry point; new code uses search(). */
  async retrieve(query: string): Promise<HybridRetrievalResult> {
    const options = this.legacyOptions;
    if (!options) throw new Error('retrieve() is only supported by the legacy adapter seam');
    const normalized = query.normalize('NFC').trim();
    if (!normalized) return { candidates: [], degraded: false, failedLegs: [], rerankerFailed: false };
    const depth = options.retrievalDepth ?? 60;
    const maxTools = options.maxTools ?? 8;
    const names: RetrievalLeg[] = ['dense', 'sparse', 'bm25'];
    const settled = await Promise.allSettled(names.map((name) => options[name].search(normalized, depth)));
    const legs = new Map<RetrievalLeg, readonly { toolId: string; score: number }[]>();
    const failedLegs: RetrievalLeg[] = [];
    settled.forEach((result, i) => result.status === 'fulfilled' ? legs.set(names[i], result.value) : failedLegs.push(names[i]));
    const bm25 = legs.get('bm25');
    if (failedLegs.length && !bm25) throw new Error(`retrieval failed closed; unavailable legs: ${failedLegs.join(', ')}`);
    const fuse = (sets: Map<RetrievalLeg, readonly { toolId: string; score: number }[]>) => {
      const scores = new Map<string, number>();
      const ranks = new Map<string, Record<string, number>>();
      for (const [name, rows] of sets) rows.forEach((row, rank) => {
        scores.set(row.toolId, (scores.get(row.toolId) ?? 0) + 1 / ((options.rrfK ?? 60) + rank + 1));
        const r = ranks.get(row.toolId) ?? {}; r[name] = rank + 1; ranks.set(row.toolId, r);
      });
      return [...scores].map(([toolId, score]) => ({ toolId, score, ranks: ranks.get(toolId) }))
        .sort((a, b) => b.score - a.score || a.toolId.localeCompare(b.toolId));
    };
    let candidates = fuse(failedLegs.length ? new Map([['bm25', bm25!]]) : legs).slice(0, maxTools);
    let rerankerFailed = false;
    if (!failedLegs.length && options.reranker) {
      try {
        const reranked = await options.reranker.rerank(normalized, candidates);
        const allowed = new Set(candidates.map((c) => c.toolId));
        const seen = new Set<string>();
        candidates = reranked.filter((c) => allowed.has(c.toolId) && !seen.has(c.toolId) && seen.add(c.toolId)).slice(0, maxTools);
        if (!candidates.length) throw new Error('empty reranker output');
      } catch {
        rerankerFailed = true;
        candidates = fuse(new Map([['bm25', bm25!]])).slice(0, maxTools);
      }
    }
    return { candidates, degraded: failedLegs.length > 0 || rerankerFailed, failedLegs, rerankerFailed };
  }

  /** True when at least one vector leg (dense or sparse) is wired. */
  get hasVectorLeg(): boolean {
    return this.deps.denseEncoder !== null || this.deps.sparseEncoder !== null;
  }

  /**
   * Run the hybrid pass. `bm25Leg` is the caller's already-computed BM25 ranked
   * candidates (tuned real-IDF, §4.2) — it is the always-present leg and the
   * fallback when the vector legs fail. Returns a deterministic, fused (and
   * reranked when a reranker is wired) outcome with calibrated confidence and
   * the CH-49 abstention verdict.
   *
   * `docTextById` supplies the lockstep document text used both as the rerank
   * input and as fused-result content; a candidate without an entry falls back
   * to its id (never dropped).
   */
  search(
    query: string,
    bm25Leg: ScoredResult[],
    docTextById?: Map<string, string>,
    /**
     * §8.6a (gate finding D1) — the REQUESTING tenant, threaded through to
     * `deps.shard.query(request, tenantId)` so a `CompositeEdgeShard`
     * resolves ONLY that tenant's overlay (never every tenant's, never a
     * different tenant's). Absent (or a plain single-shard `deps.shard`) →
     * byte-identical to the pre-§8.6a sealed-only path.
     */
    options?: { tenantId?: string },
  ): RetrievalOutcome {
    const tenantId = options?.tenantId;
    const legs: { type: RetrievalLeg; results: ScoredResult[] }[] = [];
    const legsUsed: RetrievalLeg[] = [];
    const legFailures: LegFailure[] = [];
    let degraded = false;

    // Vector legs run on the exact path for determinism. A failure in either
    // degrades to the surviving legs (§4.4) — never throws to the caller.
    // Failure detail is collected into `legFailures`, not logged here — the
    // caller (ToolPreFilter) owns the single per-query WARN (CHARIOT::§4.1::14).
    let serializedQuery: string | null = null;
    try {
      serializedQuery = this.deps.serializeQuery(query);
    } catch (err) {
      degraded = true;
      legFailures.push({ leg: 'serializer', reason: 'query_serialize_failed', detail: { error: String(err) } });
    }

    if (serializedQuery !== null && this.deps.denseEncoder) {
      try {
        const dense = this.queryDense(serializedQuery, tenantId);
        if (this.admitVectorLeg('dense', dense, legs, legsUsed, legFailures)) degraded = true;
      } catch (err) {
        degraded = true;
        legFailures.push({ leg: 'dense', reason: 'dense_leg_failed', detail: { error: String(err) } });
      }
    }

    if (serializedQuery !== null && this.deps.sparseEncoder) {
      try {
        const sparse = this.querySparse(serializedQuery, tenantId);
        if (this.admitVectorLeg('sparse', sparse, legs, legsUsed, legFailures)) degraded = true;
      } catch (err) {
        degraded = true;
        legFailures.push({ leg: 'sparse', reason: 'sparse_leg_failed', detail: { error: String(err) } });
      }
    }

    // BM25 leg is always present (computed by the caller).
    legs.push({ type: 'bm25', results: bm25Leg });
    legsUsed.push('bm25');

    // §8.6 step 6 — RRF fuse (rank-based, deterministic).
    let fused = RankFusion.rrf(legs, this.rrfK);

    // Attach lockstep doc text as content for the rerank stage + CH-34 surface.
    if (docTextById) {
      for (const r of fused) {
        const text = docTextById.get(r.id);
        if (text !== undefined) r.content = text;
      }
    }

    // §8.6 step 7 — cross-encoder rerank over the bounded fused shortlist
    // (brute-force, deterministic). Only the head of the fused list is reranked
    // (the rest cannot enter the top-K), keeping the brute-force cost bounded.
    let reranked = false;
    if (this.deps.reranker && fused.length > 0) {
      const head = fused.slice(0, this.shortlistLimit);
      const tail = fused.slice(this.shortlistLimit);
      const rescoredHead = this.deps.reranker.rerank(query, head);
      fused = [...rescoredHead, ...tail];
      reranked = true;
    }

    const { confidence, abstain } = scoreConfidence(fused, this.confidenceConfig);

    return {
      rankedIds: fused.map((r) => r.id),
      fused,
      legsUsed,
      degraded,
      legFailures,
      confidence,
      abstain,
      reranked,
      ...(this.deps.overlayStateHash && tenantId !== undefined
        ? (() => {
            const hash = this.deps.overlayStateHash!(tenantId);
            return hash !== undefined ? { overlayStateHash: hash } : {};
          })()
        : {}),
    };
  }

  // ── vector legs ────────────────────────────────────────────────────────────

  /**
   * Admit a vector leg's results into the fusion set, treating missing or
   * malformed point payloads (no usable toolId) as a leg-integrity event per
   * §4.4 rather than absorbing them: the failure is recorded into
   * `legFailures` (one entry per affected leg; the caller coalesces every
   * entry from the query into its single WARN — CHARIOT::§4.1::14), the pass
   * is flagged degraded, and a leg whose points ALL lack a toolId is treated
   * as failed (omitted from `legsUsed`) exactly like a thrown leg. Returns
   * true when the pass must be marked degraded.
   */
  private admitVectorLeg(
    type: RetrievalLeg,
    leg: LegPoints,
    legs: { type: RetrievalLeg; results: ScoredResult[] }[],
    legsUsed: RetrievalLeg[],
    legFailures: LegFailure[],
  ): boolean {
    if (leg.malformed > 0) {
      legFailures.push({
        leg: type,
        reason: 'point_payload_missing_toolid',
        detail: { malformed: leg.malformed, total: leg.total },
      });
      if (leg.results.length === 0) {
        // 100% of the leg's points lacked a toolId — the leg contributes
        // nothing usable; treat it as failed (§4.4), do not advertise it.
        return true;
      }
      legs.push({ type, results: leg.results });
      legsUsed.push(type);
      return true;
    }
    legs.push({ type, results: leg.results });
    legsUsed.push(type);
    return false;
  }

  private queryDense(serializedQuery: string, tenantId: string | undefined): LegPoints {
    const encoder = this.deps.denseEncoder;
    if (!encoder) throw new Error('dense encoder not available');
    const vectors = encoder.embed([serializedQuery]);
    const dense = vectors[0];
    if (!dense || dense.length === 0) {
      throw new Error('dense encoder returned an empty vector');
    }
    const points = this.deps.shard.query({
      prefetches: [],
      query: { using: 'dense', dense },
      limit: this.legLimit,
      withPayload: true,
      exact: true, // §8.6 / CH-23 deterministic full-scan path
    }, tenantId);
    return pointsToLeg(points);
  }

  private querySparse(serializedQuery: string, tenantId: string | undefined): LegPoints {
    const encoder = this.deps.sparseEncoder;
    if (!encoder) throw new Error('sparse encoder not available');
    const sparse = encoder.embedSparse([serializedQuery])[0];
    if (!sparse || sparse.indices.length === 0) {
      throw new Error('sparse encoder returned an empty vector');
    }
    const points = this.deps.shard.query({
      prefetches: [],
      query: { using: 'splade', sparseIndices: sparse.indices, sparseValues: sparse.values },
      limit: this.legLimit,
      withPayload: true,
      exact: true, // §8.6 / CH-23 deterministic full-scan path
    }, tenantId);
    return pointsToLeg(points);
  }
}

export type { RetrievalResult, RetrievalOutcome, ScoredResult };
