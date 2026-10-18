/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: core contracts
 *
 * Phase 6 of the 4.0.0 retrieval program (CHARIOT-SPEC §4.5 + §1.4 North Star).
 * These types define the *pluggable* surface the proof harness measures:
 *   - `Retriever`  — the retriever-under-test (today BM25 ToolPreFilter; the
 *                     P4 hybrid retriever and named competitors drop in here
 *                     with no harness change).
 *   - `GoldSet`    — the curated, versioned, per-TOOL labeled query suite.
 *   - result types — the numbers the artifact reproduces.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { Tool } from '../../types/index.js';
import type { LatencySummary } from './metrics.js';

// ─── Retriever (pluggable retriever-under-test) ─────────────────────────────

/**
 * What a retriever *is* in the benchmark:
 *  - `baseline`   — the shipped Chariot router for the measured release
 *                   (4.0.0 baseline = BM25 ToolPreFilter).
 *  - `hybrid`     — the P4 dense+SPLADE+BM25→RRF→rerank retriever (drops in
 *                   later behind the same interface).
 *  - `competitor` — a named third-party gateway / OSS tool-retrieval baseline
 *                   run on the *same* gold set for the §1.4 "provable" claim.
 */
export type RetrieverKind = 'baseline' | 'hybrid' | 'competitor';

export interface RetrieverInfo {
  /** Stable machine id committed into the artifact (e.g. `bm25-toolprefilter`). */
  id: string;
  /** Human label for the markdown report. */
  label: string;
  /** Provenance string committed into the artifact (impl version / source). */
  version: string;
  kind: RetrieverKind;
  /**
   * True when this retriever produces REAL measured numbers in this run.
   * False when it is a scaffold/stub awaiting live integration — the runner
   * records it as `pending` and NEVER fabricates a number for it (§1.4: a
   * "best in class" claim is made only on a reproduced result).
   */
  runnable: boolean;
  /**
   * True when `retrieve()` populates a per-candidate `score` that can be read as
   * a retrieval-confidence signal (feeds the calibration report). The shipped
   * BM25 ToolPreFilter returns Tool[] WITHOUT scores and is read-only (not
   * modified here), so the baseline sets this false and calibration is recorded
   * `unavailable`; the Phase 4 scoring retriever will set it true.
   */
  providesConfidence: boolean;
}

/** A single retrieved candidate at per-TOOL granularity. */
export interface RetrievedTool {
  /** `${server}:${name}` — the tool-granular id the LLM would be offered. */
  id: string;
  server: string;
  name: string;
  /**
   * Optional retrieval score/confidence for this candidate, when the retriever
   * exposes one (`info.providesConfidence === true`). Used only for the
   * calibration report; never fabricated when absent.
   */
  score?: number;
}

/**
 * The one interface the proof harness targets. Any retriever that implements
 * it — the BM25 baseline today, the P4 hybrid retriever later, or a competitor
 * adapter — is measured identically on the shared gold set.
 */
export interface Retriever {
  readonly info: RetrieverInfo;
  /** Index the tool catalog once before any `retrieve()` call. */
  index(tools: Tool[]): void | Promise<void>;
  /**
   * Return the ORDERED (best-first) candidate shortlist for `query`, capped at
   * `k` — i.e. the exact candidate set the orchestrator LLM would choose from.
   */
  retrieve(query: string, k: number): Promise<RetrievedTool[]>;
  /** Number of indexed tools. */
  readonly size: number;
}

// ─── Gold set (curated, versioned, per-TOOL labeled) ────────────────────────

/**
 * How the query was authored — drives the defensibility audit. `natural-intent`
 * and `paraphrase` queries deliberately AVOID lifting the target tool's
 * metadata tokens (the self-referential flaw of the old generated Tier-1).
 */
export type QueryStyle =
  | 'natural-intent'   // plain user intent, vendor NOT named
  | 'paraphrase'       // indirect phrasing, intentionally lexically distant
  | 'brand-named'      // user names the vendor (tests brand pin/hoist)
  | 'cross-domain';    // one request spanning multiple tools/servers

export interface GoldQuery {
  /** Stable id (e.g. `GS-001`). */
  id: string;
  /** The natural-language request a real user would type. */
  query: string;
  /**
   * Labeled relevant tool ids at per-TOOL granularity (`${server}:${name}`).
   * A query is a hit when ANY of these appears in the retriever's top-k
   * (recall is computed over the whole set). Every id MUST exist in the
   * production tool catalog — validated at load time.
   */
  relevantToolIds: string[];
  /** Catalog domain/category the intent belongs to. */
  domain: string;
  style: QueryStyle;
  /** How this label was derived — the defensibility record (§6.1). */
  labelBasis: string;
  /** Bug this query closes/tracks, if any (e.g. `biomedical-misroute-repro`). */
  bugRef?: string;
  /**
   * When true, a FAIL on this query is expected on the BM25 baseline and its
   * pass/fail is flagged pending the P4 hybrid retriever (it needs semantic
   * recall the lexical baseline cannot provide).
   */
  pendingP4?: boolean;
}

export interface GoldSetMeta {
  version: string;
  createdUtc: string;
  /** Catalog the labels were derived against (provenance / drift detection). */
  catalogEpoch: number | string;
  catalogVersion: number | string;
  /** One-paragraph statement of the authoring method. */
  methodology: string;
  /** The rules every label obeys (defensibility checklist). */
  derivationRules: string[];
  /** Spec §4.5 target (200). v1 size is reported against this honestly. */
  targetSize: number;
  notes: string[];
}

export interface GoldSet {
  meta: GoldSetMeta;
  queries: GoldQuery[];
}

// ─── Result types (the numbers the artifact reproduces) ─────────────────────

export interface PerQueryResult {
  id: string;
  query: string;
  domain: string;
  style: QueryStyle;
  relevantToolIds: string[];
  returnedToolIds: string[];
  hitToolIds: string[];
  recallAtK: number;
  precisionAtK: number;
  /** NDCG@k, binary relevance, log2 discount (see metrics.ts `ndcgAtK`). */
  ndcgAtK: number;
  /** 1-based rank of the first relevant tool, or null if none in top-k. */
  firstRelevantRank: number | null;
  reciprocalRank: number;
  /** sha256 of the ordered candidate id list (the determinism witness). */
  candidateSetSha256: string;
  /**
   * Retrieval confidence for this query (the top candidate's score), when the
   * retriever exposes one. Undefined for score-less retrievers (e.g. BM25
   * baseline). Feeds the calibration report.
   */
  confidence?: number;
  bugRef?: string;
  pendingP4?: boolean;
}

export interface AggregateMetrics {
  k: number;
  queryCount: number;
  /** Mean of per-query recall@k — the §4.5 headline (floor ≥ 0.95). */
  macroRecallAtK: number;
  /** Pooled (sum hits / sum relevant) recall@k. */
  microRecallAtK: number;
  /** Mean of per-query precision@k. */
  macroPrecisionAtK: number;
  /** Mean of per-query NDCG@k (binary relevance, log2 discount). */
  meanNdcgAtK: number;
  meanReciprocalRank: number;
  /** Fraction with the first relevant tool at rank 1 (diagnostic, NOT a claim). */
  hitAt1: number;
  /**
   * Hit-rate@k: fraction of queries with ≥1 relevant tool in top-k
   * (i.e. `anyHitAtK` under its other common IR name).
   */
  anyHitAtK: number;
  /**
   * One-sided 95% Wilson lower confidence bound of the hit-rate@k binomial
   * proportion (successes = queries with anyHitAtK=true, n = queryCount) —
   * never the point estimate alone. NaN when queryCount is 0.
   */
  hitRateWilsonLcb95: number;
  recallFloor: number;
  meetsFloor: boolean;
  /** Same metrics restricted to queries NOT flagged pending-P4. */
  excludingPendingP4?: Omit<AggregateMetrics, 'excludingPendingP4'>;
}

// ─── Determinism (the 100%-repeatability invariant, §6.3) ───────────────────

export interface DeterminismPerQuery {
  id: string;
  /** Number of DISTINCT candidate-set hashes seen across the N runs (1 == stable). */
  distinctHashes: number;
  /** The (first) candidate-set sha256 — equals the value in PerQueryResult when stable. */
  sha256: string;
}

export interface DeterminismReport {
  runsPerQuery: number;
  queryCount: number;
  /**
   * What this check verifies: each query is run N times and the candidate-set
   * hash is required to be identical across all N runs (intra-query run-to-run
   * stability). Cross-query distinctness — whether different queries return
   * distinct candidate sets — is a separate concern and is NOT verified here.
   */
  scope: 'intra-query run-to-run stability';
  /** True iff every query produced a single candidate-set hash across all runs. */
  deterministic: boolean;
  /** Ids whose candidate set varied across runs (empty when deterministic). */
  nondeterministicQueryIds: string[];
  perQuery: DeterminismPerQuery[];
}

// ─── Latency (Tier-1 selection under load, §6.4) ────────────────────────────

export interface LatencyReport {
  retrieverId: string;
  k: number;
  /** select() calls measured (excludes warmup). */
  measuredSelections: number;
  warmupSelections: number;
  /** Real per-call wall-clock summary (min/p50/p95/p99/max/mean), milliseconds. */
  summaryMs: LatencySummary;
}

// ─── Competitor benchmark (§6.5) ────────────────────────────────────────────

/**
 * One competitor's line in the artifact. `status:'measured'` carries REAL
 * metrics from a runnable adapter; `status:'pending'` carries a reason and NO
 * numbers — the harness never fabricates a competitor result (§1.4: a
 * "best in class" claim is made only on a reproduced result).
 */
export interface CompetitorEntryReport {
  info: RetrieverInfo;
  status: 'measured' | 'pending';
  pendingReason?: string;
  metrics?: AggregateMetrics;
}

// ─── First-call success (CH-37, the release gate) ───────────────────────────

/** Can the routed tool's args be validated against its input schema? */
export type ArgsValidVerdict = 'valid' | 'invalid' | 'unknown';
/** Did a real dispatch of the routed call succeed? */
export type DispatchVerdict = 'success' | 'failure' | 'pending';

/**
 * Per-query first-call-success decomposition (§CH-37). 3.1.2 shipped at G15=0%
 * because nobody measured this end-to-end; the proof artifact now carries the
 * axis so a release can never again be cut blind to it.
 *
 *  - routeCorrect       : measurable NOW — every labeled tool is within top-k
 *                         (the selection-layer precondition; for single-label
 *                         queries this is "the right tool is retrievable").
 *  - argsValid          : 'unknown' today — the routing catalog carries no
 *                         per-tool input schema (buildToolsForRouting emits empty
 *                         `properties`), so args cannot be validated; recorded
 *                         with a typed reason, never faked.
 *  - dispatchSucceeded  : 'pending' — needs the Phase 4 hybrid retriever + a safe
 *                         dispatcher fixture; wired now, never assumed success.
 *  - firstCallSuccess   : null while any of the above is unknown/pending (NOT
 *                         determinable yet); else routeCorrect ∧ argsValid==='valid'
 *                         ∧ dispatchSucceeded==='success'.
 */
export interface FirstCallPerQuery {
  id: string;
  routeCorrect: boolean;
  argsValid: ArgsValidVerdict;
  argsValidReason?: string;
  dispatchSucceeded: DispatchVerdict;
  dispatchReason?: string;
  firstCallSuccess: boolean | null;
  bugRef?: string;
  pendingP4?: boolean;
}

export interface FirstCallSuccessReport {
  k: number;
  queryCount: number;
  /** Queries whose full labeled tool set is within top-k. */
  routeCorrectCount: number;
  routeCorrectRate: number;
  argsValidBreakdown: Record<ArgsValidVerdict, number>;
  dispatchBreakdown: Record<DispatchVerdict, number>;
  /** False while args/dispatch remain unknown/pending — the headline gate is not yet measurable. */
  firstCallSuccessDeterminable: boolean;
  /** Null until determinable (no fabricated end-to-end number). */
  firstCallSuccessRate: number | null;
  /** Distinct typed reasons explaining why first-call-success is not yet determinable. */
  pendingReasons: string[];
  perQuery: FirstCallPerQuery[];
}

// ─── Retrieval-confidence calibration (3.1.2 over-confidence finding) ────────

/** One reliability bin: how confidence in [lower,upper) tracks actual route correctness. */
export interface CalibrationBin {
  lower: number;
  upper: number;
  count: number;
  meanConfidence: number;
  routeCorrectRate: number;
  /** |meanConfidence − routeCorrectRate| — the per-bin miscalibration. */
  gap: number;
}

/**
 * Calibration of the retriever's confidence against route correctness. 3.1.2
 * showed a 0.95 score on a garbage query and wrong routes at 0.91 — this makes
 * the reliability curve explicit so it is visible whether confidence can be
 * trusted. `status:'unavailable'` (with a typed reason) when the retriever
 * exposes no score (the BM25 baseline); the binning machinery is unit-tested and
 * populates `status:'measured'` for a scoring retriever (Phase 4).
 */
export interface CalibrationReport {
  retrieverId: string;
  providesConfidence: boolean;
  status: 'measured' | 'unavailable';
  reason?: string;
  binCount?: number;
  sampleCount?: number;
  /** Expected Calibration Error (Σ binWeight·gap); omitted when unavailable. */
  expectedCalibrationError?: number;
  bins?: CalibrationBin[];
}

// ─── requiresCustomerAuth segment (§4.5 / AS §1.2a) ─────────────────────────

/**
 * §4.5: "The gold set MUST include `requiresCustomerAuth` adapters (AS
 * §1.2a) ... and report `Recall@8` for that class separately, so auth-walled
 * discovery reliability is a measured, bounded number, not an assumed one
 * (no silent tail)." This is that separate report.
 *
 * `status: 'no-adapters-present'` is a FAIL-CLOSED, LOUD state — it is never
 * omitted from the artifact and never silently reported as a spurious 0/0
 * "measured" recall. It fires when either (a) the catalog under test
 * carries zero adapters flagged `requiresCustomerAuth:true` (a
 * catalog-population gap), or (b) the gold set labels none of their tools
 * (a gold-set-coverage gap) — `reason` distinguishes which.
 */
export interface RequiresCustomerAuthSegmentReport {
  /** requiresCustomerAuth adapters present in the catalog under test. */
  adapterCount: number;
  /** Gold queries whose relevantToolIds include ≥1 requiresCustomerAuth tool. */
  queryCount: number;
  status: 'measured' | 'no-adapters-present';
  /** Present, explicit, and human-readable whenever status is 'no-adapters-present'. */
  reason?: string;
  /** Present only when status is 'measured'. */
  metrics?: AggregateMetrics;
}

// ─── The committed, re-runnable proof artifact ──────────────────────────────

export interface ProofArtifact {
  schemaVersion: string;
  generatedUtc: string;
  spec: {
    /** §4.5 recall floor. */
    recallFloor: number;
    /** Shortlist size the headline recall is measured at (DEFAULT_MAX_TOOLS). */
    k: number;
    northStar: string;
  };
  catalog: {
    epoch: number | string;
    /**
     * CHARIOT::§3.5::33 (CH-22, AMENDED 2026-07-16): "The system SHALL stamp
     * the frozen record count and the catalog revision into the evaluation
     * artifact at catalog freeze." `catalogVersion` IS the CH-22 "catalog
     * revision" identifier — captured, together with `recordCount` below, at
     * the same freeze as the gold-set labels this artifact scores against.
     */
    catalogVersion: number | string;
    /**
     * CHARIOT::§3.5::33 (CH-22) — the frozen tool-granular record count
     * ("one vector per ready tool at catalog freeze") captured at the SAME
     * freeze as `catalogVersion` above. Equal to `toolCount` below: this
     * artifact's own catalog snapshot has no capability-residual records
     * (§CH-62(b)'s widened count applies to the signed 4.0.0 retrieval
     * bundle, not this proof harness's live 3.1.x-style catalog build).
     */
    recordCount: number;
    adapterCount: number;
    serverCount: number;
    toolCount: number;
    goldSetPath: string;
  };
  goldSet: {
    version: string;
    queryCount: number;
    targetSize: number;
    styleBreakdown: Record<string, number>;
    pendingP4Count: number;
    bugRefs: string[];
    labelValidation: { ok: boolean; totalLabels: number; unknownLabels: number };
  };
  baseline: {
    info: RetrieverInfo;
    metrics: AggregateMetrics;
    perQuery: PerQueryResult[];
  };
  /** §CH-37 first-call-success — THE release gate (routeCorrect now; args/dispatch wired). */
  firstCallSuccess: FirstCallSuccessReport;
  /** §4.5 / AS §1.2a — Recall@8 for requiresCustomerAuth adapters, reported separately. */
  requiresCustomerAuthSegment: RequiresCustomerAuthSegmentReport;
  /** Retrieval-confidence calibration (3.1.2 over-confidence finding). */
  calibration: CalibrationReport;
  determinism: DeterminismReport;
  latency: LatencyReport;
  competitors: CompetitorEntryReport[];
  notes: string[];
}
