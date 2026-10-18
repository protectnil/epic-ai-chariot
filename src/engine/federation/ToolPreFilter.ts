/**
 * @epicai/chariot — Tool Pre-Filter
 * Narrows N registered tools to a ranked shortlist before the orchestrator LLM sees them.
 *
 * Two-tier routing:
 *   Tier 1: Lexical retrieval — BM25 (real IDF + document-length normalization)
 *           with per-term-class and brand-exact-match boosts, followed by
 *           deterministic exact-name / canonical-vendor / high-confidence-phrase
 *           pins and a brand-token hoist. Ranks directly over the indexed tool
 *           catalog (this.docs) at zero inference cost — no embedding model and
 *           no external index load.
 *   Tier 2: Model-assisted classification — handled by the orchestrator
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { Tool } from '../types/index.js';
import { expandQuery, buildCatalogExpansionIndex, type CatalogAdapterLike, type CatalogExpansionIndex } from './QueryExpander.js';
import type { HybridRetriever, RetrieverLogger } from '../retrieval/HybridRetriever.js';
import type { ScoredResult, RetrievalLeg, RetrievalResult } from '../retrieval/types.js';
import { TenantOverlayToolRegistry, type TenantOverlayToolRegistryReader } from './TenantOverlayToolRegistry.js';
import { scoreConfidence } from '../retrieval/confidence.js';
import {
  stablePartitionOfficialIds,
  assertOfficialPartitionInvariantIds,
} from '../retrieval/OfficialPartition.js';

// BM25 tuning parameters
const K1 = 1.2;   // term frequency saturation
const B = 0.75;    // document length normalization

// Per-term-class BM25 boost. Each entry multiplies that token's BM25
// contribution by the listed factor when present in the query. Conservative
// values (1.2-1.5) — high enough to break ties on hybrid-intent queries
// (e.g. "deployment + 5xx error spike" routing to observability rather than
// CI/CD), low enough that a single boosted token cannot dominate a clean
// keyword match. Selected from AI-eval 01 failure-mode analysis:
//   - Error-state tokens (5xx, error, failure, crash, outage, spike, exception)
//     bias toward observability/incident-response adapters whose keywords
//     emphasise these terms (datadog-observability, new-relic, rootly,
//     pagerduty), not CI/CD whose keywords emphasise "deployment", "workflow".
//   - Metric-type tokens (latency, p99, p95, throughput, rate, count, duration)
//     bias toward observability/analytics.
// Time-window tokens (last, hour, yesterday, Q1..Q4) are NOT boosted: they
// carry no domain signal and risk false-routing when present in unrelated
// queries.
// Ambiguous tokens deliberately EXCLUDED from the boost set:
//   - 'alert' / 'alerts' / 'incident' / 'incidents': appear across security,
//     healthcare ('critical alerts on lab results'), operational dashboards.
//     Boosting them caused a healthcare query ("lab results critical alerts
//     unacknowledged") to misroute to datadog-observability.
//   - 'rate' / 'duration': appear across finance ('interest rate'), HR
//     ('completion rate'), payments ('refund duration') — too broad for a
//     uniform multiplier.
const TERM_CLASS_BOOST: Record<string, number> = {
  '5xx': 2.0, '4xx': 1.5, '500': 1.5, '503': 1.5, '404': 1.3, '429': 1.3,
  'error': 1.5, 'errors': 1.5, 'failure': 1.5, 'failures': 1.5,
  'crash': 1.5, 'crashed': 1.4, 'outage': 1.5, 'downtime': 1.4,
  'spike': 1.3, 'exception': 1.3, 'exceptions': 1.3, 'timeout': 1.3, 'timeouts': 1.3,
  'latency': 1.4, 'p99': 1.5, 'p95': 1.5, 'p50': 1.3,
  'throughput': 1.3,
};

// Brand-name exact-match boost. When the query literally mentions the
// adapter slug (or any token within a multi-token slug like
// `microsoft-entra` → ['microsoft','entra']), every tool of that
// adapter receives a strong multiplier so a brand-named query beats
// generic description-token matches on unrelated adapters.
//
// Eval-driven floor: BambooHR query "BambooHR vacation days remaining
// balance" routed to `hive-mcp-agent-quota` because four description
// tokens (vacation, days, remaining, balance) on the quota adapter
// summed above one IDF-weighted 'bamboohr' token on the bamboohr
// adapter. A 3.0× multiplier on adapter-id-matching tools moves the
// single brand-token contribution above the four description-token
// contributions on any unrelated adapter.
//
// Why this is not in TERM_CLASS_BOOST: that table boosts ALL adapters'
// scores when the query contains a signal-class token. The brand boost
// is selective — it only boosts the adapter whose id matches.
const BRAND_MATCH_BOOST = 3.0;

// Minimum IDF a server-slug token must have for the brand boost and brand hoist
// to apply. Low-IDF slug tokens (generic English words that appear in many
// adapters' descriptions) must not trigger brand boost — they carry no
// brand-intent signal. This gates both the scoreBM25 BRAND_MATCH_BOOST
// multiplier and the selectInternal server-hoist so that random short server
// names in small catalogs (e.g., "apply", "get", "list") do not bootstrap a
// 3.0× boost from coincidental query-token overlap.
//
// Production corpus (~800 adapters): real brand slugs ("pagerduty",
// "bamboohr", "rootly") have IDF ≥ 5 — they appear in at most 1-2 adapter
// descriptions. Generic words appear in > 100 descriptions → IDF < 2.0.
//
// Small catalogs (fuzz tests, 3–10 tools): random server slugs have IDF < 1.0
// because their tokens share the same tiny vocabulary. Without this gate the
// brand boost fires on any query token that coincidentally names a server,
// breaking the P2 BM25 monotonicity property.
const MIN_BRAND_IDF = 2.0;

// high-confidence single-brand phrase triggers. When the user's query contains
// one of these phrases, the named adapter is pinned even if the user didn't
// type the brand name verbatim. Each entry maps a phrase whose intent is
// unambiguous to ONE canonical brand — not a disambiguation list. This is
// narrower than QueryExpander (which feeds BM25 with N alternatives);
// HIGH_CONFIDENCE_PHRASE_PINS reflects "the user clearly wants brand X" intent
// that the retriever should treat as equivalent to typing brand X. Module-level
// (allocated once at load), consumed in selectInternal().
const HIGH_CONFIDENCE_PHRASE_PINS: ReadonlyArray<[RegExp, string]> = [
  [/\bsoc\s*2\b/i, 'drata'],
  [/\bsoc\s*ii\b/i, 'drata'],
  [/\bcompliance training\b/i, 'drata'],
  // NOTE: removed the unconditional second pin of 'compliance training' to
  // 'workday'. The old comment claimed it was a "sibling when drata dropped"
  // fallback, but the pin path has no such conditional — both fired together,
  // emitting a phantom second pinned brand at synthetic max IDF. workday is
  // still pinned for 'soc 2 compliance' below and surfaces via BM25 otherwise.
  [/\bsoc\s*2 compliance\b/i, 'workday'],
  [/\bactive directory\b/i, 'microsoft-entra'],
  [/\bfailed login attempts?\b/i, 'microsoft-entra'],
  [/\bproduction deployment\b/i, 'github-actions'],
  [/\bdeployment changes?\b/i, 'github-actions'],
  [/\bdeployment tracking\b/i, 'github-actions'],
  [/\bdeployment history\b/i, 'github-actions'],
  [/\bversion control changes?\b/i, 'github-actions'],
  [/\brelease pipeline\b/i, 'github-actions'],
  [/\bec2 instances?\b/i, 'kubernetes'],
  [/\baws ec2\b/i, 'kubernetes'],
  [/\bkubernetes pods?\b/i, 'kubernetes'],
  [/\berror rate (?:monitor|metric)/i, 'datadog-observability'],
  [/\berror monitoring\b/i, 'datadog-observability'],
  [/\b5xx (?:errors?|spike)/i, 'datadog-observability'],
  [/\bcpu (?:usage )?monitor/i, 'datadog-observability'],
  [/\bobservability (?:metric|stack|tool)/i, 'datadog-observability'],
  [/\bincident creation\b/i, 'rootly'],
  [/\bincident management\b/i, 'rootly'],
  [/\bon-call rotation\b/i, 'rootly'],
  [/\bpaging\b/i, 'rootly'],
  // "page the on-call" / "page on-call" — verb form of paging.
  // Customer query "page the on-call about a production database outage"
  // was scoring datadog-observability (metrics adapter) first because
  // "database outage" tokens overlapped its description, even though
  // the user intent was clearly paging-the-on-call-engineer. Pin the
  // verb form explicitly.
  [/\bpage (?:the )?on-call\b/i, 'rootly'],
  [/\bpage (?:the )?on call\b/i, 'rootly'],
  [/\bvulnerability scan/i, 'wiz'],
  [/\bcontainer security/i, 'wiz'],
  [/\bunpatched (?:endpoint|device)/i, 'crowdstrike'],
  [/\bendpoint patch/i, 'crowdstrike'],
  [/\bburn rate\b/i, 'accounting'],
  [/\bquarterly financial\b/i, 'accounting'],
  [/\bcompliance training tracking\b/i, 'drata'],
  // Curated-four phrase pins (pubmed, dns, helium-mcp).
  // Wikipedia is its own brand-token; the other three need semantic
  // phrase hooks to win over BM25 noise on multi-word natural-language
  // queries that a Workato dev would actually type.
  [/\bclinical trials?\b/i, 'pubmed'],
  [/\bbiomedical (?:research|paper|literature)\b/i, 'pubmed'],
  [/\bresearch papers?\s+(?:on|about|covering)\b/i, 'pubmed'],
  [/\bpubmed citations?\b/i, 'pubmed'],
  [/\bpublished (?:papers?|literature|studies)\b/i, 'pubmed'],
  [/\bwhois\b/i, 'dns'],
  [/\basn (?:lookup|information|info|record)/i, 'dns'],
  [/\bdns (?:lookup|records?|query|resolve|nameserver|ns)/i, 'dns'],
  [/\bnameservers?\b/i, 'dns'],
  [/\breverse dns\b/i, 'dns'],
  [/\bip address (?:of|for|lookup)\b/i, 'dns'],
  [/\b(?:latest|recent|breaking)\s+(?:\w+\s+){0,3}(?:news|articles?|headlines?)\b/i, 'helium-mcp'],
  // NOTE: no bare /\bnews\b/ pin — it fired on incidental uses ("no news is
  // good news from the deploy pipeline") and hoisted helium-mcp at synthetic
  // max IDF over BM25-legitimate matches. Real news intent is covered by the
  // qualified phrases here; BM25 still surfaces helium-mcp on a literal "news".
  [/\bnews (?:articles?|coverage|story|stories)\b/i, 'helium-mcp'],
  [/\bread (?:recent )?articles? about\b/i, 'helium-mcp'],
  [/\b(?:articles?|coverage|headlines?) about\b/i, 'helium-mcp'],
];

// shortlist-size-policy: hard upper bound on this value is 12
// (Adaline 10-12 ceiling). G4 of test/ai-evals/38-shortlist-size-accuracy.mjs
// imports and asserts on this symbol.
export const DEFAULT_MAX_TOOLS = 8;
export const DEFAULT_MAX_PER_SERVER = 3;

const STOPWORDS = new Set([
  'a', 'an', 'the', 'and', 'or', 'not', 'is', 'are', 'was', 'were',
  'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did',
  'will', 'would', 'could', 'should', 'may', 'might', 'can', 'shall',
  'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from', 'as',
  'into', 'about', 'between', 'through', 'during', 'before', 'after',
  'it', 'its', 'this', 'that', 'these', 'those', 'i', 'we', 'you',
  'he', 'she', 'they', 'me', 'him', 'her', 'us', 'them', 'my', 'your',
  'his', 'our', 'their', 'what', 'which', 'who', 'whom', 'how', 'when',
  'where', 'why', 'if', 'then', 'than', 'so', 'no', 'all', 'each',
  'any', 'some', 'such', 'only', 'just', 'also', 'very',
  // §4.2: MCP-specific noise tokens, added to the English stopword set so
  // they do not inflate BM25 IDF weight on nearly every tool query.
  'tool', 'call', 'get', 'list', 'mcp',
]);

export function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(t => t.length >= 2 && !STOPWORDS.has(t));
}

interface ToolDocument {
  tool: Tool;
  terms: string[];
  termFreq: Map<string, number>;
  length: number;
  /** Token count of ONLY the semantic content (description + parameter keys),
   * excluding server and name. Used for BM25 document-length normalization so
   * that tools with long names are not penalized relative to tools with short
   * names when scoring description-keyword matches (BM25 monotonicity). Server
   * and name tokens still contribute to termFreq/scoring for brand-name queries.
   */
  semanticLength: number;
  /** Term frequencies for description + parameter keys ONLY (semantic field).
   * Used to apply a description-field bonus so that a query term appearing in
   * a tool's description scores at least as high as the same term in another
   * tool's identifier (name/server), preserving BM25 P2 monotonicity for the
   * "add matching term to description and query" property.
   */
  descTermFreq: Map<string, number>;
}

/**
 * Three-state health verdict consumed by the runtime tool-shortlist
 * health filter. The pre-filter
 * excludes adapters with `'down'` status from the candidate pool;
 * `'healthy'` and `'degraded'` are retained. `'degraded'` exists for
 * adapters whose recent probe was uncertain (transitional / unknown);
 * over-pruning these would cause false-negative tool exclusion under
 * transient network noise.
 */
export type AdapterHealthVerdict = 'healthy' | 'degraded' | 'down';

export interface PreFilterOptions {
  maxTools?: number;
  maxPerServer?: number;
  /**
 * optional cumulative token-cost budget for the shortlist.
   * When set, the selector iterates the BM25-sorted candidates and skips
   * any tool whose addition would push runningCost over maxTokens.
   * Cumulative cost stays under this bound across all selected tools.
   * Unset → unchanged count-only behavior.
   */
  maxTokens?: number;
  /**
   * Optional runtime health gate. When provided, the pre-filter
   * removes any tool whose `tool.server` is mapped to `'down'`
   * BEFORE BM25 scoring, so the LLM never sees a
   * shortlist entry it cannot actually call.
   *
   * Implementations must return synchronously: this runs on every
   * query and cannot afford a per-call network probe. Wire from
   * `ConnectionPool.getHealthByServer()` (or equivalent cache).
   * Return `'healthy'` for unknown servers — fail-open is safer
   * than silently dropping tools the orchestrator might still
   * resolve via federation.
   */
  healthChecker?: (serverId: string) => AdapterHealthVerdict;
  /**
   * §8.6a (BIEN::§9::14, gate finding D1) — the requesting tenant, threaded
   * through to `HybridRetriever.search()` so a per-tenant overlay
   * (`overlay/CompositeEdgeShard.ts`) resolves ONLY this tenant's
   * customer-verified vectors, never another tenant's and never every
   * tenant's. Absent → sealed-catalog-only results, exactly the pre-§8.6a
   * behavior. `toolHandlers.ts`'s `handleQueryImpl` already resolves the
   * tenant via `getTenantId()` and is the intended source of this value.
   */
  tenantId?: string;
}

/**
 * Rich routing result (§4.1/§4.5). `tools` is the ordered shortlist (identical
 * to what `select()` returns). The verdict fields are the 4.0.0 honest-signal
 * surface: `confidence` (CH-37 calibration), `abstain` (CH-49 out-of-catalog
 * floor — true only on the hybrid path when no explicit pin overrides), the
 * legs that contributed, and whether a vector leg degraded to BM25 (§4.4).
 * Consumed by the `chariot_query` meta-tool to emit `no_match` rather than a
 * confident absurd top-1.
 */
export interface RoutingVerdict {
  tools: Tool[];
  confidence: number;
  abstain: boolean;
  degraded: boolean;
  legsUsed: RetrievalLeg[];
}

// Phase 0 (3.1.0): cosineSim, sparseDot, and queryMiniCOILSparse removed —
// the dense leg was never implemented and the "miniCOIL" sparse leg was a
// length-biased character-n-gram hash (no IDF/normalization). Retrieval is
// now BM25-only; see select().

// ─── ToolPreFilter ──────────────────────────────────────────

/**
 * per-tool token-cost estimate. char_count / 4 industry
 * approximation; sums name + description + canonical-JSON of parameters.
 * Deterministic; no external tokenizer dependency. Operators that need
 * model-specific precision can override via the optional `tokenEstimator`
 * constructor option (e.g. tiktoken for GPT-family).
 */
import { canonicalStringify } from '../../util/canonical-json.js';

export function estimateToolTokens(tool: Tool): number {
 // canonical-stringify so insertion-order differences in
  // logically-identical parameter objects don't produce different
  // estimates across ingestion paths or index rebuilds.
  const paramStr = canonicalStringify(tool.parameters ?? {});
  const totalChars = (tool.name?.length ?? 0) + (tool.description?.length ?? 0) + paramStr.length;
  return Math.ceil(totalChars / 4);
}

export class ToolPreFilter {
  private docs: ToolDocument[] = [];
  private idf: Map<string, number> = new Map();
  private avgDocLength = 0;
  /** Average of per-document semanticLength (description + param-keys token count).
   *  Used for BM25 length normalization so that server/name tokens do not inflate
   *  document length and penalize tools with longer adapter identifiers.
   *  Floored at 1.0 to avoid degenerate normalization when all tools have empty
   *  descriptions (semanticLength=0) — a floor of 1 gives the same normalization
   *  factor as a one-token document, which is conservative and prevents
   *  zero-denominator instability. */
  private avgSemanticLength = 1.0;
  private toolIdMap: Map<string, Tool> = new Map();
  /**
   * BIEN::§7a::2/10 — adapter id -> governance tier, wired via
   * `setAdapterTiers()`. Read ONLY by the official/non-official partition
   * step in `selectInternal()`; never consulted by BM25 scoring, indexing,
   * or any embedding/serializer path (BIEN::§7a::10's exclusion).
   */
  private adapterTierIndex: Map<string, string | undefined> = new Map();
  // Per-server slug tokens, computed once at index() time. The BM25 brand-match
  // boost and the brand-hoist both consult this (via allSlugTokensInQuery) so
  // they tokenize the slug identically; recomputing tokenize(server) per query
  // was query-invariant wasted work.
  private slugTokensByServer: Map<string, string[]> = new Map();
 // per-tool token-cost cache populated at index() time.
  // Keyed `${server}:${name}`; O(1) lookup during select().
  private tokenCostByToolId: Map<string, number> = new Map();
 // optional emitter for shortlist-token-cost telemetry.
  private observabilityEmitter?: import('../types/index.js').ObservabilityEmitterContract;
 // optional model-specific tokenizer override.
  private tokenEstimator: (tool: Tool) => number = estimateToolTokens;
  // Optional 4.0.0 hybrid retriever (dense + SPLADE over the in-process
  // EdgeShard, fused with this BM25 leg via RRF, then cross-encoder reranked,
  // §8.6). UNSET by default: with no retriever the ranking is the tuned
  // BM25-only path below, byte-identical to 3.1.x — the hybrid path engages
  // only once a verified sealed bundle + encoders are wired in the load path
  // (4.6). This keeps the lexical evals stable while the BIEN model/bundle land.
  private hybridRetriever: HybridRetriever | null = null;
  // §8.6a (BIEN::§9::14) — resolves an `overlay:<tenantId>:<adapterId>:
  // <toolName>` candidate id (surfaced only by a CompositeEdgeShard-backed
  // hybridRetriever) into the customer-verified tool it names. UNSET by
  // default: with no registry wired, an overlay: candidate id is dropped
  // from the shortlist exactly like any other unrecognized id (the
  // pre-§8.6a behavior — `this.toolIdMap.get(id)` already misses it).
  private overlayToolRegistry: TenantOverlayToolRegistryReader | null = null;
  // Optional structured logger (CHARIOT::§4.1::14). CHARIOT-SPEC.md §4.1: "the
  // pre-filter falls back to BM25-only and emits a WARN-level log entry once
  // per query" — ToolPreFilter, not HybridRetriever, owns that WARN. UNSET by
  // default so a caller that never wires a logger degrades silently, exactly
  // like the unset hybridRetriever above.
  private logger: RetrieverLogger | null = null;
  // Catalog-driven query-expansion index (CHARIOT::§4.6::1). UNSET by default:
  // with no catalog wired, expandQuery() falls back to its legacy heuristic
  // table only (see QueryExpander.ts).
  private catalogExpansionIndex: CatalogExpansionIndex | null = null;

  /**
   * Wire the hybrid retriever (4.0.0 load path). When set, selectInternal fuses
   * BM25 + dense + SPLADE via RRF and reranks; when null, BM25-only (§4.4
   * fallback is the steady state until the bundle ships).
   */
  setHybridRetriever(retriever: HybridRetriever | null): void {
    this.hybridRetriever = retriever;
  }

  /**
   * Wire the §8.6a per-tenant overlay tool registry. Independent of
   * `setHybridRetriever` — the registry is only ever consulted for an
   * `overlay:`-prefixed candidate id, which only a `CompositeEdgeShard`-
   * backed retriever can produce, but the two are set separately so a
   * caller can supply either without the other (same pattern as
   * `setLogger`).
   */
  setOverlayToolRegistry(reader: TenantOverlayToolRegistryReader | null): void {
    this.overlayToolRegistry = reader;
  }

  /**
   * §8.6a (BIEN::§9::14, gate finding D1/D2/D3 follow-up) — resolve an
   * `overlay:<tenantId>:<adapterId>:<toolName>` candidate id (never a
   * BM25/declared-tool id — those never carry this prefix) into the SAME
   * `Tool` shape `buildToolsForRoutingChariot` builds for declared tools
   * (`parameters`/`server`/`tier`; see that module for the precedent this
   * mirrors). Returns `undefined` — meaning "drop this candidate from the
   * shortlist, never a crash, never a stub tool" — when:
   *   - no registry is wired (`setOverlayToolRegistry` never called), OR
   *   - the caller supplied no `tenantId` (an unscoped query has no tenant
   *     whose overlay it could possibly be asking about), OR
   *   - `id` does not parse as a well-formed overlay id, OR
   *   - the registry itself refuses (`TenantOverlayToolRegistryReader
   *     .resolveForTenant`'s own tenant cross-check — defense-in-depth on
   *     top of this method never even asking on behalf of a tenant other
   *     than `requestingTenantId`).
   */
  private resolveOverlayTool(id: string, requestingTenantId: string | undefined): Tool | undefined {
    if (!this.overlayToolRegistry || !requestingTenantId) return undefined;
    const parsed = TenantOverlayToolRegistry.parseOverlayToolId(id);
    if (!parsed) return undefined;
    const verified = this.overlayToolRegistry.resolveForTenant(id, requestingTenantId);
    if (!verified) return undefined;
    return {
      name: verified.name,
      description: verified.description,
      parameters: (verified.inputSchema as Record<string, unknown> | undefined) ?? { type: 'object', properties: {} },
      server: parsed.adapterId,
      tier: 'orchestrated',
    };
  }

  /**
   * Every `rankedIds`/`toolIdMap` lookup in `selectInternal` (the health
   * filter, `groupAndHoist`, the pinned-server hoist, and the final
   * maxTools/maxPerServer selection loop) MUST resolve an `overlay:`
   * candidate the SAME way or an overlay tool silently vanishes at
   * whichever stage still calls `this.toolIdMap.get(id)` alone — that was
   * the actual defect: `toolIdMap` never contains an `overlay:` id (it is
   * built once, at index time, from DECLARED adapters only), so a
   * bare-`toolIdMap` lookup drops every overlay candidate at the FIRST
   * stage it passes through, before this class's own final "look it up
   * and build a Tool" line is ever reached. This single resolver is used
   * at every stage instead.
   */
  private resolveToolForId(id: string, requestingTenantId: string | undefined): Tool | undefined {
    return this.toolIdMap.get(id) ?? this.resolveOverlayTool(id, requestingTenantId);
  }

  /**
   * Wire the structured logger used to emit the single per-query WARN when a
   * hybrid retrieval pass degrades (CHARIOT::§4.1::14). Independent of
   * `setHybridRetriever` so a caller can supply either without the other.
   */
  setLogger(logger: RetrieverLogger | null): void {
    this.logger = logger;
  }

  /**
   * Wire the adapter catalog that drives query expansion (CHARIOT::§4.6::1).
   * CHARIOT-SPEC.md §4.6: "The expansion list is loaded from the catalog
   * `keywords` field per adapter." Pass the same adapter list `index()` was
   * built from (or any structurally-compatible catalog); pass `null` to clear.
   */
  setCatalogKeywords(adapters: Iterable<CatalogAdapterLike> | null): void {
    this.catalogExpansionIndex = adapters ? buildCatalogExpansionIndex(adapters) : null;
  }

  /**
   * Wire the adapter-id -> governance-tier index the official/non-official
   * partition step reads (BIEN::§7a::2/3/10). Pass the same adapter list
   * `setCatalogKeywords`/`index()` were built from (or any
   * structurally-compatible catalog carrying `id`/`tier`); pass `null` to
   * clear (every lookup then resolves to `undefined`, i.e. non-official —
   * the closed-membership-test default, never a crash).
   */
  setAdapterTiers(adapters: Iterable<{ id?: string; tier?: string }> | null): void {
    this.adapterTierIndex = new Map();
    if (!adapters) return;
    for (const a of adapters) {
      if (typeof a.id === 'string' && a.id.length > 0) {
        this.adapterTierIndex.set(a.id, a.tier);
      }
    }
  }

 /** setter so callers can wire the observability emitter post-construction. */
  setObservabilityEmitter(emitter: import('../types/index.js').ObservabilityEmitterContract | undefined): void {
    this.observabilityEmitter = emitter;
  }
 /** override the default char-count/4 estimator with a model-specific tokenizer. */
  setTokenEstimator(fn: (tool: Tool) => number): void {
    this.tokenEstimator = fn;
    // Recompute cache so subsequent select() calls see the new estimates.
    this.tokenCostByToolId.clear();
    for (const doc of this.docs) {
      this.tokenCostByToolId.set(`${doc.tool.server}:${doc.tool.name}`, fn(doc.tool));
    }
  }

  /**
 * apply optional maxTokens budget to the pre-ranked shortlist
   * and emit `shortlist-token-cost`. Called by every return site in
   * select() and selectSync() so the budget is enforced uniformly.
   */
  private applyTokenBudgetAndEmit(tools: Tool[], opts?: PreFilterOptions): Tool[] {
    const maxTools = opts?.maxTools ?? DEFAULT_MAX_TOOLS;
    const maxTokens = opts?.maxTokens;
    let result: Tool[];
    if (maxTokens === undefined) {
      result = tools;
    } else {
      result = [];
      let runningCost = 0;
      for (const t of tools) {
        const cost = this.tokenCostByToolId.get(`${t.server}:${t.name}`) ?? this.tokenEstimator(t);
        if (runningCost + cost > maxTokens) continue;
        result.push(t);
        runningCost += cost;
      }
    }
    let totalTokens = 0;
    for (const t of result) {
      totalTokens += this.tokenCostByToolId.get(`${t.server}:${t.name}`) ?? this.tokenEstimator(t);
    }
    if (this.observabilityEmitter) {
      this.observabilityEmitter.emitShortlistTokenCost({
        totalTokens,
        toolCount: result.length,
        ...(maxTokens !== undefined ? { maxTokens } : {}),
        maxTools,
      });
    }
    return result;
  }

  /**
   * Index the full tool catalog for BM25 scoring.
   */
  index(tools: Tool[]): void {
    this.docs = tools.map(tool => {
      // Index the adapter (server) slug alongside the tool's method name +
      // description + parameter keys. Without `tool.server` in the text, BM25
      // had no signal for queries that literally name the vendor ("PagerDuty",
      // "Salesforce", "BambooHR", etc.) — every tool of every adapter looked
      // equally relevant on those tokens. With it included, an exact slug match
      // contributes a high-IDF term to every tool of that adapter, which is
      // exactly the boost needed when the user names the integration.
      const text = [
        tool.server.replace(/[_:-]/g, ' '),
        tool.name.replace(/[_:-]/g, ' '),
        tool.description,
        ...Object.keys((tool.parameters as { properties?: Record<string, unknown> }).properties ?? {}),
      ].join(' ');

      const terms = tokenize(text);
      const termFreq = new Map<string, number>();
      for (const t of terms) {
        termFreq.set(t, (termFreq.get(t) ?? 0) + 1);
      }

      // semanticLength + descTermFreq: description + param keys only. Excludes
      // server and name so that brand-identifier length does not penalize tools
      // with long names in BM25 doc-length normalization (P2 monotonicity).
      // descTermFreq also powers the description-field bonus (see scoreBM25).
      const semanticText = [
        tool.description,
        ...Object.keys((tool.parameters as { properties?: Record<string, unknown> }).properties ?? {}),
      ].join(' ');
      const semanticTerms = tokenize(semanticText);
      const semanticLength = semanticTerms.length;
      const descTermFreq = new Map<string, number>();
      for (const t of semanticTerms) {
        descTermFreq.set(t, (descTermFreq.get(t) ?? 0) + 1);
      }

      return { tool, terms, termFreq, length: terms.length, semanticLength, descTermFreq };
    });

    this.toolIdMap = new Map();
 // populate per-tool token-cost cache at index time so per-call
    // selection is O(1) lookup.
    this.tokenCostByToolId = new Map();
    this.slugTokensByServer = new Map();
    for (const doc of this.docs) {
      const id = `${doc.tool.server}:${doc.tool.name}`;
      this.toolIdMap.set(id, doc.tool);
      this.tokenCostByToolId.set(id, this.tokenEstimator(doc.tool));
      if (!this.slugTokensByServer.has(doc.tool.server)) {
        this.slugTokensByServer.set(doc.tool.server, tokenize(doc.tool.server));
      }
    }

    const docCount = this.docs.length;
    const docFreq = new Map<string, number>();
    for (const doc of this.docs) {
      const seen = new Set<string>();
      for (const t of doc.terms) {
        if (!seen.has(t)) {
          docFreq.set(t, (docFreq.get(t) ?? 0) + 1);
          seen.add(t);
        }
      }
    }

    this.idf = new Map();
    for (const [term, df] of docFreq) {
      this.idf.set(term, Math.log((docCount - df + 0.5) / (df + 0.5) + 1));
    }

    this.avgDocLength = this.docs.length > 0
      ? this.docs.reduce((sum, d) => sum + d.length, 0) / this.docs.length
      : 0;

    // avgSemanticLength: average description+param-keys token count, floored at 1.
    // Flooring prevents degenerate normalization when all descriptions are empty
    // (every tool gets semanticLength=0, avg=0, ratio=0, max BM25 per term).
    this.avgSemanticLength = this.docs.length > 0
      ? Math.max(1.0, this.docs.reduce((sum, d) => sum + d.semanticLength, 0) / this.docs.length)
      : 1.0;
  }

  /**
   * True when every token of the adapter slug appears in `querySet`. Shared by
   * the scoreBM25 brand-match boost and the brand-hoist so the two apply ONE
   * slug tokenization (the per-server cache from index()) and cannot drift.
   * NOTE: the exact-name PIN path intentionally does NOT use this — it keys off
   * the RAW (un-expanded) user query plus a full-slug token (see the pin block
   * and its "pin tokens come ONLY from the literal user query" rationale);
   * routing that path through here would expose QueryExpander synonyms to pins
   * and reintroduce the multi-brand non-determinism that rationale fixed.
   */
  private allSlugTokensInQuery(server: string, querySet: Set<string>): boolean {
    const slugTokens = this.slugTokensByServer.get(server) ?? [];
    if (slugTokens.length === 0) return false;
    return slugTokens.every((t) => querySet.has(t));
  }

  /**
   * True when every slug token of `server` has IDF >= MIN_BRAND_IDF,
   * meaning the slug is a distinctive brand name rather than a generic
   * English word. Used to gate BRAND_MATCH_BOOST and the brand hoist so
   * that low-IDF server slugs (e.g. "apply", "get", "search") never receive
   * a 3.0× score multiplier for coincidental query-token overlap.
   *
   * P2 monotonicity guarantee: without this gate, a server named after a
   * low-IDF word (e.g. the extra term injected into the target's description)
   * earns BRAND_MATCH_BOOST on the same term, overriding the description-field
   * bonus and breaking the monotonicity invariant. Gating brand boost on IDF
   * distinctiveness ensures the boost fires only for semantically meaningful
   * brand mentions.
   */
  private slugIsDistinctive(server: string): boolean {
    const slugTokens = this.slugTokensByServer.get(server) ?? [];
    if (slugTokens.length === 0) return false;
    return slugTokens.every((t) => (this.idf.get(t) ?? 0) >= MIN_BRAND_IDF);
  }

  /** BM25 scoring */
  private scoreBM25(queryTerms: string[]): { tool: Tool; score: number; id: string }[] {
    const scored: { tool: Tool; score: number; id: string }[] = [];

    // Pre-build the query-term set once so the brand-match check per doc
    // is O(slug-tokens) instead of O(slug-tokens × queryTerms).
    const queryTermSet = new Set(queryTerms);

    for (const doc of this.docs) {
      let score = 0;
      for (const qt of queryTerms) {
        const tf = doc.termFreq.get(qt) ?? 0;
        if (tf === 0) continue;

        const idf = this.idf.get(qt) ?? 0;
        const numerator = tf * (K1 + 1);
        // BM25 length normalization uses semanticLength (description + parameter
        // keys token count only), not the full document length that includes
        // server and name tokens. This ensures that tools with long adapter
        // identifiers are not penalized relative to tools with short or empty
        // identifiers when both tools match the same description-field term.
        //
        // BM25 normalization uses semanticLength (description + param-keys only)
        // so server/name tokens do not inflate doc length and penalize tools with
        // long adapter identifiers. avgSemanticLength is floored at 1 in index().
        // A competitor with semanticLength=0 (no description content) gets the
        // minimum denominator (1.3) and maximum per-term BM25 score (1.692×idf);
        // the boost-scaled description-field bonus below guarantees the target
        // still wins when it has the term in its description.
        const denominator = tf + K1 * (1 - B + B * (doc.semanticLength / this.avgSemanticLength));
        // Per-term-class boost (see TERM_CLASS_BOOST docstring). Default 1.0
        // preserves baseline BM25 behaviour for all tokens not in the
        // signal-class allowlist.
        const boost = TERM_CLASS_BOOST[qt] ?? 1.0;
        score += boost * idf * (numerator / denominator);

        // Description-field bonus (P2 monotonicity guard): when the query term
        // appears in the tool's DESCRIPTION (not just server/name identifier),
        // add a bonus proportional to idf, scaled by the same per-term-class
        // boost applied to the BM25 contribution above. Scaling by `boost`
        // ensures the guarantee holds even for TERM_CLASS_BOOST tokens
        // (e.g. 'error', '5xx' with boost=2.0) — without it, a competitor
        // whose server/name contains that token gets boost×1.692×idf while
        // the target gets boost×1.0×idf + 1.0×idf, which fails for boost>1.
        //
        //   - Competitor (semanticLength=0, term in server, boost=b):
        //       bm25_max = b × idf × 1.692 (avgSemanticLength floored at 1,
        //       semanticLen=0 → denominator=1.3). No desc bonus.
        //       Total = b × 1.692 × idf.
        //
        //   - Target (semanticLength=1, term in description, boost=b):
        //       bm25 = b × idf × 1.0 (denominator=2.2).
        //       Desc bonus = b × 1.0 × idf.
        //       Total = b × 2.0 × idf.
        //       b × 2.0 > b × 1.692 → target wins for all b > 0. ✓
        // Parenthesized: `>` binds tighter than `??`, so the unparenthesized
        // form evaluated as `get(qt) ?? (0 > 0)` — behaviorally identical
        // today (stored freqs are always >= 1) but a latent trap for any
        // future zero-count entries.
        if ((doc.descTermFreq.get(qt) ?? 0) > 0) {
          score += boost * 1.0 * idf;
        }
      }

      // Brand-name exact-match boost (see BRAND_MATCH_BOOST docstring).
      // Tokenize the adapter slug (lowercase, hyphens/underscores →
      // boundaries) and require EVERY slug token to appear in the query
      // before applying the multiplier. The "any-token-match" form fired
      // too aggressively: a slug like `hive-mcp-dispute` would brand-boost
      // on any query containing the common word "dispute", overwhelming
      // unrelated brand mentions like "Zendesk". Requiring all-tokens
      // means single-token brands (bamboohr, opsgenie, zendesk) still
      // boost on the exact mention, multi-token brands (microsoft-entra,
      // app-store-connect) boost only when the user names every part,
      // and generic-word collisions inside compound slugs no longer
      // trigger. Skipped on zero-score docs and on zero-length slug
      // token lists (defensive).
      if (score > 0 && this.allSlugTokensInQuery(doc.tool.server, queryTermSet) && this.slugIsDistinctive(doc.tool.server)) {
        score *= BRAND_MATCH_BOOST;
      }

      const id = `${doc.tool.server}:${doc.tool.name}`;
      scored.push({ tool: doc.tool, score, id });
    }

    return scored;
  }

  // Phase 0 (3.1.0): searchDense / searchSparse removed with the static vector
  // index. Retrieval is BM25-only (see scoreBM25 + select()).

  /**
   * Select the top-K tools most relevant to the user query.
   *
   * Ranking: BM25 (real IDF + document-length normalization) with
   * per-term-class and brand-exact-match boosts, followed by deterministic
   * exact-name / canonical-vendor / high-confidence-phrase pins and a
   * brand-token hoist. Runs directly over the indexed catalog (this.docs) —
   * no embedding model and no external index load.
   */
  async select(query: string, options?: PreFilterOptions): Promise<Tool[]> {
    // Thin async wrapper over the shared synchronous ranker. select() and
    // selectSync() MUST share one implementation so their shortlists can never
    // diverge for the same query (an earlier version applied pins/brand-hoist
    // in select() only, so the two returned different rankings).
    //
    // async (not Promise.resolve) so that a synchronous throw inside
    // selectInternal becomes a Promise rejection — callers using .catch() or
    // await/try-catch always receive the error rather than getting an uncaught
    // synchronous exception escaping a function typed to return Promise<Tool[]>.
    return this.selectInternal(query, options).tools;
  }

  /**
   * Rich shortlist + honest-signal verdict (§4.5). Same ranking as select(),
   * additionally returning the calibrated `confidence` (CH-37), the `abstain`
   * verdict (CH-49), the contributing legs, and whether a vector leg degraded
   * to BM25 (§4.4). The `chariot_query` surface consumes this to emit no_match.
   */
  selectWithVerdict(query: string, options?: PreFilterOptions): RoutingVerdict {
    return this.selectInternal(query, options);
  }

  /**
   * Shared synchronous ranking used by BOTH select() and selectSync().
   *
   * Ranking: BM25 (real IDF + document-length normalization) with
   * per-term-class and brand-exact-match boosts, followed by deterministic
   * exact-name / canonical-vendor / high-confidence-phrase pins and a
   * brand-token hoist. When the entire candidate pool already fits within
   * maxTools, the whole pool is returned in that relevance order (the
   * maxPerServer diversity cap does not apply because nothing is being
   * dropped); otherwise the ranked list is fan-out-selected under the
   * maxPerServer and maxTokens budgets.
   */
  private selectInternal(query: string, options?: PreFilterOptions): RoutingVerdict {
    const maxTools = options?.maxTools ?? DEFAULT_MAX_TOOLS;
    const maxPerServer = options?.maxPerServer ?? DEFAULT_MAX_PER_SERVER;
    const healthChecker = options?.healthChecker;

    // Honest-signal verdict, populated as the ranking proceeds. Defaults are the
    // BM25-only steady state (no abstention, single leg); the hybrid block below
    // overwrites them when a retriever is wired.
    let confidence = 0;
    let abstain = false;
    let degraded = false;
    let legsUsed: RetrievalLeg[] = ['bm25'];

    // runtime tool-shortlist health filter: down-adapter exclusion. Tools whose
    // server is currently `'down'` are filtered out so the LLM
    // never sees a tool it can't call. Healthy and degraded
    // adapters are retained; the latter avoids over-pruning under
    // transient network noise. The filter is applied as a post-
    // score predicate so BM25's IDF (computed over the full corpus
    // at index time) stays correct.
    const isHealthy = (server: string): boolean =>
      !healthChecker || healthChecker(server) !== 'down';

    const candidateDocs = healthChecker
      ? this.docs.filter((d) => isHealthy(d.tool.server))
      : this.docs;

    // Deterministic candidate ordering: sort by tool id (server:name) ASC so any
    // path that returns/slices candidateDocs without scoring is stable under
    // input-order permutation (P1 tie-breaker stability invariant).
    const sortedCandidates = [...candidateDocs].sort((a, b) => {
      const idA = `${a.tool.server}:${a.tool.name}`;
      const idB = `${b.tool.server}:${b.tool.name}`;
      return idA < idB ? -1 : idA > idB ? 1 : 0;
    });

    // ── EXACT ADAPTER-NAME PIN ──────────────────────────────────────────────
    // When the user's query contains an adapter slug verbatim, that adapter
    // pins to the top of the ranked list. BM25 on long-form
    // adapter descriptions can otherwise let a semantically-similar competitor
    // out-score the named one ("Salesforce" loses to pipedrive on "deals
    // pipeline" overlap; "Gmail" loses to amazon-ses on "email send"
    // overlap). When the user types the integration name they want the LLM
    // to use, the router honors that intent literally.
    //
    // Match rules:
    //   - case-insensitive
    //   - whole-token only (so "pagerduty" matches but a substring of a
    //     longer token does not — prevents "git" from pinning "github-actions"
    //     and shadowing "github")
    //   - slug "atlassian-jira" is split on `-` so both "atlassian" and "jira"
    //     individually qualify; longer-slug match wins on collision
    //   - only adapters from the healthy-and-candidate set are eligible
    // Pin tokens come ONLY from the literal user query.
    // Exposing QueryExpander's brand-list expansions to the pin set caused
    // multiple canonical brands to simultaneously pin (e.g. "action items"
    // -> notion+asana+jira+monday+linear all pinning at synthetic IDF 100;
    // the alphabetical/length tiebreaker then produced non-deterministic
    // ordering between equally-pinned brands). QueryExpander tokens feed
    // BM25 only.
    const qLowerTokens = new Set(
      query.toLowerCase().split(/[\s,;:!?"'.()[\]{}<>/\\]+/).filter((t) => t.length > 0),
    );
    // Pin only when the matching slug token is sufficiently distinctive —
    // measured by BM25 IDF over the corpus. Adapters with generic slugs
    // ("jobs", "countries", "search", "azure", "tools") have low IDF because
    // their slug token appears in many other adapters' descriptions; pinning
    // those would shadow the real intended integration whenever the user
    // happens to type a common English word. Adapters with distinctive
    // slugs ("pagerduty", "salesforce", "bamboohr", "atlassian", "jira")
    // have high IDF because the slug appears nowhere else in the corpus.
    //
    // Threshold: the IDF distribution in this corpus places brand-name
    // slugs above ~2.5 and generic English nouns below ~1.5. We require
    // every constituent slug-token to clear the threshold so a multi-word
    // slug ("atlassian-jira") qualifies only when BOTH "atlassian" and
    // "jira" are distinctive.
    const MIN_PIN_IDF = 4.0;
    // Canonical vendor slugs that the user types BY BRAND NAME in plain
    // English. These bypass MIN_PIN_IDF because the slug token itself
    // appears in many adapter descriptions (every adapter says "integrates
    // with GitHub" so idf('github') is below the floor), but a user query
    // that literally names the brand has unambiguous intent. The allowlist
    // is narrow: each slug must (a) match the canonical adapter id in the
    // bundle exactly, (b) be a well-known vendor a customer would type by
    // name. New brand names land here individually with a routing-eval
    // case demonstrating the failure they close.
    const CANONICAL_VENDOR_SLUGS = new Set<string>([
      'github', 'gitlab', 'bitbucket',
      'slack', 'discord', 'microsoft-teams',
      'stripe', 'paypal', 'square',
      'salesforce', 'hubspot', 'pipedrive',
      'gmail', 'sendgrid', 'mailchimp',
      'notion', 'linear', 'jira', 'atlassian-jira', 'asana', 'monday',
      'pagerduty', 'datadog', 'sentry', 'newrelic',
      'aws', 'azure', 'gcp', 'kubernetes',
      'github-actions', 'argocd', 'circleci',
      'okta', 'auth0', 'microsoft-entra',
      'wiz', 'snyk', 'crowdstrike',
      'twilio', 'zoom', 'webex',
      'shopify', 'zendesk', 'intercom',
      'playwright', 'tavily', 'wayback-machine', 'pubmed',
      // Curated default adapters (also in dist/catalog/curated.js). Customers
      // running `chariot add wikipedia` then `chariot query` reasonably
      // expect a query naming "wikipedia" to route to wikipedia.
      'wikipedia', 'dns', 'helium-mcp',
    ]);
    // Tuple of (server, minIdfAcrossMatchTokens) so we can sort the pins by
    // most-distinctive-first when multiple match. "Okta" (high IDF — brand)
    // beats "countries" (lower IDF — common noun) even though both
    // technically clear the floor, so a query like "Okta simultaneous
    // logins from different countries" pins okta, not countries.
    // Detect whether the query names a canonical brand. If it does AND that
    // brand's adapter is dropped (not in sortedCandidates), suppress the
    // generic-IDF pin path so a stray English token ('countries', 'jobs',
    // 'tools') doesn't win over the brand the user actually named. ai-eval
    // 01 S30 example: "Okta simultaneous login detection different countries"
    // — okta is dropped (no published MCP), but 'countries' is a loaded
    // adapter whose IDF clears MIN_PIN_IDF. Without this suppression the
    // generic pin fires for 'countries' and BM25 never gets a fair fight.
    const queryNamesCanonicalBrandToken = (() => {
      for (const tok of qLowerTokens) {
        if (CANONICAL_VENDOR_SLUGS.has(tok)) return true;
      }
      return false;
    })();

    // HIGH_CONFIDENCE_PHRASE_PINS is a module-level constant (defined once at
    // load, not re-allocated per query). See its definition + rationale near
    // the top of this file.
    const phraseTriggeredPins = new Set<string>();
    for (const [re, brand] of HIGH_CONFIDENCE_PHRASE_PINS) {
      if (re.test(query)) phraseTriggeredPins.add(brand);
    }

    const pinCandidates: { server: string; minIdf: number; fullSlugMatch: boolean }[] = [];
    const seenServers = new Set<string>();
    // Phrase-triggered pins MUST be honored even when the target
    // adapter has zero BM25 score (e.g. helium-mcp has no overlap with
    // "Latest AI regulation news" tokens). Pre-emit phrase-triggered
    // brands as pin candidates BEFORE the sortedCandidates loop so they
    // are not skipped when the adapter is absent from the BM25 top-N.
    for (const brand of phraseTriggeredPins) {
      pinCandidates.push({ server: brand, minIdf: 100, fullSlugMatch: true });
      seenServers.add(brand);
    }
    for (const d of sortedCandidates) {
      const server = d.tool.server;
      if (seenServers.has(server)) continue;
      seenServers.add(server);
      const slugLower = server.toLowerCase();
      // Phrase-triggered single-brand pin checked FIRST so it
      // fires even when the user did not literally type the brand name (the
      // standard slug-token-presence check below would skip the adapter).
      if (phraseTriggeredPins.has(slugLower)) {
        pinCandidates.push({ server, minIdf: 100, fullSlugMatch: true });
        continue;
      }
      // NOTE: the pin path tokenizes the slug differently from the brand
      // boost/hoist (allSlugTokensInQuery) ON PURPOSE — it splits only on -/_
      // (no length/stopword filter) and matches against qLowerTokens (the RAW,
      // un-expanded query) plus a full-slug token. This is the deliberate "pin
      // tokens come ONLY from the literal user query" semantics noted above; do
      // NOT route it through allSlugTokensInQuery (that would expose
      // QueryExpander synonyms to pins and reintroduce multi-brand flapping).
      const slugTokens = slugLower.split(/[-_]/).filter((t) => t.length > 0);
      const fullSlugIsToken = qLowerTokens.has(slugLower);
      const allSlugTokensPresent =
        slugTokens.length > 1 && slugTokens.every((t) => qLowerTokens.has(t));
      if (!fullSlugIsToken && !allSlugTokensPresent) continue;
      const matchTokens = fullSlugIsToken && slugTokens.length === 1
        ? [slugLower]
        : slugTokens;
      const idfs = matchTokens.map((t) => this.idf.get(t) ?? 0);
      const minIdf = Math.min(...idfs);
      // Bypass MIN_PIN_IDF for canonical vendor slugs that appear verbatim
      // in the user query. idf('github') falls below the floor because the
      // token shows up in 200+ adapter descriptions; a query that literally
      // says "GitHub" still wants the github adapter, not gitea or any
      // similar-substring competitor. Use a synthetic high score so the
      // canonical match outranks any non-canonical pin candidate.
      if (fullSlugIsToken && CANONICAL_VENDOR_SLUGS.has(slugLower)) {
        pinCandidates.push({ server, minIdf: 100, fullSlugMatch: true });
        continue;
      }
      // When the query already names a canonical brand (its adapter may be
      // dropped, but the user intent is clear), do NOT pin any non-canonical
      // adapter. Let BM25 rank instead — that gives the actual semantic
      // sibling a chance to surface rather than letting a coincidental
      // English token outrank everything.
      if (queryNamesCanonicalBrandToken) continue;
      if (minIdf < MIN_PIN_IDF) continue;
      pinCandidates.push({ server, minIdf, fullSlugMatch: fullSlugIsToken });
    }
    // Pin sort:
    //  1. Multi-token compound slug whose ENTIRE slug appeared verbatim in the
    //     query (e.g. "microsoft-entra" in a query expanded from "Azure Active
    //     Directory") outranks a single-token slug that appeared (e.g. "azure"
    //     alone), because the compound is a more specific identifier the user
    //     spelled out. Closes the AAD→microsoft-entra retrieval miss on ai-eval
    //     01 S31 where the synonym expander supplies "microsoft-entra" as a
    //     compound token and the bare "azure" slug was previously winning the
    //     IDF tiebreak.
    //  2. Otherwise, most-distinctive IDF wins.
    //  3. On IDF tie, longer slug wins (more specific).
    pinCandidates.sort((a, b) => {
      const aCompoundFull = a.fullSlugMatch && a.server.includes('-');
      const bCompoundFull = b.fullSlugMatch && b.server.includes('-');
      if (aCompoundFull !== bCompoundFull) return aCompoundFull ? -1 : 1;
      if (b.minIdf !== a.minIdf) return b.minIdf - a.minIdf;
      return b.server.length - a.server.length;
    });
    const pinnedServerSlugs = pinCandidates.map((p) => p.server);

    // Build the verdict at every return site. CH-49 abstention engages ONLY on
    // the hybrid path (abstain is never set true otherwise) AND only when no
    // explicit pin overrides — a user who literally names an adapter has a
    // clear intent that is not an out-of-catalog miss, so the pin wins and the
    // router does not abstain. When abstaining, the shortlist is emptied so the
    // surface returns no_match rather than a confident absurd top-1.
    const finalize = (tools: Tool[]): RoutingVerdict => {
      const budgeted = this.applyTokenBudgetAndEmit(tools, options);
      const abstaining = abstain && pinnedServerSlugs.length === 0;
      return {
        tools: abstaining ? [] : budgeted,
        confidence,
        abstain: abstaining,
        degraded,
        legsUsed,
      };
    };

    // BIEN::§7a::10 — tier resolver shared by EVERY exit path in this
    // method, including the zero-lexical-signal fallback immediately
    // below (this candidate list is "each query result set" per
    // BIEN::§7a::1 exactly as much as the hybrid/BM25 paths further down —
    // there is no carve-out for a query with no tokenizable terms).
    const tierOf = (id: string): string | undefined =>
      this.adapterTierIndex.get(this.toolIdMap.get(id)?.server ?? '');

    // Expand query with domain-specific synonyms before tokenizing.
    // CHARIOT::§4.6::1 — catalog-driven expansion when a catalog is wired.
    const expandedQuery = expandQuery(query, this.catalogExpansionIndex ?? undefined);
    const queryTerms = tokenize(expandedQuery);
    if (queryTerms.length === 0) {
      // No lexical signal — deterministic alphabetical fallback.
      // BIEN::§7a::1/5/6/14 — partition the COMPLETE alphabetical candidate
      // list, THEN truncate to maxTools, THEN assert the truncated output —
      // same partition-before-truncation discipline as every other exit
      // path in this method (see the shared `finalizePartitionedIds`
      // comment further below for the full rationale).
      const allIds = sortedCandidates.map((d) => `${d.tool.server}:${d.tool.name}`);
      const partitionedIds = stablePartitionOfficialIds(allIds, tierOf).slice(0, maxTools);
      assertOfficialPartitionInvariantIds(partitionedIds, tierOf);
      const tools = partitionedIds
        .map((id) => this.toolIdMap.get(id))
        .filter((t): t is Tool => t !== undefined);
      return finalize(tools);
    }

    // BM25 scores — always computed (zero inference cost). Score
    // over the full corpus to keep IDF correct, then drop down-
    // adapter results before fan-out so unhealthy servers cannot
    // crowd out healthy alternatives in the top-N candidate set.
    const bm25ScoredAll = this.scoreBM25(queryTerms);
    const bm25Scored = healthChecker
      ? bm25ScoredAll.filter((s) => isHealthy(s.tool.server))
      : bm25ScoredAll;

    // BM25 base order: score-desc, id-asc (deterministic, golden-trace
    // comparable). Tools are mapped to `server:name` ids; the brand-hoist
    // (groupAndHoist) then reorders by server exactly as before.
    const bm25Positive = bm25Scored
      .filter(s => s.score > 0)
      .sort((a, b) => b.score - a.score || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const bm25Ids = bm25Positive.map(s => `${s.tool.server}:${s.tool.name}`);

    let rankedIds: string[];
    if (this.hybridRetriever && this.hybridRetriever.hasVectorLeg) {
      // §4.5 HYBRID path (engaged once the 4.0.0 bundle + encoders are wired):
      // BM25 is the always-present leg; the dense (BIEN) + SPLADE legs come from
      // the in-process EdgeShard; RankFusion.rrf fuses the three; the fused
      // shortlist is cross-encoder reranked (§8.6 step 7). A dense/sparse leg
      // failure degrades to the survivors with a WARN (§4.4) — search() never
      // throws to here. Deterministic tie-breaks are preserved by the retriever
      // (RRF id tie-break + brute-force rerank) and by groupAndHoist below.
      const bm25Leg: ScoredResult[] = bm25Positive.map(s => ({
        id: `${s.tool.server}:${s.tool.name}`,
        score: s.score,
      }));
      // Lockstep doc text (the routing text) for the rerank stage + CH-34
      // surface. The freeze-side serialized form rides the EdgeShard payload;
      // at query time the tool description is the available document text.
      const docTextById = new Map<string, string>();
      for (const s of bm25Scored) {
        docTextById.set(`${s.tool.server}:${s.tool.name}`, s.tool.description);
      }
      const outcome = this.hybridRetriever.search(query, bm25Leg, docTextById, { tenantId: options?.tenantId });
      confidence = outcome.confidence;
      abstain = outcome.abstain;
      degraded = outcome.degraded;
      legsUsed = outcome.legsUsed;
      // CHARIOT::§4.1::14 — CHARIOT-SPEC.md §4.1: "the pre-filter falls back
      // to BM25-only and emits a WARN-level log entry once per query." A pass
      // can accumulate multiple leg failures (serializer + dense + sparse +
      // malformed-payload events); they are coalesced into exactly ONE WARN
      // call here, with every failure's detail nested inside that one record,
      // never one WARN call per affected leg.
      if (outcome.legFailures.length > 0) {
        this.logger?.warn('retrieval.degraded', {
          query,
          legsUsed: outcome.legsUsed,
          failures: outcome.legFailures,
        });
      }
      // Keep only ids known to the routing index (declared OR a resolvable
      // §8.6a overlay:-candidate — see resolveToolForId), honoring the
      // health filter; group-by-server + brand-hoist on top of the fused
      // order.
      const known = outcome.rankedIds.filter((id) => {
        const tool = this.resolveToolForId(id, options?.tenantId);
        return !!tool && isHealthy(tool.server);
      });
      rankedIds = this.groupAndHoist(known, queryTerms, (id) => this.resolveOverlayTool(id, options?.tenantId));
      // Safety net: never return a strict subset of the BM25 shortlist — append
      // any BM25-positive id the fused legs did not surface, in BM25+hoist order.
      const inRanked = new Set(rankedIds);
      for (const id of this.groupAndHoist(bm25Ids, queryTerms)) {
        if (!inRanked.has(id)) {
          rankedIds.push(id);
          inRanked.add(id);
        }
      }
    } else {
      // BM25-only steady state (byte-identical to 3.1.x). The former "miniCOIL"
      // sparse leg and the never-implemented dense leg were removed at 3.1.0;
      // the dense + SPLADE legs return via the hybrid branch above once the
      // bundle ships. Confidence is reported for telemetry but never gates here
      // (abstain stays false without the hybrid relevance signal).
      rankedIds = this.groupAndHoist(bm25Ids, queryTerms);
      confidence = this.bm25Confidence(bm25Positive);
    }

    // Apply exact-name pin: move tools of pinned servers to the front of
    // rankedIds, preserving their relative tool-level order. Pinned servers
    // appear in pinnedServerSlugs order (longer slug first), so a query that
    // matches both "atlassian-jira" and "jira" gets atlassian-jira pinned
    // ahead of jira.
    if (pinnedServerSlugs.length > 0) {
      const pinnedSet = new Set(pinnedServerSlugs);
      const pinnedIds: string[] = [];
      const otherIds: string[] = [];
      // Preserve the priority order: iterate pinnedServerSlugs and pull every
      // ranked id whose server matches in order.
      for (const slug of pinnedServerSlugs) {
        for (const id of rankedIds) {
          const tool = this.resolveToolForId(id, options?.tenantId);
          if (tool && tool.server === slug) pinnedIds.push(id);
        }
      }
      for (const id of rankedIds) {
        const tool = this.resolveToolForId(id, options?.tenantId);
        if (!tool || !pinnedSet.has(tool.server)) otherIds.push(id);
      }
      // Also include pinned-server tools that BM25 did NOT rank (score=0
      // or missed the topN slice) so the explicit name match wins even when
      // the keyword overlap on the rest of the query was sparse.
      const pinnedAlreadyIncluded = new Set(pinnedIds);
      for (const slug of pinnedServerSlugs) {
        for (const doc of sortedCandidates) {
          if (doc.tool.server !== slug) continue;
          const fullId = `${doc.tool.server}:${doc.tool.name}`;
          if (!pinnedAlreadyIncluded.has(fullId)) {
            pinnedIds.push(fullId);
            pinnedAlreadyIncluded.add(fullId);
          }
        }
      }
      rankedIds = [...pinnedIds, ...otherIds];
    }

    // `tierOf` is defined once, earlier in this method (immediately after
    // `finalize`), so the zero-lexical-signal early-return path above and
    // every path below share the exact same resolver.
    //
    // BIEN::§7a::1/5/6/7/14 — partition THEN assert, called immediately
    // before each of the exit points below builds its final returned id
    // list, so every list that actually LEAVES this method (never an
    // intermediate state a later step can still mutate) is both partitioned
    // and invariant-checked. `stablePartitionOfficialIds` is a stable
    // partition (Array.prototype.sort, ES2019+ stability), so ties
    // preserve the accumulated fusion+rerank+§4.6-hoist+pin ordering,
    // satisfying §7a::7's within-partition tiebreak without re-deriving it
    // (no `rerankScore` survives to this call site — see
    // OfficialPartition.ts's docstring). `assertOfficialPartitionInvariantIds`
    // throws `OfficialPartitionInvariantError` (code
    // `retrieval_partition_invariant_failed`, MASTER ruling item 90) on any
    // violation — the query FAILS, propagating like any other synchronous
    // throw through select()/selectWithVerdict()/selectSync(), NEVER
    // silently substituting the un-partitioned order and NEVER the
    // separate `rerankerFailed` BM25 degradation used elsewhere in this
    // file for a different failure class (a leg/reranker exception, not a
    // proven partition-ordering violation).
    const finalizePartitionedIds = (ids: string[]): string[] => {
      const partitioned = stablePartitionOfficialIds(ids, tierOf);
      assertOfficialPartitionInvariantIds(partitioned, tierOf);
      return partitioned;
    };

    // Whole-pool completeness: when every candidate already fits within
    // maxTools the shortlist will show all of them, so neither the maxPerServer
    // diversity cap nor rank truncation applies. Return the full pool in
    // BM25+pin order, appending any tools BM25 left unscored (and that no pin
    // surfaced) in deterministic id order. This replaces a prior short-circuit
    // that returned the whole small pool in plain alphabetical order, ignoring
    // BM25 and pins entirely.
    //
    // BIEN::§7a::1/5 — the straggler append below runs BEFORE
    // finalizePartitionedIds, not after: partitioning only `rankedIds` and
    // then appending unpartitioned stragglers afterward would let an
    // official straggler land after a non-official record already in
    // `rankedIds` (the defect a prior revision of this method had — the
    // partition must cover the COMPLETE post-rerank candidate list, and
    // the stragglers are part of that complete list, not an addendum to
    // an already-finalized one).
    if (sortedCandidates.length <= maxTools) {
      const inRanked = new Set(rankedIds);
      for (const doc of sortedCandidates) {
        const id = `${doc.tool.server}:${doc.tool.name}`;
        if (!inRanked.has(id)) {
          rankedIds.push(id);
          inRanked.add(id);
        }
      }
      const ordered = finalizePartitionedIds(rankedIds)
        .map((id) => this.resolveToolForId(id, options?.tenantId))
        .filter((t): t is Tool => t !== undefined);
      return finalize(ordered);
    }

    // Select with server diversity constraint
 // integrate maxTokens into the selection loop so an early
    // over-budget tool does NOT consume a server slot. Tools that exceed
    // the running cost are skipped; the loop continues searching for a
    // cheaper tool further down the ranking.
    //
    // BIEN::§7a::5/6/8 — partition `rankedIds` BEFORE this loop scans it,
    // so official candidates get first claim on the maxPerServer/token
    // slots the loop hands out; §7a::14's assert then re-runs on the
    // ACTUAL selected output below (a subsequence of a correctly
    // partitioned sequence stays correctly partitioned by construction,
    // but the assert is unconditional here too — one shared discipline,
    // not a proof left unverified for this path).
    rankedIds = finalizePartitionedIds(rankedIds);
    const selected: Tool[] = [];
    const selectedIds: string[] = [];
    const serverCounts = new Map<string, number>();
    const maxTokensBudget = options?.maxTokens;
    let runningCost = 0;

    for (const id of rankedIds) {
      if (selected.length >= maxTools) break;

      const tool = this.resolveToolForId(id, options?.tenantId);
      if (!tool) continue;

      const serverCount = serverCounts.get(tool.server) ?? 0;
      if (serverCount >= maxPerServer) continue;

      if (maxTokensBudget !== undefined) {
        const cost = this.tokenCostByToolId.get(id) ?? this.tokenEstimator(tool);
        if (runningCost + cost > maxTokensBudget) continue;
        runningCost += cost;
      }

      selected.push(tool);
      selectedIds.push(id);
      serverCounts.set(tool.server, serverCount + 1);
    }

    // BIEN::§7a::14 — assert the ACTUAL returned list, not just the
    // pre-loop input (see the comment above the loop).
    assertOfficialPartitionInvariantIds(selectedIds, tierOf);
    return finalize(selected);
  }

  /**
   * Confidence for the BM25-only path (CH-37 telemetry; never gates). Reuses the
   * shared `scoreConfidence` calibration over the top-2 BM25 candidates so the
   * signal is comparable to the hybrid path: a strong, well-separated top-1
   * reads high; a weak or ambiguous one reads low.
   */
  private bm25Confidence(bm25Positive: { tool: Tool; score: number; id: string }[]): number {
    if (bm25Positive.length === 0) return 0;
    const top2: RetrievalResult[] = bm25Positive.slice(0, 2).map((s, i) => ({
      id: s.id,
      fusionScore: s.score,
      fusionSources: [{ type: 'bm25', rank: i, originalScore: s.score }],
    }));
    return scoreConfidence(top2).confidence;
  }

  /**
   * Synchronous shortlist — identical ranking to select() via the shared
   * selectInternal() implementation, for callers that cannot await. Applies
   * the same BM25 + pins + brand-hoist path (including query expansion), so a
   * given query yields the same shortlist whether reached sync or async.
   */
  selectSync(query: string, options?: PreFilterOptions): Tool[] {
    return this.selectInternal(query, options).tools;
  }

  /**
   * Group an ordered tool-id list by server (preserving first-seen server
   * order), then hoist brand-matched servers (every distinctive slug token
   * present in the query) to the front. Shared by the BM25 and hybrid paths so
   * the brand-hoist semantics are identical regardless of how the base order
   * was produced. Unknown ids (not in the routing index) are skipped.
   */
  private groupAndHoist(
    orderedIds: string[],
    queryTerms: string[],
    /** §8.6a — resolves an `overlay:` id `this.toolIdMap` never contains
     * (built once, at index time, from declared adapters only). Omitted by
     * the BM25-only call sites, which never see an overlay: id. */
    resolveExtra?: (id: string) => Tool | undefined,
  ): string[] {
    const serverOrder: string[] = [];
    const idsByServer = new Map<string, string[]>();
    for (const id of orderedIds) {
      const tool = this.toolIdMap.get(id) ?? resolveExtra?.(id);
      if (!tool) continue;
      let bucket = idsByServer.get(tool.server);
      if (bucket === undefined) {
        bucket = [];
        idsByServer.set(tool.server, bucket);
        serverOrder.push(tool.server);
      }
      bucket.push(id);
    }
    const querySet = new Set(queryTerms);
    const brandMatched: string[] = [];
    const others: string[] = [];
    for (const server of serverOrder) {
      if (this.allSlugTokensInQuery(server, querySet) && this.slugIsDistinctive(server)) {
        brandMatched.push(server);
      } else {
        others.push(server);
      }
    }
    const out: string[] = [];
    for (const server of [...brandMatched, ...others]) {
      const bucket = idsByServer.get(server);
      if (bucket) out.push(...bucket);
    }
    return out;
  }

  /** Number of indexed tools */
  get size(): number {
    return this.docs.length;
  }
}
