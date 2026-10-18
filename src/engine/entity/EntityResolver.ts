/**
 * @epicai/chariot — Entity Resolver
 * Engine-level entity intelligence service: resolve, compare, and profile
 * entities via a unified, gateway-independent resolver. Each operation probes
 * the top-`maxAdapters` most query-relevant adapters (relevance-ranked over
 * the candidate set, default 12, max 50) — NOT the full catalog; use
 * `adapterIds` to scope explicitly, and read `candidateCount` /
 * `unprobedAdapters` on the result to detect partial fan-out.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { ChariotState } from '../server/ChariotState.js';
import type { CallContext } from '../server/toolHandlers.js';
import { createLogger } from '../logger.js';

const log = createLogger('engine.entity.resolver');

/**
 * Maximum number of adapter probes dispatched concurrently within a single
 * resolve(). `maxAdapters` bounds the total work-set; this bounds how many of
 * those run in parallel, so a wide fan-out (or compare(), which runs two
 * resolves) cannot spawn an unbounded number of stdio/docker subprocesses at
 * once (EMFILE/ENOMEM protection).
 */
const PROBE_CONCURRENCY = 8;

/**
 * Per-probe interactive wall-clock budget, in ms. (§1.4 latency SLO):
 * resolve() awaits EVERY probe (mapWithConcurrency → Promise.all), so its
 * wall-clock is set by the SLOWEST probe. handleCall's transport dispatch
 * ceiling is DEFAULT_DISPATCH_TIMEOUT_MS = 30s — a black-holed adapter in the
 * fan-out therefore pinned a single-entity resolve at a fixed ~30s even when a
 * fast source had already resolved in ~200ms. That 30s is a transport-hang
 * *safety* bound, NOT an interactive one. The resolver, which deliberately
 * fans out to many adapters, needs a tighter per-probe budget so one slow/hung
 * adapter cannot dominate the aggregate latency. A probe that exceeds this
 * budget is treated as a MISS (fail-closed abstention — identical handling to
 * an errored/empty probe): its evidence is simply not collected, never
 * fabricated. Overridable per call via EntityResolveOpts.probeTimeoutMs.
 */
const PROBE_BUDGET_MS = 5_000;

/**
 * Overall fan-out wall-clock budget, in ms. Bounds the ENTIRE resolve()
 * fan-out regardless of how many concurrency waves the target set spans (with
 * PROBE_CONCURRENCY workers a per-probe budget alone caps latency at
 * ceil(targets/concurrency) × probeBudget). Each probe races against
 * min(probeBudget, remaining-until-deadline); once the deadline passes, any
 * still-unstarted/in-flight probe is a miss and resolve() returns promptly with
 * whatever sources responded in time. Overridable via
 * EntityResolveOpts.fanoutTimeoutMs. Must be >= a single probe budget.
 */
const FANOUT_BUDGET_MS = 8_000;

/**
 * Sentinel distinguishing a probe that blew its wall-clock budget from a probe
 * that resolved to a real (possibly error) CallResult. Returned by `withProbeBudget`
 * so the caller records a miss rather than awaiting the underlying dispatch to
 * its 30s transport ceiling.
 */
const PROBE_TIMED_OUT = Symbol('probe-timed-out');

/**
 * Race `op` against a `budgetMs` wall-clock. Resolves to the op's value if it
 * settles first, or to PROBE_TIMED_OUT on budget breach. The underlying
 * dispatch keeps running in the background (handleCall reaps its own transport
 * at the 30s ceiling); a late rejection is swallowed so it can never surface as
 * an unhandledRejection after the race is already decided. The timer is always
 * cleared so a fast probe never keeps the event loop alive to the budget.
 */
function withProbeBudget<T>(op: Promise<T>, budgetMs: number): Promise<T | typeof PROBE_TIMED_OUT> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<typeof PROBE_TIMED_OUT>((resolve) => {
    timer = setTimeout(() => resolve(PROBE_TIMED_OUT), budgetMs);
  });
  op.catch(() => { /* swallow late rejection once the race is already settled */ });
  return Promise.race([op, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

/**
 * Run `fn` over `items` with at most `limit` invocations in flight at a time.
 * Resolves once every item has been processed; individual rejections are the
 * callback's responsibility (callers below catch per-probe).
 */
async function mapWithConcurrency<T>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<void>,
): Promise<void> {
  let idx = 0;
  const workerCount = Math.max(1, Math.min(limit, items.length));
  const workers = Array.from({ length: workerCount }, async () => {
    while (idx < items.length) {
      const current = idx++;
      await fn(items[current], current);
    }
  });
  await Promise.all(workers);
}

/**
 * Per-evidence serialized payload budget. A single probe's payload is already
 * capped at MAX_RESPONSE_BYTES (1 MiB) by handleCall, but 12–50 such payloads
 * aggregated verbatim into one entity response is an unbounded memory /
 * context bomb. Oversized payloads are replaced in `evidence` by an explicit
 * truncation marker (never a silent slice); the adapter still counts as a
 * source, and attribute extraction runs on the full in-memory payload first.
 */
const EVIDENCE_MAX_BYTES = 65_536;

// =============================================================================
// Public types
// =============================================================================

/**
 * A single piece of evidence about an entity from one adapter. A normalized,
 * gateway-independent evidence shape so callers see a structurally stable
 * response regardless of the source adapter.
 */
export interface EntityEvidence {
  /** Adapter that produced this evidence. */
  adapterId: string;
  /** Human-readable adapter name. */
  adapterName: string;
  /** Tool on that adapter that returned the data. */
  toolName: string;
  /** Raw content returned by the tool (string or parsed object). */
  data: unknown;
  /** Whether the adapter returned an error for this query. */
  isError: boolean;
}

/**
 * Result shape for resolve_entity — a canonical record plus all
 * supporting evidence from every adapter that recognised the entity.
 */
export interface ResolvedEntity {
  /**
   * CH-39 typed outcome. `resolved` when at least one adapter returned usable
   * (non-error) evidence; `no_source` when the fan-out completed but produced
   * zero usable sources. The handler maps `no_source` to isError:true so the
   * caller never sees the silent-false-success shape (isError:false + 0
   * sources + error noise) flagged in the 3.1.2 dogfood.
   */
  status: 'resolved' | 'no_source';
  /**
   * Echoes the input query verbatim (NO normalisation is applied); callers
   * must not treat case/whitespace variants as the same id.
   */
  canonicalId: string;
  /** Display name if resolvable; null when no adapter recognised the entity. */
  displayName: string | null;
  /** Category/type inferred from adapter responses (e.g. "user", "host", "package"). */
  entityType: string | null;
  /** Number of adapters that returned non-error evidence. */
  sourceCount: number;
  /**
   * All adapter-level evidence from adapters that returned USABLE (non-error)
   * data. Failed/empty probes are summarised in `probedAdapters` /
   * `missedAdapters` instead of being dumped here as error noise (CH-39).
   */
  evidence: EntityEvidence[];
  /**
   * Aggregated flat attribute bag built from the FULL (pre-truncation)
   * evidence payloads. compare()/profile() consume this instead of
   * re-deriving from `evidence`, whose oversized entries may be replaced by
   * truncation markers.
   */
  attributes: Record<string, unknown>;
  /** Number of adapters actually probed (after identity + tool-fit filtering). */
  probedAdapters: number;
  /**
   * Total coherent candidates considered BEFORE the maxAdapters cap.
   * `unprobedAdapters` = candidateCount - (adapters selected for probing);
   * non-zero means the fan-out was PARTIAL — callers must not read
   * status:'resolved' as "the whole catalog was consulted".
   */
  candidateCount: number;
  /** Count of coherent candidates dropped by the maxAdapters cap (see candidateCount). */
  unprobedAdapters: number;
  /** Adapters that were queried but returned no relevant data. */
  missedAdapters: string[];
  /**
   * Adapters skipped because their catalog identity is incoherent (e.g. an id
   * that does not correspond to its name — the 3.1.2 `4fetch` /
   * `@amcharts/amcharts5-mcp` scramble). Their identity is NOT re-emitted as a
   * source; it is reported here by the (authoritative) lookup-key id only.
   */
  flaggedAdapters: Array<{ id: string; reason: 'identity_incoherent' }>;
  /**
   * Caller-supplied adapterIds that did not match any adapter in the catalog.
   * Lets callers distinguish "no evidence found" from "the ids you passed do
   * not exist" — non-empty here means the scope was (partly) a typo.
   */
  unknownAdapterIds: string[];
  /** ISO timestamp of when the resolution ran. */
  resolvedAt: string;
}

/**
 * Per-field diff entry used by compare_entities.
 */
export interface EntityDiff {
  field: string;
  entityAValue: unknown;
  entityBValue: unknown;
  match: boolean;
}

/**
 * Result shape for compare_entities.
 */
export interface EntityComparison {
  /**
   * CH-39 typed outcome. `compared` only when BOTH entities resolved to at
   * least one usable source (so a similarity score is meaningful);
   * `no_comparison` when one or both sides produced no source — in which case
   * `similarityScore` is null, NOT a vacuous 0 that would falsely read as
   * "compared and found 0% similar".
   */
  status: 'compared' | 'no_comparison';
  entityA: string;
  entityB: string;
  /** 0.0–1.0 — fraction of comparable fields that matched; null on no_comparison. */
  similarityScore: number | null;
  /** Number of usable sources found for each side (so the caller sees WHY no_comparison). */
  entityASourceCount: number;
  entityBSourceCount: number;
  /** Fields where the two entities differ. */
  diffs: EntityDiff[];
  /**
   * True when similarityScore >= 0.9 (attribute-overlap heuristic computed
   * by compare()). This is NOT an adapter-asserted identity match — no
   * adapter is asked whether the two records are the same entity.
   */
  resolvedAsSame: boolean;
  /** Caller-supplied adapterIds that matched no adapter (applies to both entities). */
  unknownAdapterIds: string[];
  resolvedAt: string;
}

/**
 * Result shape for entity_profile — a structured summary of everything
 * Chariot knows about an entity aggregated from all adapters.
 */
export interface EntityProfile {
  /**
   * CH-39 typed outcome. `profiled` when at least one adapter returned usable
   * data; `no_source` when the fan-out produced none — in which case the
   * handler maps to isError:true and `adapterData`/`attributes` are returned
   * empty by construction, but the typed status makes that an explicit
   * no-source result, NOT an undifferentiated empty shell.
   */
  status: 'profiled' | 'no_source';
  entityId: string;
  displayName: string | null;
  entityType: string | null;
  /** Adapters that have data about this entity. */
  knownAdapters: string[];
  /** Raw evidence from each adapter, keyed by adapter id. */
  adapterData: Record<string, unknown>;
  /** Structured attribute bag (flattened from adapter responses). */
  attributes: Record<string, unknown>;
  /** Adapters skipped for incoherent catalog identity (see ResolvedEntity.flaggedAdapters). */
  flaggedAdapters: Array<{ id: string; reason: 'identity_incoherent' }>;
  /** Caller-supplied adapterIds that matched no adapter. */
  unknownAdapterIds: string[];
  profiledAt: string;
}

/** Options shared by resolve/compare/profile. */
export interface EntityResolveOpts {
  adapterIds?: string[];
  maxAdapters?: number;
  /**
   * Per-probe interactive wall-clock budget in ms (default PROBE_BUDGET_MS). A
   * single adapter probe that exceeds this is treated as a miss so one hung
   * adapter cannot pin resolve() at the 30s transport dispatch ceiling.
   * Must be > 0.
   */
  probeTimeoutMs?: number;
  /**
   * Overall fan-out wall-clock budget in ms (default FANOUT_BUDGET_MS). Bounds
   * the whole resolve() regardless of concurrency-wave count. Must be > 0.
   */
  fanoutTimeoutMs?: number;
}

// =============================================================================
// Internal helpers
// =============================================================================

/** A tool candidate with the optional description the catalog published for it. */
export interface ToolCandidate {
  name: string;
  description?: string;
  /**
   * MCP tool annotations, when the catalog published them. When present,
   * `readOnlyHint === true` is the authoritative read-only signal for the
   * mutation gate; any other annotated value disqualifies the tool from a
   * blind probe. Absence falls through to the strict name heuristic — never
   * to "allowed".
   */
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean };
}

/**
 * Structural view of the fields EntityResolver reads off an adapter row. The
 * concrete AdapterEntry type carries far more; this local shape keeps the
 * resolver decoupled and lets it read the per-tool metadata defensively.
 */
interface AdapterLike {
  id?: string;
  name?: string;
  description?: string;
  keywords?: string[];
  category?: string;
  rest?: { toolNames?: string[]; tools?: Array<{ name: string; description?: string; annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean } }> };
  mcp?: { toolNames?: string[]; tools?: Array<{ name: string; description?: string; annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean } }> };
  // cli-bridge adapters (AS §1.5) carry their tool surface in
  // cli.toolSchemas[] so entity-based tool selection can reach them during query.
  cli?: { toolSchemas?: Array<{ name: string; description?: string }> };
}

/**
 * Build the candidate tool set for an adapter, preferring per-tool metadata
 * (name + description, when the bundle published rest.tools[]/mcp.tools[]) and
 * falling back to the bare name list. Descriptions let selectEntityTool score
 * semantically even when a tool name is opaque.
 */
function buildToolCandidates(adapter: AdapterLike): ToolCandidate[] {
  const detailed = adapter.rest?.tools ?? adapter.mcp?.tools ?? adapter.cli?.toolSchemas;
  if (detailed && detailed.length > 0) {
    return detailed
      .filter((t) => t && typeof t.name === 'string')
      .map((t) => ({
        name: t.name,
        ...(t.description ? { description: t.description } : {}),
        ...('annotations' in t && t.annotations && typeof t.annotations === 'object' ? { annotations: t.annotations } : {}),
      }));
  }
  const names = adapter.rest?.toolNames ?? adapter.mcp?.toolNames ?? adapter.cli?.toolSchemas?.map((s) => s.name) ?? [];
  return names.filter((n) => typeof n === 'string').map((n) => ({ name: n }));
}

/**
 * Read-intent verbs that make a tool a plausible entity-lookup surface,
 * scored by how specifically they denote "look this entity up and return what
 * you know about it". Higher = better fit. `get`/`fetch`/`read` are weak
 * signals (they match `get_vault` on a password manager just as readily as a
 * real lookup) so they score low and only win when nothing better exists.
 */
const ENTITY_INTENT_SCORES: ReadonlyArray<readonly [RegExp, number]> = [
  [/\b(resolve|whois|lookup|look_up)\b/, 10],
  [/\b(search|find|query)\b/, 8],
  [/\b(profile|describe|details|detail|info|information|enrich)\b/, 6],
  [/\b(list|browse|scan)\b/, 4],
  [/\b(get|fetch|read|show|view|retrieve)\b/, 2],
];

/**
 * Verb lexicon that marks a tool NAME as MUTATING or otherwise unsafe to fire
 * blindly during a read-only entity probe. Any name token in this set
 * disqualifies the tool — a resolution must never create/delete/charge/rotate
 * state as a side effect of "tell me about X". (The 3.1.2 dogfood fired a
 * password vault's `get_vault` for "Stripe"; mutation guards close the
 * worse-than-noise cases.)
 *
 * Fail-closed layering (a bare denylist over an unbounded verb space is
 * fail-open by construction — `search_and_replace` used to slip through on
 * its `search` token):
 *   1. When the catalog publishes MCP tool annotations, ONLY
 *      `readOnlyHint === true` is probe-eligible; any other annotated value
 *      disqualifies. Absence of annotations falls through to (2), never to
 *      "allowed".
 *   2. The tool NAME's tokens are screened against this lexicon — one
 *      mutating token disqualifies regardless of any read-ish sibling token.
 *   3. Eligibility still requires a positive read-intent match
 *      (ENTITY_INTENT_SCORES) — a tool with no recognised read verb never
 *      fires at all.
 * The lexicon is deliberately broad: a false positive merely skips a tool
 * (miss), a false negative fires a mutation. When in doubt, add the verb.
 */
const MUTATION_VERBS: ReadonlySet<string> = new Set([
  'create', 'update', 'delete', 'remove', 'destroy', 'set', 'put', 'post',
  'patch', 'write', 'add', 'insert', 'drop', 'revoke', 'rotate', 'reset',
  'send', 'charge', 'refund', 'pay', 'transfer', 'cancel', 'approve',
  'deploy', 'execute', 'run', 'invoke', 'trigger', 'start', 'stop', 'kill',
  'terminate', 'grant', 'disable', 'enable',
  // Fail-closed expansion — verbs the original denylist missed:
  'replace', 'purge', 'wipe', 'erase', 'clear', 'flush', 'truncate', 'merge',
  'publish', 'unpublish', 'upload', 'move', 'rename', 'edit', 'apply',
  'submit', 'sync', 'import', 'export', 'copy', 'clone', 'restore', 'assign',
  'unassign', 'attach', 'detach', 'link', 'unlink', 'archive', 'unarchive',
  'restart', 'reboot', 'scale', 'promote', 'demote', 'lock', 'unlock',
  'suspend', 'resume', 'install', 'uninstall', 'upgrade', 'downgrade',
  'migrate', 'seed', 'mint', 'issue', 'register', 'unregister', 'subscribe',
  'unsubscribe', 'acknowledge', 'ack', 'close', 'reopen', 'open', 'save',
  'store', 'push', 'pull', 'commit', 'revert', 'rollback', 'undo', 'redo',
  'modify', 'change', 'toggle', 'switch', 'configure', 'provision',
  'deprovision', 'allocate', 'deallocate', 'release', 'claim', 'reserve',
  'schedule', 'unschedule', 'enqueue', 'dequeue', 'requeue', 'retry',
  'escalate', 'forget', 'redact', 'anonymize', 'encrypt', 'decrypt', 'sign',
  'verify', 'authorize', 'deauthorize', 'ban', 'unban', 'block', 'unblock',
  'mute', 'unmute', 'follow', 'unfollow', 'like', 'unlike', 'react', 'reply',
  'forward', 'share', 'invite', 'uninvite', 'join', 'leave', 'accept',
  'reject', 'decline', 'complete', 'finish', 'abort', 'expire',
]);

/** Split a tool name into lowercase tokens along conventional separators. */
function toolNameTokens(name: string): string[] {
  return name
    // split camelCase boundaries before separator split (searchAndReplace)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0);
}

/**
 * Score a single tool for entity-lookup fitness against the query tokens.
 * Returns a number; ≤0 means "not a usable entity tool". Name + description
 * are tokenized so a tool whose name is opaque but whose description says
 * "search the registry for a package" still scores. Query-token overlap adds
 * a small semantic bonus so, given several read tools, the one whose surface
 * text relates to the entity wins over an unrelated read tool.
 */
export function scoreEntityTool(tool: ToolCandidate, queryTokens: ReadonlySet<string>): number {
  // ---- Mutation gate (fail-closed, layered) ---------------------------------
  // Layer 1: authoritative MCP annotations, when published. Only an explicit
  // readOnlyHint === true is probe-eligible; an annotated tool that is not
  // explicitly read-only (or is flagged destructive) is disqualified.
  const ann = tool.annotations;
  if (ann && typeof ann === 'object' && ('readOnlyHint' in ann || 'destructiveHint' in ann)) {
    if (ann.destructiveHint === true || ann.readOnlyHint !== true) return -1;
    // readOnlyHint === true → verified read-only; the name heuristic below is
    // skipped (a read-only tool named e.g. `search_and_replace_preview` stays
    // eligible on the adapter's own authority).
  } else {
    // Layer 2: strict heuristic over the tool NAME's tokens only. One
    // mutating verb token disqualifies regardless of read-ish siblings
    // (`search_and_replace` → 'replace' → rejected). The description is
    // deliberately NOT screened here — a pure read tool whose description
    // says "results can be used to update records" must remain eligible
    // (the old whole-haystack regex zeroed such tools); the description
    // still participates in positive intent scoring below.
    for (const t of toolNameTokens(tool.name)) {
      if (MUTATION_VERBS.has(t)) return -1;
    }
  }
  const haystack = `${tool.name} ${tool.description ?? ''}`
    .toLowerCase()
    .replace(/[_\-./]+/g, ' ');
  let best = 0;
  for (const [re, weight] of ENTITY_INTENT_SCORES) {
    if (re.test(haystack)) { best = Math.max(best, weight); }
  }
  if (best === 0) return 0;
  // Semantic overlap bonus: reward tools whose surface text shares a token
  // with the query (bounded so it never outweighs the intent class).
  const toolTokens = new Set(haystack.split(/\s+/).filter((w) => w.length > 2));
  let overlap = 0;
  for (const qt of queryTokens) { if (toolTokens.has(qt)) overlap++; }
  return best + Math.min(3, overlap);
}

/**
 * Select the best entity-lookup tool from a candidate set SEMANTICALLY (CH-39)
 * rather than by blind first-verb-prefix. Returns the highest-scoring eligible
 * tool, or null when none clears the bar (mutation-only / no read surface) —
 * in which case the adapter is a miss, not a forced probe of an unsafe tool.
 */
export function selectEntityTool(tools: readonly ToolCandidate[], queryTokens: ReadonlySet<string>): string | null {
  let bestName: string | null = null;
  let bestScore = 0;
  for (const t of tools) {
    if (!t || typeof t.name !== 'string' || t.name.length === 0) continue;
    const score = scoreEntityTool(t, queryTokens);
    if (score > bestScore) { bestScore = score; bestName = t.name; }
  }
  return bestScore > 0 ? bestName : null;
}

/** Lowercase word tokens (len>2), shared by the tool scorer and identity guard. */
function wordTokens(text: string): Set<string> {
  return new Set(
    text.toLowerCase().replace(/[^a-z0-9]+/g, ' ').split(/\s+/).filter((w) => w.length > 2),
  );
}

/**
 * CH-39 identity-coherence guard. A catalog row is incoherent when its `name`
 * is a raw package-style identifier (npm scope/path, or a `*-mcp` slug) whose
 * derived slug shares NO token with the adapter's authoritative id — the
 * 3.1.2 scramble where id `4fetch` was paired with name
 * `@amcharts/amcharts5-mcp`. Such a row's identity must not be re-emitted as a
 * source. Conservative by design: a normal display name ("Wikipedia",
 * "Stripe") is not package-shaped and is always treated as coherent, so this
 * never drops a legitimately-named adapter.
 */
export function isIdentityCoherent(id: string, name: string): boolean {
  if (typeof id !== 'string' || id.length === 0) return false;
  if (typeof name !== 'string' || name.length === 0) return true; // no name to contradict the id
  const looksPackageShaped = /[/@]/.test(name) || /[_-]mcp\b/i.test(name);
  if (!looksPackageShaped) return true; // ordinary display name — trust it
  const idTokens = wordTokens(id);
  const nameTokens = wordTokens(name);
  for (const t of idTokens) {
    if (nameTokens.has(t)) return true;
    // substring relation in either direction also counts as coherent
    for (const n of nameTokens) {
      if (t.length > 2 && (n.includes(t) || t.includes(n))) return true;
    }
  }
  return false;
}

/**
 * Normalise an entity tool result's content to a plain object.
 * Returns null when the content carries no extractable data.
 */
function normaliseContent(raw: unknown): Record<string, unknown> | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch { /* not JSON — return null */ }
  }
  return null;
}

/**
 * Conventional result-list keys used by search/lookup tools. When any of
 * these is present, the response is treated as a search-result envelope and
 * hits exist only when at least one list is non-empty (or a non-bookkeeping
 * sibling field carries data).
 */
const RESULT_LIST_KEYS: ReadonlySet<string> = new Set([
  'results', 'items', 'hits', 'data', 'matches', 'records', 'entries', 'values',
]);

/** Counter/pagination scaffolding that never constitutes entity evidence by itself. */
const BOOKKEEPING_KEYS: ReadonlySet<string> = new Set([
  'total', 'count', 'total_count', 'totalcount', 'total_results',
  'totalresults', 'num_results', 'numresults', 'page', 'pages', 'offset',
  'limit', 'per_page', 'perpage', 'page_size', 'pagesize', 'next', 'previous',
  'prev', 'cursor', 'next_cursor', 'nextcursor', 'has_more', 'hasmore',
  'took', 'elapsed', 'query', 'q', 'search',
  // adapter/dispatch envelope scaffolding — transport metadata Chariot wraps
  // around a tool result, NEVER entity-hit content. Without these a zero-result
  // search envelope (matches:[], count:0) whose only non-empty fields are
  // scaffolding counted as a hit → ghost-resolve ("dental-planning"
  // resolving Stripe). CH-39 fail-closed.
  'endpoint', 'mode', 'freshness', 'toolname', 'tool_name', 'tool',
  'latency', 'latencyms', 'latency_ms', 'cached', 'adapter', 'adapterid',
  'adapter_id',
]);

/** True when a value is structurally empty (no entity-bearing content). */
function isEmptyValue(v: unknown): boolean {
  if (v === null || v === undefined) return true;
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === 'string') return v.trim().length === 0;
  if (typeof v === 'number') return v === 0;
  if (typeof v === 'boolean') return v === false;
  if (typeof v === 'object') return Object.keys(v as object).length === 0;
  return false;
}

/**
 * CH-39 empty-hit gate: does a successful (non-error) tool response actually
 * carry entity hits? Transport success alone is NOT evidence — a search tool
 * returning `{"results":[],"total":0}` for a nonexistent entity previously
 * counted as a "source", producing status:'resolved' for ghost entities and
 * similarityScore 1.0 when two ghosts' identical empty scaffolding was
 * diffed. Fail closed: a response with no demonstrable hit content is a miss.
 */
export function hasEntityHits(content: unknown): boolean {
  let value: unknown = content;
  if (typeof value === 'string') {
    const s = value.trim();
    if (s.length === 0) return false;
    try {
      value = JSON.parse(s);
    } catch {
      // Non-JSON prose carries no verifiable hit structure — a probe must
      // demonstrate actual hit content to count as resolution evidence.
      return false;
    }
  }
  if (value === null || value === undefined) return false;
  if (Array.isArray(value)) return value.length > 0; // bare hit array
  if (typeof value !== 'object') return false; // bare number/bool/JSON-string
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length === 0) return false;
  const listKeys = keys.filter((k) => RESULT_LIST_KEYS.has(k.toLowerCase()));
  if (listKeys.length > 0) {
    // Search-result envelope: hits IFF a result list is non-empty. If every
    // result list is empty the tool found NOTHING — sibling fields (ok, count,
    // query, endpoint, mode, freshness, safety, timestamp, request_id, …) are
    // transport/status metadata, NEVER entity-hit content, and must not rescue
    // a zero-result envelope. Fail closed (CH-39). Enumerating scaffolding keys
    // was whack-a-mole (the live "dental-planning" payload leaked via
    // ok/safety/timestamp/request_id) — the result lists are the sole signal.
    for (const k of listKeys) {
      if (!isEmptyValue(obj[k])) return true;
    }
    return false;
  }
  // No conventional list keys: entity-bearing iff any non-bookkeeping field
  // has a non-empty value.
  for (const k of keys) {
    if (BOOKKEEPING_KEYS.has(k.toLowerCase())) continue;
    if (!isEmptyValue(obj[k])) return true;
  }
  return false;
}

/**
 * Count fields in an aggregated attribute bag that carry actual entity
 * content (non-bookkeeping, non-empty). Used by compare() as defense-in-depth
 * so identical empty scaffolding from the same probed tools can never score.
 */
function countEntityBearingFields(attrs: Record<string, unknown>): number {
  let n = 0;
  for (const [k, v] of Object.entries(attrs)) {
    const lk = k.toLowerCase();
    if (BOOKKEEPING_KEYS.has(lk)) continue;
    if (RESULT_LIST_KEYS.has(lk) && isEmptyValue(v)) continue;
    if (isEmptyValue(v)) continue;
    n++;
  }
  return n;
}

/**
 * Shallow flatten the fields of two normalised-content objects and
 * produce a diff list.
 */
function diffObjects(
  a: Record<string, unknown> | null,
  b: Record<string, unknown> | null,
): EntityDiff[] {
  const diffs: EntityDiff[] = [];
  const allKeys = new Set<string>([
    ...Object.keys(a ?? {}),
    ...Object.keys(b ?? {}),
  ]);
  for (const key of allKeys) {
    const aVal = a ? a[key] : undefined;
    const bVal = b ? b[key] : undefined;
    // Simple equality — JSON-stringify for structural comparison.
    const match = JSON.stringify(aVal) === JSON.stringify(bVal);
    if (!match) {
      diffs.push({ field: key, entityAValue: aVal, entityBValue: bVal, match: false });
    }
  }
  return diffs;
}

/**
 * Build a flat attribute bag from normalised evidence objects in DETERMINISTIC
 * target order (slot-indexed by the resolver — never async completion order,
 * which made last-writer-wins displayName/attribute values flap across runs).
 * Later entries for the same key win (last-writer-wins across adapters).
 */
function buildAttributesFromObjects(
  objects: ReadonlyArray<Record<string, unknown> | null | undefined>,
): Record<string, unknown> {
  const attrs: Record<string, unknown> = {};
  for (const obj of objects) {
    if (!obj) continue;
    for (const [k, v] of Object.entries(obj)) {
      attrs[k] = v;
    }
  }
  return attrs;
}

/**
 * Relevance score for ranking candidate adapters against the query BEFORE the
 * maxAdapters cap is applied. The fan-out previously probed the FIRST
 * maxAdapters rows in catalog-load order, making every adapter beyond the cap
 * structurally unreachable on the default path. Adapters with an eligible
 * read tool rank strictly above those without one (which could only ever be
 * misses); within each group, query-token overlap with the adapter's surface
 * text dominates, then best tool fitness. Ties keep candidate order (explicit
 * index tiebreak at the sort site), so ranking is deterministic for a given
 * catalog.
 */
function scoreAdapterRelevance(
  id: string,
  adapter: AdapterLike,
  queryTokens: ReadonlySet<string>,
): number {
  const surface = [
    id,
    typeof adapter.name === 'string' ? adapter.name : '',
    typeof adapter.description === 'string' ? adapter.description : '',
    typeof adapter.category === 'string' ? adapter.category : '',
    ...(Array.isArray(adapter.keywords)
      ? adapter.keywords.filter((k): k is string => typeof k === 'string')
      : []),
  ].join(' ');
  const tokens = wordTokens(surface);
  let overlap = 0;
  for (const qt of queryTokens) {
    if (tokens.has(qt)) overlap++;
  }
  let bestTool = 0;
  for (const t of buildToolCandidates(adapter)) {
    bestTool = Math.max(bestTool, scoreEntityTool(t, queryTokens));
  }
  if (bestTool <= 0) {
    // No eligible read/lookup tool — can never produce evidence; rank below
    // every adapter that has one.
    return overlap;
  }
  return 1_000 + overlap * 10 + bestTool;
}

/**
 * Infer an entity type label from the fields present in an attribute bag.
 */
function inferEntityType(attrs: Record<string, unknown>): string | null {
  const keys = new Set(Object.keys(attrs).map((k) => k.toLowerCase()));
  if (keys.has('username') || keys.has('email') || keys.has('user_id')) return 'user';
  if (keys.has('hostname') || keys.has('ip') || keys.has('host_id')) return 'host';
  if (keys.has('package_name') || keys.has('version') || keys.has('registry')) return 'package';
  if (keys.has('repo') || keys.has('repository') || keys.has('commit')) return 'repository';
  if (keys.has('alert_id') || keys.has('severity') || keys.has('finding_id')) return 'security-finding';
  if (keys.has('company') || keys.has('org_id') || keys.has('organization')) return 'organization';
  return null;
}

/**
 * Extract a display name from a normalised attribute bag.
 */
function extractDisplayName(attrs: Record<string, unknown>): string | null {
  for (const key of ['display_name', 'name', 'displayName', 'title', 'full_name', 'username', 'email']) {
    const v = attrs[key];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return null;
}

// =============================================================================
// EntityResolver
// =============================================================================

export class EntityResolver {
  private readonly state: ChariotState;

  constructor(state: ChariotState) {
    this.state = state;
  }

  /**
   * Rank the coherent candidate adapters by how likely they are to HOLD the
   * queried entity, BEFORE the maxAdapters cap slices the probe set. This is
   * the recall-critical step: the fan-out budget only probes the top `cap`, so
   * if the true holder is not ranked into that prefix it is never probed and a
   * resolvable entity returns no_source (recall regression).
   *
   * Primary signal is the catalog's OWN relevance ranking — the same BM25
   * pre-filter `chariot_query` routes with (state.fullCatalogFilter). It
   * applies IDF, exact-adapter-name pinning and brand-token hoisting, so for a
   * brand/product entity ("GitHub", "Stripe", "Kubernetes") the adapter that
   * actually owns it pins to the top instead of drowning under the hundreds of
   * adapters that merely declare a generic read tool. Adapters the pre-filter
   * does not score for this query (e.g. a bare username with no lexical match,
   * where BM25 legitimately returns nothing) fall back to a reachability signal
   * then the local `scoreAdapterRelevance` heuristic — so recall is never WORSE
   * than the pre-fix behaviour and a genuine no-lexical-signal entity still
   * abstains (fail-closed) rather than being force-resolved.
   *
   * Reachability sub-key (below BM25, above the lexical heuristic): among
   * adapters the pre-filter did NOT lexically rank, prefer the ones the caller
   * has actually CONFIGURED (credentials present). An unconfigured adapter can
   * only ever return an auth error — a guaranteed miss — so probing it burns a
   * budget slot the resolver could have spent on a reachable general-purpose
   * resolver (e.g. a configured web-search adapter) that CAN answer an entity
   * BM25 could not route (the audit's bare-identifier case). This never
   * reorders a lexically-matched holder (BM25 rank dominates); it only breaks
   * ties inside the no-lexical-signal tier. Deterministic: final tiebreak is
   * original candidate index.
   */
  private rankCandidatesByRelevance(
    coherent: ReadonlyArray<{ id: string; adapter: AdapterLike }>,
    entityQuery: string,
    queryTokens: ReadonlySet<string>,
  ): Array<{ id: string; adapter: AdapterLike }> {
    // BM25 rank of each adapter id for this query (lower = more relevant).
    // maxPerServer:1 → one entry per adapter; ask for well beyond any plausible
    // maxAdapters cap so the ranked prefix is deep enough to fill the budget.
    const bm25Rank = new Map<string, number>();
    const filter = this.state.fullCatalogFilter;
    if (filter && typeof filter.selectSync === 'function') {
      try {
        // shortlist-size: > 12 OK because this is the relevance-ranking breadth
        // for entity resolution (rank the full catalog, then probe only the top
        // candidates within the 5s/8s fan-out budget) — not a per-dispatch tool
        // shortlist. (recall fix.)
        const rankedTools = filter.selectSync(entityQuery, { maxTools: 128, maxPerServer: 1 });
        let r = 0;
        for (const t of rankedTools) {
          const server = (t as { server?: unknown }).server;
          if (typeof server === 'string' && !bm25Rank.has(server)) {
            bm25Rank.set(server, r++);
          }
        }
      } catch (err) {
        // Pre-filter failure must never sink the resolve — degrade to the
        // local heuristic (below) rather than throwing on the fan-out path.
        log.debug('entity_resolve_prefilter_rank_failed', {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    const configured = this.state.configuredAdapterIds;
    const INF = Number.POSITIVE_INFINITY;
    return coherent
      .map((c, i) => ({
        c,
        i,
        // BM25-ranked adapters sort first (by ascending rank); unranked ones
        // share +Infinity and are ordered by the reachability + heuristic tiers.
        bm25: bm25Rank.has(c.id) ? (bm25Rank.get(c.id) as number) : INF,
        // 0 = configured/reachable (can actually answer), 1 = not. Only
        // discriminates inside the no-lexical-signal tier (see doc-comment).
        cfg: configured && configured.has(c.id) ? 0 : 1,
        heur: scoreAdapterRelevance(c.id, c.adapter, queryTokens),
      }))
      .sort((a, b) => {
        // Guard: Infinity - Infinity is NaN (unstable sort). Equal ranks
        // (including both-unranked) fall through to reachability then the
        // heuristic tiebreak.
        const byBm25 = a.bm25 === b.bm25 ? 0 : a.bm25 - b.bm25;
        return byBm25 || (a.cfg - b.cfg) || (b.heur - a.heur) || (a.i - b.i);
      })
      .map((r) => r.c);
  }

  /**
   * Resolve an entity by querying the top-`maxAdapters` most query-relevant
   * adapters (relevance-ranked; default 12) that declare a plausible
   * search/lookup tool. Fans out (bounded concurrency) and aggregates
   * evidence from all responding adapters. The fan-out is PARTIAL by design —
   * `candidateCount`/`unprobedAdapters` on the result report how many
   * candidates were left unprobed by the cap.
   *
   * SECURITY: `ctx` carries the caller's tenantId/auth/localMode and is passed
   * verbatim to handleCall so the per-operation RBAC and per-tenant rate-limit
   * apply to every fan-out call. It MUST be the caller's real context — never a
   * synthetic `{ localMode: true }`, which would bypass RBAC (deny-by-default).
   */
  async resolve(entityQuery: string, opts: EntityResolveOpts = {}, ctx?: CallContext): Promise<ResolvedEntity> {
    const resolvedAt = new Date().toISOString();
    const missedAdapters: string[] = [];
    const flaggedAdapters: Array<{ id: string; reason: 'identity_incoherent' }> = [];
    const unknownAdapterIds: string[] = [];

    // CHARIOT::§23.2::70 — resolve_entity returns real sources or a
    // typed no-source failure, NEVER isError:false with 0 sources): an empty /
    // whitespace-only query is NO INPUT, never a
    // resolvable entity. The emptiness gate must screen the TRIMMED input — an
    // untrimmed "   " has non-zero length and previously sailed into the
    // fan-out, where a permissive search adapter echoed scaffolding back and
    // the resolver recorded it as a false source (status:'resolved',
    // sourceCount>=1; two such ghosts compared at similarityScore 1.0 /
    // resolvedAsSame:true). Reject as no_source WITHOUT dispatching any probe,
    // so no source is ever fabricated. Only the validity check is trimmed; the
    // echoed canonicalId stays VERBATIM per the ResolvedEntity contract.
    if (entityQuery.trim().length === 0) {
      return {
        status: 'no_source',
        canonicalId: entityQuery,
        displayName: null,
        entityType: null,
        sourceCount: 0,
        evidence: [],
        attributes: {},
        probedAdapters: 0,
        candidateCount: 0,
        unprobedAdapters: 0,
        missedAdapters,
        flaggedAdapters,
        unknownAdapterIds,
        resolvedAt,
      };
    }

    // Scope to the caller-supplied adapter list or the full catalog. Unknown
    // ids are surfaced (not silently dropped) so a typo is distinguishable
    // from a genuine no-evidence result. `state.adapterById` is keyed by the
    // authoritative id, so the lookup key is always the canonical id even when
    // a row's own fields are scrambled.
    let candidates: Array<{ id: string; adapter: AdapterLike }>;
    if (opts.adapterIds) {
      candidates = [];
      for (const id of opts.adapterIds) {
        const a = this.state.adapterById.get(id) as AdapterLike | undefined;
        if (a) candidates.push({ id, adapter: a });
        else unknownAdapterIds.push(id);
      }
    } else {
      candidates = (this.state.allAdapters as AdapterLike[]).map((a, i) => ({
        // Prefer the row's own id, but fall back to nothing-trusted only when
        // present; the catalog key is reconstructed via adapterById below.
        id: typeof a.id === 'string' && a.id.length > 0 ? a.id : `adapter-${i}`,
        adapter: a,
      }));
    }

    // CH-39 identity guard — drop rows whose catalog identity is incoherent so
    // a scrambled id/name pair is never re-emitted as a source. Probe against
    // the authoritative lookup-key id.
    const coherent: Array<{ id: string; adapter: AdapterLike }> = [];
    for (const c of candidates) {
      if (isIdentityCoherent(c.id, typeof c.adapter.name === 'string' ? c.adapter.name : '')) {
        coherent.push(c);
      } else {
        flaggedAdapters.push({ id: c.id, reason: 'identity_incoherent' });
      }
    }

    const rawMax = opts.maxAdapters ?? 12;
    if (rawMax < 1) {
      // Negative → slice(0, N) probes the wrong count; 0 → always no_source with
      // no diagnostic. Both are caller errors; fail loudly rather than silently.
      throw new RangeError(
        `EntityResolver.resolve: maxAdapters must be >= 1, got ${rawMax}.`,
      );
    }
    const queryTokens = wordTokens(entityQuery);

    // Relevance-rank the coherent candidates BEFORE applying the cap so the
    // probe budget is spent on the adapters most likely to HOLD the entity,
    // not on the first `maxAdapters` rows in catalog-load order. The prior
    // local heuristic flat-based every read-capable adapter at ~1000, so the
    // hundreds of adapters that merely declare a generic read/search tool tied
    // and the sort collapsed to load order — the true holder (e.g. `github`
    // for "GitHub", which the catalog's own BM25 router ranks #1) was buried
    // past the cap and never probed, so a resolvable entity returned no_source
    // (recall regression). Rank via the shared pre-filter instead.
    const ranked = this.rankCandidatesByRelevance(coherent, entityQuery, queryTokens);
    const cap = Math.min(rawMax, ranked.length);
    const targets = ranked.slice(0, cap);
    const candidateCount = coherent.length;
    const unprobedAdapters = candidateCount - targets.length;

    // Import lazily to avoid a circular module dependency — EntityResolver
    // lives under src/engine/entity/ and toolHandlers under src/engine/server/;
    // a top-level import would create a cycle. Resolved once per call (the
    // loader caches it) rather than once per probe.
    const { handleCall } = await import('../server/toolHandlers.js');

    // CH-39: derive a fan-out context that is exempt from the session-surface
    // gate (which the resolver could never satisfy — it never runs
    // chariot_query) while preserving the caller's tenant/auth so RBAC,
    // rate-limit, and tenant accounting still apply.
    //
    // SECURITY: ctx MUST be the real caller context. Spreading `{}` when ctx
    // is absent produces a context without tenantId/auth — effectively a
    // synthetic permissive context that bypasses RBAC (deny-by-default). Fail
    // closed instead.
    if (!ctx) {
      throw new Error(
        'EntityResolver.resolve: ctx is required for RBAC-safe fan-out. ' +
        'A missing context would produce a synthetic, RBAC-bypassed call — denied.',
      );
    }
    const fanoutCtx: CallContext = { ...ctx, internalResolverFanout: true };

    // §1.4 latency SLO: bound the fan-out so a single black-holed
    // adapter (which handleCall only abandons at its 30s transport dispatch
    // ceiling) cannot dominate resolve()'s wall-clock. Each probe races against
    // min(perProbe, remaining-until-deadline); a breach is a fail-closed miss.
    const probeBudgetMs = opts.probeTimeoutMs ?? PROBE_BUDGET_MS;
    if (!(probeBudgetMs > 0)) {
      throw new RangeError(
        `EntityResolver.resolve: probeTimeoutMs must be > 0, got ${String(opts.probeTimeoutMs)}.`,
      );
    }
    const fanoutBudgetMs = opts.fanoutTimeoutMs ?? FANOUT_BUDGET_MS;
    if (!(fanoutBudgetMs > 0)) {
      throw new RangeError(
        `EntityResolver.resolve: fanoutTimeoutMs must be > 0, got ${String(opts.fanoutTimeoutMs)}.`,
      );
    }
    const fanoutDeadline = Date.now() + fanoutBudgetMs;

    let probedAdapters = 0;
    // Slot-indexed by position in `targets` so evidence/attribute aggregation
    // order is the deterministic target order — NEVER async completion order,
    // which made last-writer-wins attributes (and thus displayName /
    // similarityScore / resolvedAsSame) flap across runs for identical inputs.
    const evidenceSlots: (EntityEvidence | undefined)[] = new Array<EntityEvidence | undefined>(targets.length);
    const attrObjectSlots: (Record<string, unknown> | null | undefined)[] = new Array<Record<string, unknown> | null | undefined>(targets.length);
    const missSlots: (string | undefined)[] = new Array<string | undefined>(targets.length);
    await mapWithConcurrency(targets, PROBE_CONCURRENCY, async ({ id, adapter }, index) => {
      // Build candidate tools from names + (when published) per-tool
      // descriptions so selection is semantic, not first-verb-prefix.
      const candidateTools = buildToolCandidates(adapter);
      const tool = selectEntityTool(candidateTools, queryTokens);
      if (!tool) {
        // No usable read/lookup tool (or mutation-only) → a miss, not a forced
        // probe of an unsafe tool.
        missSlots[index] = id;
        return;
      }
      probedAdapters++;
      // never wait past the fan-out deadline, and cap any single probe
      // at the per-probe budget. Once the deadline has passed this probe is a
      // miss without dispatching at all — resolve() returns promptly with the
      // sources that responded in time instead of blocking on a hung adapter.
      const remainingMs = fanoutDeadline - Date.now();
      if (remainingMs <= 0) {
        missSlots[index] = id;
        return;
      }
      const budgetMs = Math.min(probeBudgetMs, remainingMs);
      try {
        // Dispatch via handleCall to reuse the full guard stack (rate limit,
        // depth guard, RBAC, DLP, injection scanner) under the CALLER's
        // context — RBAC and tenant accounting are enforced here. The dispatch
        // is raced against the probe budget; a breach is a fail-closed miss
        // (the background dispatch reaps its own transport at the 30s ceiling).
        const raced = await withProbeBudget(
          handleCall(
            { adapter: id, tool, args: { query: entityQuery, q: entityQuery, search: entityQuery } },
            this.state,
            fanoutCtx,
          ),
          budgetMs,
        );
        if (raced === PROBE_TIMED_OUT) {
          log.debug('entity_resolve_probe_budget_exceeded', { adapterId: id, tool, budgetMs });
          missSlots[index] = id;
          return;
        }
        const result = raced;
        // CH-39: a probe that errored is a miss — summarised, not re-emitted
        // as evidence "error noise". An empty-hit success (e.g.
        // '{"results":[],"total":0}' for a ghost entity) is ALSO a miss:
        // transport success is not evidence, only actual hit content is —
        // otherwise a nonexistent entity presents as 'resolved' and two
        // ghosts' identical empty scaffolding compares at similarity 1.0.
        if (result.isError || !hasEntityHits(result.content)) {
          missSlots[index] = id;
          return;
        }
        // Attribute extraction runs on the FULL payload before any
        // truncation, so the aggregated attribute bag never degrades.
        attrObjectSlots[index] = normaliseContent(result.content);
        // Per-evidence size budget: replace an oversized payload with an
        // EXPLICIT truncation marker (never a silent slice — the marker is
        // visible to the caller, and the adapter still counts as a source).
        let data: unknown = result.content;
        const serialized = typeof result.content === 'string' ? result.content : JSON.stringify(result.content);
        const bytes = Buffer.byteLength(serialized, 'utf8');
        if (bytes > EVIDENCE_MAX_BYTES) {
          data = {
            truncated: true,
            bytes,
            maxBytes: EVIDENCE_MAX_BYTES,
            adapterId: id,
            toolName: tool,
            note: 'Evidence payload exceeded the per-evidence budget and was withheld from the aggregate response. Call the adapter tool directly for the full payload.',
          };
        }
        // Emit identity by the AUTHORITATIVE lookup-key id; use the row name
        // only when it is coherent (it passed the guard above).
        evidenceSlots[index] = {
          adapterId: id,
          adapterName: typeof adapter.name === 'string' ? adapter.name : id,
          toolName: tool,
          data,
          isError: false,
        };
      } catch (err) {
        log.debug('entity_resolve_adapter_error', {
          adapterId: id,
          tool,
          error: err instanceof Error ? err.message : String(err),
        });
        missSlots[index] = id;
      }
    });

    const evidence = evidenceSlots.filter((e): e is EntityEvidence => e !== undefined);
    for (const m of missSlots) {
      if (m !== undefined) missedAdapters.push(m);
    }

    const attrs = buildAttributesFromObjects(attrObjectSlots);
    const sourceCount = evidence.length;
    const status: ResolvedEntity['status'] = sourceCount > 0 ? 'resolved' : 'no_source';
    const displayName = extractDisplayName(attrs) ?? (sourceCount > 0 ? entityQuery : null);
    const entityType = inferEntityType(attrs);

    return {
      status,
      canonicalId: entityQuery,
      displayName,
      entityType,
      sourceCount,
      evidence,
      attributes: attrs,
      probedAdapters,
      candidateCount,
      unprobedAdapters,
      missedAdapters,
      flaggedAdapters,
      unknownAdapterIds,
      resolvedAt,
    };
  }

  /**
   * Compare two entities by resolving each and diffing their aggregated
   * attribute bags. Returns a similarity score and a per-field diff list.
   */
  async compare(entityA: string, entityB: string, opts: EntityResolveOpts = {}, ctx?: CallContext): Promise<EntityComparison> {
    const resolvedAt = new Date().toISOString();

    const [resA, resB] = await Promise.all([
      this.resolve(entityA, opts, ctx),
      this.resolve(entityB, opts, ctx),
    ]);

    // CH-39: a similarity score is only meaningful when BOTH sides resolved to
    // at least one usable source. If either side has no source there is nothing
    // to compare — return a typed no_comparison with similarityScore:null,
    // NOT a vacuous 0 that reads as "compared, 0% similar".
    if (resA.sourceCount === 0 || resB.sourceCount === 0) {
      return {
        status: 'no_comparison',
        entityA,
        entityB,
        similarityScore: null,
        entityASourceCount: resA.sourceCount,
        entityBSourceCount: resB.sourceCount,
        diffs: [],
        resolvedAsSame: false,
        unknownAdapterIds: resA.unknownAdapterIds,
        resolvedAt,
      };
    }

    // Consume the resolver's aggregated attribute bags (built from the FULL
    // pre-truncation payloads, in deterministic target order) rather than
    // re-deriving from `evidence`, whose oversized entries carry markers.
    const attrsA = resA.attributes;
    const attrsB = resB.attributes;

    const diffs = diffObjects(
      Object.keys(attrsA).length > 0 ? attrsA : null,
      Object.keys(attrsB).length > 0 ? attrsB : null,
    );

    const allKeys = new Set([...Object.keys(attrsA), ...Object.keys(attrsB)]);
    const totalFields = allKeys.size;
    const matchedFields = totalFields - diffs.length;

    // CH-39 fail-closed guards, mirroring the sourceCount gate above:
    // (a) zero comparable structured fields (both sides prose/no JSON) must
    //     be a typed no_comparison — NOT the forbidden vacuous
    //     similarityScore:0 that reads as "compared, 0% similar";
    // (b) defense-in-depth: if either side's bag carries no entity-bearing
    //     field (only counters/pagination/empty scaffolding), identical
    //     bookkeeping from the same probed tools must never score — least of
    //     all as similarity 1.0 / resolvedAsSame:true.
    if (totalFields === 0
      || countEntityBearingFields(attrsA) === 0
      || countEntityBearingFields(attrsB) === 0) {
      return {
        status: 'no_comparison',
        entityA,
        entityB,
        similarityScore: null,
        entityASourceCount: resA.sourceCount,
        entityBSourceCount: resB.sourceCount,
        diffs: [],
        resolvedAsSame: false,
        unknownAdapterIds: resA.unknownAdapterIds,
        resolvedAt,
      };
    }

    const similarityScore = Number((matchedFields / totalFields).toFixed(3));

    // Attribute-overlap heuristic: "resolved as same" when score is ≥0.9.
    // This is NOT an adapter-asserted identity match (see the type doc).
    const resolvedAsSame = similarityScore >= 0.9;

    return {
      status: 'compared',
      entityA,
      entityB,
      similarityScore,
      entityASourceCount: resA.sourceCount,
      entityBSourceCount: resB.sourceCount,
      diffs,
      resolvedAsSame,
      unknownAdapterIds: resA.unknownAdapterIds,
      resolvedAt,
    };
  }

  /**
   * Build a structured profile for an entity by resolving it across the
   * catalog and aggregating all returned data into a flat attribute bag.
   */
  async profile(entityId: string, opts: EntityResolveOpts = {}, ctx?: CallContext): Promise<EntityProfile> {
    const profiledAt = new Date().toISOString();

    const resolved = await this.resolve(entityId, opts, ctx);

    // resolve() already filters error/empty probes out of `evidence`, so every
    // entry here is a usable source. Oversized payloads appear as explicit
    // truncation markers (per-evidence budget in resolve()).
    const adapterData: Record<string, unknown> = {};
    for (const ev of resolved.evidence) {
      adapterData[ev.adapterId] = ev.data;
    }

    // Full-payload attribute bag computed by resolve() in deterministic order.
    const attrs = resolved.attributes;

    return {
      // CH-39: typed no_source (→ isError:true in the handler) instead of an
      // undifferentiated empty shell when nothing resolved.
      status: resolved.sourceCount > 0 ? 'profiled' : 'no_source',
      entityId: resolved.canonicalId,
      displayName: resolved.displayName,
      entityType: resolved.entityType,
      knownAdapters: resolved.evidence.map((e) => e.adapterId),
      adapterData,
      attributes: attrs,
      flaggedAdapters: resolved.flaggedAdapters,
      unknownAdapterIds: resolved.unknownAdapterIds,
      profiledAt,
    };
  }
}
