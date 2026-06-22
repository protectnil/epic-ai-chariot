/**
 * @epicai/chariot — Entity Resolver
 * Engine-level entity intelligence service: resolve, compare, and profile
 * entities across the full adapter catalog via a unified, gateway-independent
 * resolver.
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
 * Run `fn` over `items` with at most `limit` invocations in flight at a time.
 * Resolves once every item has been processed; individual rejections are the
 * callback's responsibility (callers below catch per-probe).
 */
async function mapWithConcurrency<T>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let idx = 0;
  const workerCount = Math.max(1, Math.min(limit, items.length));
  const workers = Array.from({ length: workerCount }, async () => {
    while (idx < items.length) {
      const current = items[idx++];
      await fn(current);
    }
  });
  await Promise.all(workers);
}

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
  /** Canonical entity identifier (normalised from the input query). */
  canonicalId: string;
  /** Display name if resolvable; null when no adapter recognised the entity. */
  displayName: string | null;
  /** Category/type inferred from adapter responses (e.g. "user", "host", "package"). */
  entityType: string | null;
  /** Number of adapters that returned non-error evidence. */
  sourceCount: number;
  /** All adapter-level evidence collected. */
  evidence: EntityEvidence[];
  /** Adapters that were queried but returned no relevant data. */
  missedAdapters: string[];
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
  entityA: string;
  entityB: string;
  /** 0.0–1.0 — fraction of comparable fields that matched. */
  similarityScore: number;
  /** Fields where the two entities differ. */
  diffs: EntityDiff[];
  /** Whether any adapter treated the two as the same canonical record. */
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
  entityId: string;
  displayName: string | null;
  entityType: string | null;
  /** Adapters that have data about this entity. */
  knownAdapters: string[];
  /** Raw evidence from each adapter, keyed by adapter id. */
  adapterData: Record<string, unknown>;
  /** Structured attribute bag (flattened from adapter responses). */
  attributes: Record<string, unknown>;
  /** Caller-supplied adapterIds that matched no adapter. */
  unknownAdapterIds: string[];
  profiledAt: string;
}

/** Options shared by resolve/compare/profile. */
export interface EntityResolveOpts {
  adapterIds?: string[];
  maxAdapters?: number;
}

// =============================================================================
// Internal helpers
// =============================================================================

/**
 * Find the best "search" or "lookup" tool on an adapter by scanning its
 * declared tool name list for common entity-search verb prefixes.
 * Returns null when no plausible tool exists.
 */
function pickEntityTool(toolNames: readonly string[]): string | null {
  const ENTITY_VERBS = [
    'search', 'lookup', 'resolve', 'find', 'get', 'query', 'fetch', 'describe',
  ];
  for (const verb of ENTITY_VERBS) {
    const match = toolNames.find((t) => t.toLowerCase().startsWith(verb));
    if (match) return match;
  }
  return null;
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
 * Build a flat attribute bag from an array of evidence objects.
 * Later evidence for the same key wins (last-writer-wins across adapters).
 */
function buildAttributes(evidence: EntityEvidence[]): Record<string, unknown> {
  const attrs: Record<string, unknown> = {};
  for (const ev of evidence) {
    if (ev.isError) continue;
    const obj = normaliseContent(ev.data);
    if (!obj) continue;
    for (const [k, v] of Object.entries(obj)) {
      attrs[k] = v;
    }
  }
  return attrs;
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
   * Resolve an entity by querying every adapter in the catalog that
   * declares a plausible search/lookup tool. Fans out (bounded concurrency)
   * and aggregates evidence from all responding adapters.
   *
   * SECURITY: `ctx` carries the caller's tenantId/auth/localMode and is passed
   * verbatim to handleCall so the per-operation RBAC and per-tenant rate-limit
   * apply to every fan-out call. It MUST be the caller's real context — never a
   * synthetic `{ localMode: true }`, which would bypass RBAC (deny-by-default).
   */
  async resolve(entityQuery: string, opts: EntityResolveOpts = {}, ctx?: CallContext): Promise<ResolvedEntity> {
    const resolvedAt = new Date().toISOString();
    const evidence: EntityEvidence[] = [];
    const missedAdapters: string[] = [];
    const unknownAdapterIds: string[] = [];

    // Scope to the caller-supplied adapter list or the full catalog. Unknown
    // ids are surfaced (not silently dropped) so a typo is distinguishable
    // from a genuine no-evidence result.
    let candidates;
    if (opts.adapterIds) {
      candidates = [];
      for (const id of opts.adapterIds) {
        const a = this.state.adapterById.get(id);
        if (a) candidates.push(a);
        else unknownAdapterIds.push(id);
      }
    } else {
      candidates = this.state.allAdapters;
    }

    const cap = Math.min(opts.maxAdapters ?? 12, candidates.length);
    const targets = candidates.slice(0, cap);

    // Import lazily to avoid a circular module dependency — EntityResolver
    // lives under src/engine/entity/ and toolHandlers under src/engine/server/;
    // a top-level import would create a cycle. Resolved once per call (the
    // loader caches it) rather than once per probe.
    const { handleCall } = await import('../server/toolHandlers.js');

    await mapWithConcurrency(targets, PROBE_CONCURRENCY, async (adapter) => {
      const toolNames = adapter.rest?.toolNames ?? adapter.mcp?.toolNames ?? [];
      const tool = pickEntityTool(toolNames);
      if (!tool) {
        // No suitable search/lookup tool → counts as a miss.
        missedAdapters.push(adapter.id);
        return;
      }
      try {
        // Dispatch via handleCall to reuse the full guard stack (rate limit,
        // depth guard, RBAC, session surface, DLP, injection scanner) under the
        // CALLER's context — RBAC and tenant accounting are enforced here.
        const result = await handleCall(
          { adapter: adapter.id, tool, args: { query: entityQuery, q: entityQuery, search: entityQuery } },
          this.state,
          ctx,
        );
        evidence.push({
          adapterId: adapter.id,
          adapterName: adapter.name,
          toolName: tool,
          data: result.content,
          isError: result.isError,
        });
      } catch (err) {
        log.debug('entity_resolve_adapter_error', {
          adapterId: adapter.id,
          tool,
          error: err instanceof Error ? err.message : String(err),
        });
        missedAdapters.push(adapter.id);
      }
    });

    const successful = evidence.filter((e) => !e.isError);
    const attrs = buildAttributes(successful);
    const displayName = extractDisplayName(attrs) ?? (successful.length > 0 ? entityQuery : null);
    const entityType = inferEntityType(attrs);

    return {
      canonicalId: entityQuery,
      displayName,
      entityType,
      sourceCount: successful.length,
      evidence,
      missedAdapters,
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

    const attrsA = buildAttributes(resA.evidence.filter((e) => !e.isError));
    const attrsB = buildAttributes(resB.evidence.filter((e) => !e.isError));

    const diffs = diffObjects(
      Object.keys(attrsA).length > 0 ? attrsA : null,
      Object.keys(attrsB).length > 0 ? attrsB : null,
    );

    const allKeys = new Set([...Object.keys(attrsA), ...Object.keys(attrsB)]);
    const totalFields = allKeys.size;
    const matchedFields = totalFields - diffs.length;
    const similarityScore = totalFields > 0
      ? Number((matchedFields / totalFields).toFixed(3))
      : 0;

    // Treat as "resolved as same" when score is ≥0.9.
    const resolvedAsSame = similarityScore >= 0.9;

    return {
      entityA,
      entityB,
      similarityScore,
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

    const adapterData: Record<string, unknown> = {};
    for (const ev of resolved.evidence) {
      if (!ev.isError) {
        adapterData[ev.adapterId] = ev.data;
      }
    }

    const attrs = buildAttributes(resolved.evidence.filter((e) => !e.isError));

    return {
      entityId: resolved.canonicalId,
      displayName: resolved.displayName,
      entityType: resolved.entityType,
      knownAdapters: resolved.evidence.filter((e) => !e.isError).map((e) => e.adapterId),
      adapterData,
      attributes: attrs,
      unknownAdapterIds: resolved.unknownAdapterIds,
      profiledAt,
    };
  }
}
