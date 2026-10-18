/**
 * @epicai/chariot — Composite (sealed + per-tenant overlay) EdgeShard query fusion
 *
 * CHARIOT-SPEC.md:767 (§8.6a), verbatim: "Query-time `HybridRetriever` fuses
 * catalog-shard + overlay-shard results under RRF; the overlay contributes to
 * the `overlayStateHash` that scopes §8.6 determinism." BIEN::§9::14
 * (constraint): overlay vectors "SHALL be retrievable within the same vector
 * space as the sealed catalog (queryable together without a separate index
 * or re-embedding step)."
 *
 * ── Tenant isolation (gate-round-2 finding D1, 2026-09-05) ──
 * §8.6a's overlay is PER-TENANT customer data. The first version of this
 * class took a STATIC array of overlay shards resolved once, which had two
 * defects: (1) `loadRetrieval.ts`'s `wireHybridRetrieval` runs ONCE at
 * process startup, before any `requiresCustomerAuth` adapter has ever
 * connected — overlay shards open LAZILY on first embed, so the static list
 * was always empty and the composite was never actually installed; (2) even
 * if populated, a static array holds EVERY tenant's overlay shard
 * indiscriminately, so a query issued on behalf of tenant B would also
 * search (and could return) tenant A's customer-verified tools — a
 * cross-tenant exposure of exactly the private, on-device customer data
 * §8.6a exists to keep host-local ("The customer credential, tools, and
 * vectors NEVER leave the host").
 *
 * The fix: `query()` takes the REQUESTING tenant's id as an explicit
 * argument (never inferred, never defaulted to "all tenants") and resolves
 * ONLY that tenant's overlay shard, PER QUERY, via an injected provider
 * function `(tenantId: string) => NativeEdgeShard | null`
 * (`OverlayEmbedder.ts::NativeOverlayEmbedder.getOverlayShard`, which opens
 * the tenant's persisted shard from disk on first use if it is not already
 * resident in this process — so a query-only process, or one restarted
 * after the tenant's last embed, still finds it). No tenantId → no overlay
 * lookup at all, sealed-only (the pre-§8.6a behavior, byte-identical).
 *
 * `HybridRetriever.search()` (HybridRetriever.ts, `queryDense`/`querySparse`)
 * issues exactly ONE `this.deps.shard.query(...)` call per vector leg (dense,
 * then sparse) and feeds the returned points into ONE
 * `RankFusion.rrf(legs, this.rrfK)` call alongside the caller-supplied BM25
 * leg — "one RRF" per the build brief. This class satisfies that contract
 * WITHOUT touching `RankFusion.ts`: it implements the `NativeEdgeShard`
 * surface `HybridRetriever` already depends on, EXTENDED with an optional
 * second `tenantId` parameter on `query()` (the "native contract untouched"
 * choice explicitly preferred over smuggling `tenantId` into the
 * `NativeQueryRequest` object): the REAL native `EdgeShardHandle.query`
 * (`native/src/edge_shard.rs`) is a compiled N-API function of declared
 * arity 1 — napi-rs's generated binding reads only the JS arguments it
 * declares, so an extra trailing JS call argument is simply never inspected
 * by the real binding (verified against every other native call site in
 * this codebase: none takes a variable argument count, and N-API/V8 do not
 * error on an over-supplied argument list to a function that does not use
 * `arguments.length`). This means `CompositeEdgeShard` can pass `tenantId`
 * as a second argument to `.query()` with ZERO change to
 * `native/src/edge_shard.rs`'s struct or function signature, and the raw
 * sealed `EdgeShardHandle` (used directly, without a composite, when no
 * overlay capability is wired) is completely unaffected either way.
 *
 * ── Why the merge key is `payload.toolId`, not the raw Qdrant point id ──
 * `HybridRetriever.ts`'s private `pointToToolId`/`pointsToLeg` (read in
 * full) extract the FUSION identity from `payload.toolId` (freeze-stamped
 * `"server:name"`), never the raw point id, and `RankFusion.rrf` sums an
 * RRF contribution PER ENTRY in a leg's `results` array keyed by that same
 * `id`, with no de-duplication of its own (it iterates `results` positionally
 * and simply accumulates into a `Map` — two raw points that both decode to
 * the same `toolId` inside ONE leg's results would each add an RRF term,
 * double-counting that tool). Merging the two shards' raw NativeScoredPoint
 * arrays by raw point id would NOT catch that: `nativeEdge.ts`'s point id is
 * a stringified qdrant `ExtendedPointId` (`NumId(u64)` or `Uuid`, per the
 * vendored `qdrant-edge-0.7.2` crate `segment/types.rs:169` — arbitrary
 * strings are not a valid point id), so a sealed point and an overlay point
 * legitimately have DIFFERENT raw ids even when they represent the identical
 * logical tool. This class therefore extracts and dedupes on `payload.toolId`
 * — mirroring `pointToToolId` exactly — BEFORE the merged list ever reaches
 * `HybridRetriever`, so `RankFusion` never sees two rows for one id within a
 * leg. `OverlayEmbedder.ts` reserves the `overlay:<tenantId>:<adapterId>:`
 * `toolId` prefix for every overlay-embedded point specifically so this
 * dedup path is a defense-in-depth backstop, not the primary safety
 * property: a sealed catalog `toolId` is always `server:name` and can never
 * start with `overlay:`, so an accidental collision with a sealed tool's
 * identity is impossible by construction; dedup only ever fires as a
 * safety net, never expected in practice.
 *
 * A point whose payload carries no usable `toolId` is left exactly as
 * returned (never dropped or merged away here) — `HybridRetriever`'s own
 * `pointsToLeg` already treats that as a per-leg integrity event
 * (`legFailures`, `degraded: true`); this class must not mask or duplicate
 * that accounting by discarding or coalescing malformed points itself.
 *
 * Each underlying `query()` call already runs the deterministic exact
 * (brute-force) path the caller requested (`exact: true`, §8.6/CH-23); this
 * class does not alter that per-shard determinism. On top of it, the merge
 * itself is deterministic and independent of which shard answered first:
 * sort by score descending with a lexicographic id tie-break (mirrors
 * `RankFusion`'s own `a.toolId.localeCompare(b.toolId)` / HybridRetriever's
 * fused-map pattern), then truncate to the caller's requested `limit`.
 *
 * Write operations (`upsert`, `flush`) are refused outright (fail-closed
 * `Error`, never a silent no-op): this class exists ONLY as the read-side
 * fan-out `HybridRetriever` queries. Writing overlay vectors is
 * `OverlayEmbedder`'s job, against the specific tenant's overlay shard
 * directly, never through this composite.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { NativeEdgeShard, NativeQueryRequest, NativeScoredPoint } from '../nativeEdge.js';

/**
 * Extract the fusion identity from a point's payload, exactly mirroring
 * `HybridRetriever.ts`'s private `pointToToolId` (duplicated here rather than
 * imported because that function is module-private by design — see its own
 * doc comment — and this class must not widen its visibility just to reuse
 * three lines; any drift between the two is caught by
 * `CompositeEdgeShard.dedup-matches-pointsToLeg.test.ts`, which asserts both
 * extract the identical id for the same fixture points).
 */
function payloadToolId(p: NativeScoredPoint): string | null {
  if (p.payloadJson) {
    try {
      const payload = JSON.parse(p.payloadJson) as { toolId?: unknown };
      if (typeof payload.toolId === 'string' && payload.toolId.length > 0) {
        return payload.toolId;
      }
    } catch {
      /* malformed payload — left as-is, HybridRetriever's own pointsToLeg accounts for it */
    }
  }
  return null;
}

/** Resolves the SPECIFIC requesting tenant's overlay shard, or `null` when
 * that tenant has no overlay (never created on a query — see
 * `OverlayEmbedder.ts::getOverlayShard`'s own doc comment). MUST NOT return
 * a shard belonging to any tenant other than the one passed in. */
export type OverlayShardProvider = (tenantId: string) => NativeEdgeShard | null;

/**
 * Gate-round-3 finding E1(b) — resolves the SPECIFIC requesting tenant's
 * currently-live overlay toolIds (`OverlayEmbedder.ts::
 * NativeOverlayEmbedder.liveOverlayToolIds`, manifest-derived — the same
 * source `listTools`/`overlayStateHash` read, so this can never disagree
 * with either). `null` means "no liveness answer for this tenant at all"
 * (never returned for a tenant with zero CURRENTLY live tools — that is a
 * valid state with an EMPTY, non-null `Set`).
 */
export type OverlayLiveToolIdsProvider = (tenantId: string) => ReadonlySet<string> | null;

/**
 * Read-only fan-out over the sealed catalog shard and (per query, per
 * requesting tenant) at most one overlay shard. Implements `NativeEdgeShard`
 * so it is a drop-in `HybridRetrieverDeps.shard` — `HybridRetriever.ts`
 * needs no change beyond threading `tenantId` through to `query()`.
 */
export class CompositeEdgeShard implements NativeEdgeShard {
  constructor(
    private readonly sealed: NativeEdgeShard,
    private readonly overlayFor: OverlayShardProvider,
    /**
     * Gate-round-3 finding E1(b) — "the overlay is never CORRECTED, only
     * grown": the native shard has no delete, so a tool a re-embed drops
     * stays physically retrievable from the overlay shard's OWN `query()`
     * call. This provider is consulted for every overlay point BEFORE the
     * merge/sort/slice below, so a stale point can never displace a live
     * result from the top-k merely by scoring high in the shard's own
     * ranking — it is removed before ranking against the merged set even
     * happens. A point with NO usable `toolId` (malformed payload) is NOT
     * staleness-checked here — that is `HybridRetriever`'s own
     * leg-integrity accounting, unrelated to freshness, and untouched.
     */
    private readonly liveToolIdsFor: OverlayLiveToolIdsProvider,
  ) {}

  /**
   * `tenantId` is OPTIONAL and, when absent, this is an exact pass-through
   * to the sealed shard — no overlay lookup is even attempted. This is the
   * "no tenantId → sealed results only" contract: an anonymous/unscoped
   * query (e.g. a health probe, or a caller that genuinely has no tenant
   * context) must never accidentally see ANY tenant's private overlay data.
   */
  query(request: NativeQueryRequest, tenantId?: string): NativeScoredPoint[] {
    if (!tenantId) {
      return this.sealed.query(request);
    }
    const overlay = this.overlayFor(tenantId);
    if (!overlay) {
      // This tenant has no overlay (yet, or ever) — sealed-only, byte-
      // identical to the no-overlay-wired path.
      return this.sealed.query(request);
    }
    // E1(b): drop every overlay point whose toolId is not currently live,
    // BEFORE it ever reaches the merge. `liveIds === null` means no
    // liveness answer could be obtained at all (should not happen for a
    // tenant `overlayFor` just proved has a shard, but if it does, fail
    // CLOSED — drop every checkable overlay point rather than trust
    // unverified freshness) — a point with no toolId at all is left for
    // HybridRetriever's own malformed-payload accounting, untouched here.
    const liveIds = this.liveToolIdsFor(tenantId);
    const freshOverlayPoints = overlay.query(request).filter((point) => {
      const toolId = payloadToolId(point);
      if (toolId === null) return true;
      return liveIds !== null && liveIds.has(toolId);
    });

    const byIdentity = new Map<string, NativeScoredPoint>();
    const admit = (points: NativeScoredPoint[]) => {
      for (const point of points) {
        const key = payloadToolId(point) ?? `__malformed__:${point.id}`;
        // First writer wins: sealed is always admitted before the overlay,
        // so an (unexpected) toolId collision resolves in the sealed
        // catalog's favor — never silently overwritten by a lower-authority
        // overlay row.
        if (!byIdentity.has(key)) byIdentity.set(key, point);
      }
    };
    admit(this.sealed.query(request));
    admit(freshOverlayPoints);
    return [...byIdentity.values()]
      .sort((a, b) => b.score - a.score || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .slice(0, request.limit);
  }

  upsert(_pointsJson: string): void {
    throw new Error(
      'CompositeEdgeShard is read-only fan-out for HybridRetriever queries; ' +
      'write overlay vectors via OverlayEmbedder against the specific tenant\'s overlay shard, never through the composite.',
    );
  }

  flush(): void {
    throw new Error('CompositeEdgeShard is read-only; flush the specific underlying shard instead.');
  }

  /** Sealed shard's own count only — this class has no fixed set of overlay
   * shards to sum (they are resolved per-tenant, per-query, on demand), so a
   * tenant-less "total points" figure would be meaningless (whose tenant's
   * overlay would it include?). Callers that need an overlay's count should
   * ask `OverlayEmbedder`/the specific `NativeEdgeShard` directly. */
  pointsCount(): number {
    return this.sealed.pointsCount();
  }

  snapshotManifestJson(): string {
    return this.sealed.snapshotManifestJson();
  }
}
