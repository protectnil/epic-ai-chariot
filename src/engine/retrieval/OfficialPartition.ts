/**
 * @epicai/chariot — BIEN §7a official/non-official hard partition (`G-D`).
 *
 * BIEN::§7a::1 (requirement): "THE SYSTEM SHALL rank every official record
 * strictly above every non-official record in each query result set."
 *
 * BIEN::§7a::2 (requirement): "THE SYSTEM SHALL derive the partition key
 * from the catalog record's tier field, classifying a record official iff tier is
 * tier-0-protectnil or tier-1-provenance-verified per FPS §15.1's 'may
 * present as official/first-party' column."
 *
 * BIEN::§7a::3 (constraint): "THE SYSTEM SHALL treat the official/
 * non-official derivation as owned exclusively by AS §3.5 G17-03/G17-04
 * and SHALL NOT re-compute it within this clause's partition mechanism."
 * — this module never derives `tier`; it only reads the value already
 * stamped on catalog metadata (`AdapterEntry.tier`, `ChariotState.ts`)
 * by the catalog publisher's G17-03/G17-04 pipeline.
 *
 * BIEN::§7a::4 (constraint): "THE SYSTEM SHALL NOT introduce a cross-query
 * capability-clustering primitive; 'same capability' for this clause's
 * partition means co-presence in the same query's post-candidate-selection
 * list at BIEN retrieval-record granularity only." — `stablePartitionOfficial`
 * takes exactly one query's candidate list and returns it re-ordered; it
 * carries no state across calls and clusters nothing across queries.
 *
 * BIEN::§7a::5 (requirement): "THE SYSTEM SHALL apply the official/
 * non-official partition to the complete post-rerank candidate list BEFORE
 * final top-K truncation."
 *
 * BIEN::§7a::6 (requirement): "THE SYSTEM SHALL stable-partition the
 * complete post-rerank candidate list by officialPartition DESC as the
 * first step of the re-sort."
 *
 * BIEN::§7a::7 (requirement): "WITHIN each partition, THE SYSTEM SHALL
 * preserve the existing rerank ordering using the tiebreak (rerankScore
 * DESC, id ASC)."
 *
 * BIEN::§7a::8 (requirement): "THE SYSTEM SHALL truncate to top-K ONLY
 * AFTER the partition and within-partition ordering steps are complete."
 * — nodes 5/8 are satisfied by the CALLERS (`HybridRetriever.ts`), which
 * MUST invoke `stablePartitionOfficial` between the rerank stage and any
 * `.slice(0, topK)`/`.slice(0, maxTools)` truncation; this module supplies
 * only the pure partition/assert primitives, not the call-site ordering.
 *
 * BIEN::§7a::9 (constraint): "THE SYSTEM SHALL implement the partition as
 * a deterministic stable re-sort, not a ranker: it SHALL NOT invoke a
 * model, alter rerankScore, generate a replacement score, perform semantic
 * similarity, or create an alternative routing path." — `stablePartitionOfficial`
 * is a pure, synchronous `Array.prototype.sort` over a boolean partition key
 * plus the existing `(rerankScore DESC, id ASC)` tiebreak; it reads
 * `rerankScore`, never writes it, and calls no model/scorer.
 *
 * BIEN::§7a::10 (constraint): "THE SYSTEM SHALL keep tier excluded from
 * the serializer/ToolRecord contract per §17.3/§16.5, consuming it only as
 * catalog metadata at re-sort time, never as an embedded or training
 * feature." — this module's functions take a `tierByAdapterId` LOOKUP MAP
 * built by the caller from catalog metadata; `tier` is never read off a
 * `RetrievalResult`/`ToolRecord` value itself (neither carries a `tier`
 * field — see `src/engine/retrieval/types.ts`), so there is no path by
 * which `tier` could leak into the embedding/serializer surface through
 * this module.
 *
 * BIEN::§7a::14 (requirement): "THE SYSTEM'S production re-sort SHALL
 * assert the official-before-non-official invariant after partitioning at
 * runtime, and SHALL fail closed -- SHALL NOT return the reordered result
 * -- on an invariant failure." — `assertOfficialPartitionInvariant` throws
 * `OfficialPartitionInvariantError` (code `retrieval_partition_invariant_failed`)
 * on any violation; per MASTER ruling (rulings item 90), the caller MUST
 * let this propagate as a typed query failure — never substitute the
 * un-partitioned order, and never degrade to the BM25-only fallback
 * `HybridRetriever.ts` uses for a reranker failure (that degradation is a
 * DIFFERENT failure class — a reranker exception — not a partition
 * invariant violation, and reusing it here would silently serve results
 * the invariant assertion has already proven wrong).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/**
 * BIEN::§7a::2 — the closed membership test: a tier is official iff it is
 * EXACTLY one of these two values. Any other value (including every other
 * currently-defined tier — `tier-2-behaviorally-proven`, `tier-3-rejected`,
 * `registry-only-legacy`, `unassigned`, the retired `tier-1-registry-verified`
 * alias — see `materializer/types.ts`'s tier doc comment, mirrored at
 * `AdapterEntry.tier`) and an ABSENT tier (a catalog entry the publisher
 * has not yet classified) are both non-official. This is a strict `iff`,
 * not a denylist: adding a new tier value elsewhere requires no change
 * here, because everything not on this list stays non-official by default
 * — the safe direction for a partition that exists to protect official
 * ranking, not to award it speculatively.
 */
const OFFICIAL_TIERS: ReadonlySet<string> = new Set([
  'tier-0-protectnil',
  'tier-1-provenance-verified',
]);

/**
 * BIEN::§7a::2 — true iff `tier` is one of the two official values.
 * `undefined` (absent tier) is non-official, per the closed membership
 * test above.
 */
export function isOfficialTier(tier: string | undefined): boolean {
  return tier !== undefined && OFFICIAL_TIERS.has(tier);
}

/**
 * Extract the owning adapter id from a retrieval-record id.
 *
 * Tool records carry `id = "server:name"` (§5.2/CH-22 tool-granular,
 * `src/engine/retrieval/types.ts:15`); the adapter id is everything before
 * the FIRST colon (matching the split convention already used at
 * `FederationManager.ts`/`setup.ts`/`TieredAutonomy.ts`:
 * `name.includes(':') ? name.split(':').slice(1).join(':') : name` takes
 * the tool name AFTER the first colon, so the adapter id is symmetrically
 * everything BEFORE it). A capability-residual record (CH-62, "keyed by
 * its server / adapter id") carries no colon at all — its id IS the
 * adapter id, so the no-colon branch returns it unchanged.
 */
// FIX (2026-09-30, release-blocking): "everything before the FIRST colon"
// assumed the adapter id itself never contains a colon — true for every
// catalog adapter, false for a discovered adapter's `discovered:
// <serviceId>` operational-namespace prefix (src/engine/federation/
// configuredAdapterIds.ts). For "discovered:server-abc123:get_widgets"
// the naive `indexOf(':')` returned "discovered" as the "adapter id"
// instead of "discovered:server-abc123" — silently misattributing every
// discovered adapter's tool records to a nonexistent "discovered" adapter
// during BIEN §7a partitioning. Mirrors the same colon-aware fix applied
// at FederationManager.ts's 4 sibling call sites (toolNameFromCombinedName).
const DISCOVERED_ADAPTER_ID_PREFIX = 'discovered:';
export function adapterIdFromRetrievalId(id: string): string {
  if (id.startsWith(DISCOVERED_ADAPTER_ID_PREFIX)) {
    const rest = id.slice(DISCOVERED_ADAPTER_ID_PREFIX.length);
    const idx = rest.indexOf(':');
    return idx === -1 ? id : DISCOVERED_ADAPTER_ID_PREFIX + rest.slice(0, idx);
  }
  const idx = id.indexOf(':');
  return idx === -1 ? id : id.slice(0, idx);
}

/**
 * BIEN::§7a::6/7/9 — stable-partition `candidates` by `officialPartition
 * DESC` (official first), preserving `(rerankScore DESC, id ASC)` as the
 * within-partition tiebreak. Pure: no model invocation, no `rerankScore`
 * mutation (the comparator only READS it), no alternative routing path.
 *
 * `tierByAdapterId` is the caller-supplied catalog-metadata lookup
 * (BIEN::§7a::10 — never read off `candidates` themselves).
 */
export function stablePartitionOfficial<T extends { id: string; rerankScore?: number }>(
  candidates: readonly T[],
  tierByAdapterId: ReadonlyMap<string, string | undefined>,
): T[] {
  const officialOf = (item: T): boolean =>
    isOfficialTier(tierByAdapterId.get(adapterIdFromRetrievalId(item.id)));

  return [...candidates].sort((a, b) => {
    const aOfficial = officialOf(a);
    const bOfficial = officialOf(b);
    if (aOfficial !== bOfficial) return aOfficial ? -1 : 1;

    // BIEN::§7a::7 tiebreak: (rerankScore DESC, id ASC). Explicit
    // comparisons (not subtraction) so a NaN/±Infinity rerankScore cannot
    // poison the comparator — same defensive pattern as
    // CrossEncoderReranker.ts's own (rerankScore DESC, id ASC) sort.
    const as = a.rerankScore ?? 0;
    const bs = b.rerankScore ?? 0;
    if (bs > as) return 1;
    if (bs < as) return -1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
}

/**
 * BIEN::§7a::1/5/6/7/9 — plain-id variant of `stablePartitionOfficial` for
 * callers whose "complete post-rerank candidate list" is already reduced
 * to an ordered array of tool ids (e.g. `ToolPreFilter.selectInternal`'s
 * `rankedIds`, after RRF fusion + rerank + server-group-and-hoist +
 * exact-name pinning have already run) rather than `RetrievalResult`
 * objects carrying `rerankScore`. `tierOf` is the caller's own tier
 * resolver (BIEN::§7a::10 — reads catalog metadata, e.g. a
 * `toolIdMap`-backed lookup, never a field on the id/record itself).
 *
 * Because a plain id array carries no `rerankScore` to re-derive a
 * tiebreak from, this is a STABLE partition ONLY: ties (both official or
 * both non-official) keep their existing relative order exactly as
 * `Array.prototype.sort`'s ES2019+ stability guarantees — which already
 * IS the accumulated post-rerank/hoist/pin ordering BIEN::§7a::7 says to
 * preserve, since nothing upstream of this call has changed that order.
 */
export function stablePartitionOfficialIds(
  ids: readonly string[],
  tierOf: (id: string) => string | undefined,
): string[] {
  return [...ids].sort((a, b) => {
    const aOfficial = isOfficialTier(tierOf(a));
    const bOfficial = isOfficialTier(tierOf(b));
    if (aOfficial === bOfficial) return 0;
    return aOfficial ? -1 : 1;
  });
}

/**
 * BIEN::§7a::14 — thrown by `assertOfficialPartitionInvariant` on any
 * official-after-non-official ordering found in an already-partitioned
 * list. `code` is the typed failure MASTER ruling item 90 names:
 * `retrieval_partition_invariant_failed`. The caller MUST propagate this
 * (fail the query) rather than substitute any other result.
 */
export class OfficialPartitionInvariantError extends Error {
  readonly code = 'retrieval_partition_invariant_failed' as const;
  constructor(message: string) {
    super(message);
    this.name = 'OfficialPartitionInvariantError';
  }
}

/**
 * BIEN::§7a::14 — verify `partitioned` (the output of
 * `stablePartitionOfficial`, or any list a caller claims is already
 * partitioned) genuinely has every official record before every
 * non-official record. Throws `OfficialPartitionInvariantError` at the
 * FIRST official record found after a non-official one — "an invariant
 * failure SHALL fail closed and SHALL NOT return the reordered result",
 * so this function is a pure guard: it returns nothing on success and
 * throws on the first violation, giving the caller no reordered list to
 * accidentally return.
 */
export function assertOfficialPartitionInvariant<T extends { id: string }>(
  partitioned: readonly T[],
  tierByAdapterId: ReadonlyMap<string, string | undefined>,
): void {
  assertOfficialPartitionInvariantIds(
    partitioned.map((item) => item.id),
    (id) => tierByAdapterId.get(adapterIdFromRetrievalId(id)),
  );
}

/**
 * BIEN::§7a::14 — plain-id variant of `assertOfficialPartitionInvariant`,
 * paired with `stablePartitionOfficialIds` for callers operating on a
 * plain `string[]` of ids (see that function's docstring for why).
 */
export function assertOfficialPartitionInvariantIds(
  partitioned: readonly string[],
  tierOf: (id: string) => string | undefined,
): void {
  let sawNonOfficial = false;
  for (const id of partitioned) {
    const official = isOfficialTier(tierOf(id));
    if (!official) {
      sawNonOfficial = true;
      continue;
    }
    if (sawNonOfficial) {
      throw new OfficialPartitionInvariantError(
        `BIEN::§7a::14 invariant violated: official record "${id}" ranked after a non-official record`,
      );
    }
  }
}
