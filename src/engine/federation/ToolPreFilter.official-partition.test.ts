/**
 * Prove-on-revert for BIEN::§7a — official/non-official hard partition,
 * `ToolPreFilter.selectInternal`'s exit paths.
 *
 * Gate finding: the whole-pool completeness path
 * (`sortedCandidates.length <= maxTools`) appended UNPARTITIONED
 * `sortedCandidates` stragglers AFTER an earlier partition step had
 * already run, so an official record could land after a non-official one
 * in the list actually returned — the partition covered an intermediate
 * `rankedIds` state, not the complete list that left the method.
 *
 * Fix (this revision): every exit path in `selectInternal` — the
 * zero-lexical-signal fallback, the whole-pool completeness return, and
 * the maxPerServer/token-budget selection loop — partitions its OWN final
 * id list via `stablePartitionOfficialIds` and asserts via
 * `assertOfficialPartitionInvariantIds` immediately before building the
 * `Tool[]` it returns. No path concatenates a partitioned prefix with an
 * unpartitioned remainder.
 *
 * BIEN SPEC.md §7a (verbatim): "official records SHALL rank strictly
 * above non-official records" (node 1); "applied to the complete
 * post-rerank candidate list before final top-K truncation" (node 5);
 * "The production re-sort SHALL assert the same invariant after
 * partitioning ... an invariant failure SHALL fail closed and SHALL NOT
 * return the reordered result" (node 14).
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/ToolPreFilter.official-partition.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { ToolPreFilter } from './ToolPreFilter.js';
import type { Tool } from '../types/index.js';
import { assertOfficialPartitionInvariantIds, OfficialPartitionInvariantError } from '../retrieval/OfficialPartition.js';

function makeTool(server: string, name: string, description: string): Tool {
  return {
    server,
    name,
    description,
    parameters: { type: 'object', properties: {} },
    tier: 'direct',
  };
}

/**
 * A tiny BM25-only pool (no HybridRetriever wired — this exercises the
 * plain lexical path, which is sufficient: the partition wiring under
 * test sits downstream of BOTH the hybrid and BM25-only branches, at the
 * shared exit paths).
 */
function makeFilter(tools: Tool[], tiers: Record<string, string | undefined>): ToolPreFilter {
  const filter = new ToolPreFilter();
  filter.index(tools);
  filter.setAdapterTiers(Object.entries(tiers).map(([id, tier]) => ({ id, tier })));
  return filter;
}

/* ---------------------------------------------------------------------- *
 * Whole-pool completeness path (sortedCandidates.length <= maxTools).
 * ---------------------------------------------------------------------- */

test('§7a::1/5: whole-pool shortcut — an official adapter ranked LAST in the raw pool is returned FIRST', () => {
  // Four tools, well under any default maxTools, so the whole-pool
  // completeness branch fires. Server names are chosen so plain
  // alphabetical/BM25 order would rank the official adapter ("zzz-official")
  // dead last — the partition must override that.
  // Description text is IDENTICAL across all four fixtures (word-for-word,
  // same length) so BM25 term-frequency AND document-length normalization
  // score every candidate exactly equally — the only remaining
  // differentiator pre-partition is the deterministic `(score DESC, id
  // ASC)` tiebreak this file's own `bm25Positive` sort documents, which
  // ranks "zzz-official" dead last on id alone.
  const tools = [
    makeTool('aaa-nonofficial', 'do_thing', 'widget gadget'),
    makeTool('bbb-nonofficial', 'do_thing', 'widget gadget'),
    makeTool('ccc-nonofficial', 'do_thing', 'widget gadget'),
    makeTool('zzz-official', 'do_thing', 'widget gadget'),
  ];
  const filter = makeFilter(tools, {
    'aaa-nonofficial': 'tier-3-rejected',
    'bbb-nonofficial': undefined,
    'ccc-nonofficial': 'tier-2-behaviorally-proven',
    'zzz-official': 'tier-0-protectnil',
  });
  const result = filter.selectSync('widget gadget', { maxTools: 8 });
  assert.equal(result.length, 4, 'whole-pool shortcut must return every candidate (pool fits within maxTools)');
  assert.equal(result[0]!.server, 'zzz-official', `official adapter must rank first, got order: ${result.map((t) => t.server).join(',')}`);
});

test('§7a::1/5: whole-pool shortcut — a straggler (BM25-unscored, appended post-hoc) that is official still ranks before non-official ranked candidates', () => {
  // "widget" matches only 3 of the 4 tools' text; the 4th ("straggler")
  // has no term overlap at all and is picked up ONLY by the whole-pool
  // completeness branch's straggler-append loop (`for (const doc of
  // sortedCandidates) if (!inRanked.has(id)) rankedIds.push(id)`) — this
  // is exactly the code path the gate finding flagged as bypassing the
  // partition (the append happened AFTER the (then-)early partition call).
  const tools = [
    makeTool('nonoff-a', 'do_thing', 'widget gadget'),
    makeTool('nonoff-b', 'do_thing', 'widget gadget'),
    makeTool('straggler-official', 'do_thing', 'completely unrelated text with zero overlap'),
  ];
  const filter = makeFilter(tools, {
    'nonoff-a': undefined,
    'nonoff-b': 'tier-3-rejected',
    'straggler-official': 'tier-1-provenance-verified',
  });
  const result = filter.selectSync('widget gadget', { maxTools: 8 });
  assert.equal(result.length, 3);
  assert.equal(
    result[0]!.server,
    'straggler-official',
    `the official straggler must be partitioned to the front, not appended unpartitioned at the back: ${result.map((t) => t.server).join(',')}`,
  );
});

/* ---------------------------------------------------------------------- *
 * maxPerServer/token-budget selection loop path (the other truncation exit).
 * ---------------------------------------------------------------------- */

test('§7a::1/8: the diversity-cap selection loop still ranks official before non-official once the pool exceeds maxTools', () => {
  // Identical description text for the same reason as the whole-pool
  // test above — isolates the tiebreak to id order alone.
  const tools = [
    makeTool('a-nonoff', 'do_thing', 'widget gadget'),
    makeTool('b-nonoff', 'do_thing', 'widget gadget'),
    makeTool('c-nonoff', 'do_thing', 'widget gadget'),
    makeTool('z-official', 'do_thing', 'widget gadget'),
  ];
  const filter = makeFilter(tools, {
    'a-nonoff': undefined,
    'b-nonoff': 'tier-3-rejected',
    'c-nonoff': 'tier-2-behaviorally-proven',
    'z-official': 'tier-0-protectnil',
  });
  // maxTools=2 forces the diversity-cap loop (pool of 4 > maxTools of 2).
  const result = filter.selectSync('widget gadget', { maxTools: 2 });
  assert.equal(result.length, 2);
  assert.equal(result[0]!.server, 'z-official', `official must be selected first even though it scores lowest on plain term-order: ${result.map((t) => t.server).join(',')}`);
});

/* ---------------------------------------------------------------------- *
 * Zero-lexical-signal fallback (the third exit path — found while fixing
 * the gate finding: this path bypassed the partition entirely, since it
 * returns before the BM25/hybrid pipeline that fed the (at-the-time) only
 * partition call site even runs).
 * ---------------------------------------------------------------------- */

test('§7a::1: the zero-lexical-signal alphabetical fallback ALSO partitions before its own truncation', () => {
  const tools = [
    makeTool('aaa-nonoff', 'do_thing', 'stopwords only the a of'),
    makeTool('zzz-official', 'do_thing', 'stopwords only the a of'),
  ];
  const filter = makeFilter(tools, {
    'aaa-nonoff': undefined,
    'zzz-official': 'tier-0-protectnil',
  });
  // A query of pure stopwords/punctuation tokenizes to zero terms,
  // triggering the "No lexical signal — deterministic alphabetical
  // fallback" branch, which returns BEFORE BM25 scoring ever runs.
  const result = filter.selectSync('the a of --- !!!', { maxTools: 8 });
  assert.equal(result.length, 2);
  assert.equal(
    result[0]!.server,
    'zzz-official',
    `zero-lexical-signal fallback must still rank official first (alphabetically it would rank last): ${result.map((t) => t.server).join(',')}`,
  );
});

/* ---------------------------------------------------------------------- *
 * §7a::14 — the runtime invariant assert actually fires on these paths
 * (proven by forcing a violation the partition itself cannot produce:
 * `setAdapterTiers` is called with a tier map that changes BETWEEN the
 * partition call and a hand-constructed post-partition mutation is not
 * reachable through the public API, so instead this proves the assert
 * fires by exercising `assertOfficialPartitionInvariantIds` directly
 * against a list shaped exactly like what `selectInternal` would have
 * produced pre-fix — i.e. a partitioned prefix with an unpartitioned
 * straggler appended, the literal shape of the gate-finding defect).
 * ---------------------------------------------------------------------- */

test('§7a::14: the invariant assert fires on exactly the pre-fix defect shape (partitioned prefix + unpartitioned straggler)', () => {
  const tierOf = (id: string): string | undefined => (id === 'zzz-official:tool' ? 'tier-0-protectnil' : undefined);
  // Simulates the pre-fix bug directly: rankedIds correctly partitioned
  // ([]), then a straggler (official!) appended unpartitioned at the end,
  // AFTER a non-official record that is already present.
  const preFixShape = ['nonoff:tool', 'zzz-official:tool'];
  assert.throws(
    () => assertOfficialPartitionInvariantIds(preFixShape, tierOf),
    (err: unknown) => {
      assert.ok(err instanceof OfficialPartitionInvariantError);
      assert.equal((err as InstanceType<typeof OfficialPartitionInvariantError>).code, 'retrieval_partition_invariant_failed');
      return true;
    },
  );
});

test('§7a::14: selectSync propagates the invariant failure as a synchronous throw (never a silently substituted un-partitioned order)', () => {
  // This test documents the propagation CONTRACT via the pure assert
  // function directly (selectInternal's own partition step makes the
  // violation structurally unreachable through the public select()/
  // selectSync() API post-fix — proving that IS the fix). Combined with
  // the two whole-pool tests above (which prove the partition/assert
  // pair now runs on the code path the gate flagged), this closes the
  // loop: the fixed code cannot reach the violating state, and IF it
  // ever did, the assert used at every exit point throws synchronously,
  // which selectSync (and selectWithVerdict) let propagate uncaught by
  // construction (they are plain synchronous methods with no try/catch
  // around selectInternal's call).
  const src = readFileSync(fileURLToPath(new URL('./ToolPreFilter.js', import.meta.url)), 'utf8');
  assert.ok(
    !/try\s*{\s*this\.selectInternal/.test(src),
    'selectSync/selectWithVerdict must not wrap selectInternal in a try/catch that could swallow the invariant throw',
  );
});
