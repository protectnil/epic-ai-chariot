/**
 * Prove-on-revert for BIEN::§7a — official/non-official hard partition +
 * runtime invariant assert.
 *
 * BIEN SPEC.md §7a (verbatim, lines 138-150, quoted per-node in
 * `OfficialPartition.ts`'s module docstring): "official records SHALL rank
 * strictly above non-official records"; "stable-partition ... by
 * officialPartition DESC, then preserve the existing rerank ordering
 * within each partition using (rerankScore DESC, id ASC)"; "The production
 * re-sort SHALL assert the same invariant after partitioning; an invariant
 * failure SHALL fail closed and SHALL NOT return the reordered result."
 *
 * Run (after tsc): node --test dist/engine/retrieval/OfficialPartition.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import {
  isOfficialTier,
  adapterIdFromRetrievalId,
  stablePartitionOfficial,
  stablePartitionOfficialIds,
  assertOfficialPartitionInvariant,
  assertOfficialPartitionInvariantIds,
  OfficialPartitionInvariantError,
} from './OfficialPartition.js';

/* ---------------------------------------------------------------------- *
 * BIEN::§7a::2 — closed membership test.
 * ---------------------------------------------------------------------- */

test('§7a::2: tier-0-protectnil and tier-1-provenance-verified are official; nothing else is', () => {
  assert.equal(isOfficialTier('tier-0-protectnil'), true);
  assert.equal(isOfficialTier('tier-1-provenance-verified'), true);
  assert.equal(isOfficialTier('tier-2-behaviorally-proven'), false);
  assert.equal(isOfficialTier('tier-3-rejected'), false);
  assert.equal(isOfficialTier('registry-only-legacy'), false);
  assert.equal(isOfficialTier('unassigned'), false);
  // The retired legacy alias name is NOT the same string as the current
  // value and must NOT be treated as official by accident.
  assert.equal(isOfficialTier('tier-1-registry-verified'), false);
});

test('§7a::2: an ABSENT tier (undefined) is non-official — the closed membership test default', () => {
  assert.equal(isOfficialTier(undefined), false);
});

test('adapterIdFromRetrievalId: splits "server:name" tool-record ids on the FIRST colon', () => {
  assert.equal(adapterIdFromRetrievalId('github:create_issue'), 'github');
  // A tool name that itself contains a colon must not truncate the adapter id.
  assert.equal(adapterIdFromRetrievalId('aws:s3:put_object'), 'aws');
});

test('adapterIdFromRetrievalId: a bare id with no colon (CH-62 capability residual) returns unchanged', () => {
  assert.equal(adapterIdFromRetrievalId('some-adapter'), 'some-adapter');
});

/* ---------------------------------------------------------------------- *
 * BIEN::§7a::1/6/7/9 — stablePartitionOfficial (RetrievalResult-shaped).
 * ---------------------------------------------------------------------- */

function record(id: string, rerankScore: number): { id: string; rerankScore: number } {
  return { id, rerankScore };
}

test('§7a::1/6: mixed list, official scattered non-adjacently -> every official ranks before every non-official', () => {
  const candidates = [
    record('nonoff-a:tool', 0.9),
    record('off-a:tool', 0.5),
    record('nonoff-b:tool', 0.8),
    record('off-b:tool', 0.3),
  ];
  const tierByAdapterId = new Map<string, string | undefined>([
    ['off-a', 'tier-0-protectnil'],
    ['off-b', 'tier-1-provenance-verified'],
    ['nonoff-a', 'tier-2-behaviorally-proven'],
    ['nonoff-b', undefined],
  ]);
  const result = stablePartitionOfficial(candidates, tierByAdapterId);
  const ids = result.map((r) => r.id);
  const firstNonOfficialIdx = ids.findIndex((id) => !tierByAdapterId.get(adapterIdFromRetrievalId(id)));
  const lastOfficialIdx = ids.map((id) => isOfficialTier(tierByAdapterId.get(adapterIdFromRetrievalId(id)))).lastIndexOf(true);
  assert.ok(lastOfficialIdx < firstNonOfficialIdx, `officials must all precede non-officials, got order ${ids.join(',')}`);
});

test('§7a::7: within the OFFICIAL partition, (rerankScore DESC, id ASC) tiebreak is preserved exactly', () => {
  const candidates = [
    record('off-low:tool', 0.1),
    record('off-high:tool', 0.9),
    record('off-mid:tool', 0.5),
  ];
  const tierByAdapterId = new Map<string, string | undefined>([
    ['off-low', 'tier-0-protectnil'],
    ['off-high', 'tier-0-protectnil'],
    ['off-mid', 'tier-0-protectnil'],
  ]);
  const result = stablePartitionOfficial(candidates, tierByAdapterId);
  assert.deepEqual(result.map((r) => r.id), ['off-high:tool', 'off-mid:tool', 'off-low:tool']);
});

test('§7a::7: equal rerankScore ties break by id ASC (lexicographic)', () => {
  const candidates = [record('b:tool', 0.5), record('a:tool', 0.5)];
  const tierByAdapterId = new Map<string, string | undefined>([
    ['b', 'tier-0-protectnil'],
    ['a', 'tier-0-protectnil'],
  ]);
  const result = stablePartitionOfficial(candidates, tierByAdapterId);
  assert.deepEqual(result.map((r) => r.id), ['a:tool', 'b:tool']);
});

test('§7a::6/9: an all-official list is a no-op re-sort by partition, only the tiebreak applies (no model, no rerankScore mutation)', () => {
  const candidates = [record('off-a:tool', 0.9), record('off-b:tool', 0.1)];
  const tierByAdapterId = new Map<string, string | undefined>([
    ['off-a', 'tier-0-protectnil'],
    ['off-b', 'tier-1-provenance-verified'],
  ]);
  const result = stablePartitionOfficial(candidates, tierByAdapterId);
  assert.deepEqual(result.map((r) => r.id), ['off-a:tool', 'off-b:tool']);
  assert.equal(result[0]!.rerankScore, 0.9, 'rerankScore must never be mutated by the partition');
  assert.equal(result[1]!.rerankScore, 0.1);
});

test('§7a::6/9: an all-non-official list is a no-op re-sort by partition, only the tiebreak applies', () => {
  const candidates = [record('n-a:tool', 0.2), record('n-b:tool', 0.7)];
  const tierByAdapterId = new Map<string, string | undefined>([
    ['n-a', 'tier-2-behaviorally-proven'],
    ['n-b', undefined],
  ]);
  const result = stablePartitionOfficial(candidates, tierByAdapterId);
  assert.deepEqual(result.map((r) => r.id), ['n-b:tool', 'n-a:tool']);
});

test('§7a::2: a candidate whose tier is absent from the lookup map entirely (unknown adapter) is treated as non-official', () => {
  const candidates = [record('unknown:tool', 0.9), record('off:tool', 0.1)];
  const tierByAdapterId = new Map<string, string | undefined>([['off', 'tier-0-protectnil']]);
  const result = stablePartitionOfficial(candidates, tierByAdapterId);
  assert.deepEqual(result.map((r) => r.id), ['off:tool', 'unknown:tool']);
});

/* ---------------------------------------------------------------------- *
 * BIEN::§7a::1/6 — stablePartitionOfficialIds (plain-id variant).
 * ---------------------------------------------------------------------- */

test('stablePartitionOfficialIds: mixed ids partition correctly and ties preserve existing relative order (stability)', () => {
  const ids = ['n1:tool', 'o1:tool', 'n2:tool', 'o2:tool', 'n3:tool'];
  const tierOf = (id: string): string | undefined => {
    const adapter = adapterIdFromRetrievalId(id);
    return adapter.startsWith('o') ? 'tier-0-protectnil' : undefined;
  };
  const result = stablePartitionOfficialIds(ids, tierOf);
  assert.deepEqual(result, ['o1:tool', 'o2:tool', 'n1:tool', 'n2:tool', 'n3:tool']);
});

test('stablePartitionOfficialIds: BIEN::§7a::8 — this partition happens before any truncation the caller applies', () => {
  // Simulates ToolPreFilter.selectInternal's maxTools=2 truncation loop:
  // without the partition, the top-2 by pre-existing rank would be two
  // non-official ids and the official one would be dropped entirely.
  const preExistingOrder = ['nonoff-1:tool', 'nonoff-2:tool', 'official-1:tool'];
  const tierOf = (id: string): string | undefined =>
    adapterIdFromRetrievalId(id) === 'official-1' ? 'tier-0-protectnil' : undefined;
  const partitioned = stablePartitionOfficialIds(preExistingOrder, tierOf);
  const maxTools = 2;
  const truncated = partitioned.slice(0, maxTools);
  assert.ok(truncated.includes('official-1:tool'), 'the official record must survive truncation once partitioned first');
  assert.deepEqual(truncated, ['official-1:tool', 'nonoff-1:tool']);
});

/* ---------------------------------------------------------------------- *
 * BIEN::§7a::14 — runtime invariant assert, fail-closed.
 * ---------------------------------------------------------------------- */

test('§7a::14: assertOfficialPartitionInvariant passes silently on a genuinely partitioned list', () => {
  const partitioned = [record('off:tool', 0.9), record('n:tool', 0.1)];
  const tierByAdapterId = new Map<string, string | undefined>([
    ['off', 'tier-0-protectnil'],
    ['n', undefined],
  ]);
  assert.doesNotThrow(() => assertOfficialPartitionInvariant(partitioned, tierByAdapterId));
});

test('§7a::14: assertOfficialPartitionInvariant throws OfficialPartitionInvariantError on a forced violation (official after non-official)', () => {
  // Deliberately mis-ordered — non-official first, official second.
  const violating = [record('n:tool', 0.9), record('off:tool', 0.1)];
  const tierByAdapterId = new Map<string, string | undefined>([
    ['off', 'tier-0-protectnil'],
    ['n', undefined],
  ]);
  assert.throws(
    () => assertOfficialPartitionInvariant(violating, tierByAdapterId),
    (err: unknown) => {
      assert.ok(err instanceof OfficialPartitionInvariantError);
      assert.equal((err as OfficialPartitionInvariantError).code, 'retrieval_partition_invariant_failed');
      return true;
    },
  );
});

test('§7a::14: a single official-after-non-official pair among many records is caught (one counterexample is a failure)', () => {
  const violating = [
    record('off-1:tool', 0.9),
    record('n-1:tool', 0.8),
    record('n-2:tool', 0.7),
    record('off-2:tool', 0.6), // <-- the ONE counterexample
    record('n-3:tool', 0.5),
  ];
  const tierByAdapterId = new Map<string, string | undefined>([
    ['off-1', 'tier-0-protectnil'],
    ['off-2', 'tier-1-provenance-verified'],
    ['n-1', undefined],
    ['n-2', 'tier-3-rejected'],
    ['n-3', undefined],
  ]);
  assert.throws(() => assertOfficialPartitionInvariant(violating, tierByAdapterId), OfficialPartitionInvariantError);
});

test('§7a::14: assertOfficialPartitionInvariantIds mirrors the RetrievalResult variant for plain ids', () => {
  const tierOf = (id: string): string | undefined =>
    adapterIdFromRetrievalId(id) === 'off' ? 'tier-0-protectnil' : undefined;
  assert.doesNotThrow(() => assertOfficialPartitionInvariantIds(['off:tool', 'n:tool'], tierOf));
  assert.throws(() => assertOfficialPartitionInvariantIds(['n:tool', 'off:tool'], tierOf), OfficialPartitionInvariantError);
});

test('§7a::14: an all-official or all-non-official list never violates the invariant (nothing to compare)', () => {
  const tierOf = (): string | undefined => 'tier-0-protectnil';
  assert.doesNotThrow(() => assertOfficialPartitionInvariantIds(['a:tool', 'b:tool', 'c:tool'], tierOf));
  const tierOfNone = (): string | undefined => undefined;
  assert.doesNotThrow(() => assertOfficialPartitionInvariantIds(['a:tool', 'b:tool'], tierOfNone));
});

test('§7a::14: an empty list never violates the invariant', () => {
  assert.doesNotThrow(() => assertOfficialPartitionInvariantIds([], () => undefined));
});

/* ---------------------------------------------------------------------- *
 * BIEN::§7a::10 guard — the governance tier vocabulary (the two official
 * tier VALUES, and the lookup-index names) must appear in
 * src/engine/retrieval/*.js ONLY at the partition site (this module).
 * `types.ts` (RetrievalResult/ScoredResult — the ToolRecord-shaped types
 * the embedding/serializer path consumes) must never declare a `tier`
 * field. NOTE: this directory ALSO uses the word "tier" for a wholly
 * unrelated concept (`Tool.tier: 'orchestrated' | 'direct'`, defined in
 * `ChariotState.ts`, referenced by a couple of retrieval test fixtures) —
 * this guard checks the SPECIFIC BIEN::§7a governance-tier vocabulary
 * (the literal tier VALUE strings), not the bare word "tier", so it does
 * not false-positive on that unrelated usage.
 * ---------------------------------------------------------------------- */
test('§7a::10 guard: the BIEN governance-tier value strings appear in src/engine/retrieval/*.js ONLY in OfficialPartition.js', () => {
  const dir = fileURLToPath(new URL('.', import.meta.url));
  const governanceTierPattern = /tier-0-protectnil|tier-1-provenance-verified|adapterTierIndex|tierByAdapterId/;
  const offenders: string[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.js') || name.endsWith('.test.js')) continue;
    if (name === 'OfficialPartition.js') continue; // the partition module itself — expected to match
    const src = readFileSync(join(dir, name), 'utf8');
    if (governanceTierPattern.test(src)) offenders.push(name);
  }
  assert.deepEqual(
    offenders,
    [],
    `BIEN::§7a governance-tier vocabulary leaked into retrieval file(s) outside the partition module: ${offenders.join(', ')}`,
  );
});

test('§7a::10 guard: RetrievalResult/ScoredResult (types.js) never declare a tier field', () => {
  // types.ts compiles to an (near-)empty types.js under isolatedModules —
  // the authoritative check is against the SOURCE .ts, which is what
  // actually declares the interface shape a future edit would touch.
  const src = readFileSync(fileURLToPath(new URL('../../../src/engine/retrieval/types.ts', import.meta.url)), 'utf8');
  assert.ok(
    !/\btier\??\s*:/.test(src),
    'types.ts (RetrievalResult/ScoredResult) must never declare a `tier` field — BIEN::§7a::10 excludes it from the serializer/ToolRecord contract',
  );
});
