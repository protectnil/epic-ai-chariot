/**
 * Adversarial eval: CompositeEdgeShard (BIEN::§9::14 / CHARIOT-SPEC.md:767)
 *
 * Failure classes enumerated from the clause bytes (see CompositeEdgeShard.ts
 * header for the full quotes) and each proven closed here:
 *  1. Overlay contributes results alongside sealed, for the CORRECT tenant
 *     ("queryable together").
 *  2. Deterministic order independent of shard resolution order (tie-break).
 *  3. A toolId collision across shards is not double-counted (RankFusion
 *     double-count hazard from `pointsToLeg`'s positional accumulation).
 *  4. A malformed (no-toolId) point from either shard is passed through
 *     unmolested, never coalesced with another malformed point or dropped
 *     here (HybridRetriever's own accounting must still see it).
 *  5. Write operations are refused, fail-closed, never a silent no-op.
 *  6. No tenantId → sealed-only, the overlay provider is never even called.
 *  7. Cross-tenant isolation: tenant B's query never resolves, never sees,
 *     tenant A's overlay (gate finding D1 — the defect this design exists
 *     to close).
 *  8. A tenant with no overlay (provider returns null) is sealed-only, byte-
 *     identical to the no-tenant path.
 *  9. Gate-round-3 finding E1(b): a STALE overlay point (its toolId not in
 *     the live-toolIds set) is dropped BEFORE merge/sort/slice — it can
 *     never displace a live result from the top-k even if it scores
 *     highest in the overlay shard's own ranking.
 *  10. E1(b): a `null` live-toolIds answer (no liveness signal at all) is
 *      fail-closed — every checkable overlay point is dropped, never
 *      trusted as fresh by default.
 *  11. E1(b): a malformed (no-toolId) overlay point is NOT staleness-
 *      checked — it is a leg-integrity concern (failure class 4 above),
 *      unrelated to freshness, and passes through regardless of the live set.
 *
 * Run (after tsc):
 *   node --test dist/engine/retrieval/overlay/CompositeEdgeShard.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { CompositeEdgeShard, type OverlayLiveToolIdsProvider } from './CompositeEdgeShard.js';
import type { NativeEdgeShard, NativeScoredPoint, NativeQueryRequest } from '../nativeEdge.js';

function fakeShard(points: NativeScoredPoint[]): NativeEdgeShard {
  return {
    upsert() { throw new Error('not used in this fixture'); },
    flush() { throw new Error('not used in this fixture'); },
    pointsCount() { return points.length; },
    snapshotManifestJson() { return '{}'; },
    query(_req: NativeQueryRequest, _tenantId?: string) { return points; },
  };
}

const REQUEST: NativeQueryRequest = { prefetches: [], query: { using: 'dense', dense: [1, 0, 0] }, limit: 8, exact: true };

/** Every checkable point counts as live — for tests that are about the
 * merge/fusion logic (failure classes 1-8), not about E1 staleness
 * filtering itself (classes 9-11, which build their own live sets). Only
 * `.has()` is ever called on this by `CompositeEdgeShard`. */
const ALWAYS_LIVE: OverlayLiveToolIdsProvider = () => ({ has: () => true }) as unknown as ReadonlySet<string>;

test('composite: overlay results are surfaced alongside sealed results for the resolved tenant', () => {
  const sealed = fakeShard([
    { id: '1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) },
  ]);
  const overlayA = fakeShard([
    { id: '2', score: 0.5, version: 1, payloadJson: JSON.stringify({ toolId: 'overlay:tenant-a:acme:widget_lookup' }) },
  ]);
  const composite = new CompositeEdgeShard(sealed, (tenantId) => (tenantId === 'tenant-a' ? overlayA : null), ALWAYS_LIVE);
  const results = composite.query(REQUEST, 'tenant-a');
  const ids = results.map((r) => JSON.parse(r.payloadJson!).toolId).sort();
  assert.deepEqual(ids, ['overlay:tenant-a:acme:widget_lookup', 'stripe:create_invoice']);
});

test('composite: deterministic order — score desc, id tie-break, regardless of shard order', () => {
  const sealed = fakeShard([
    { id: 'a', score: 0.5, version: 1, payloadJson: JSON.stringify({ toolId: 'z:tool' }) },
  ]);
  const overlay = fakeShard([
    { id: 'b', score: 0.5, version: 1, payloadJson: JSON.stringify({ toolId: 'a:tool' }) },
  ]);
  const composite = new CompositeEdgeShard(sealed, () => overlay, ALWAYS_LIVE);
  const results = composite.query(REQUEST, 'tenant-a');
  // Equal score → lexicographic id tie-break on the RAW point id ('a' < 'b').
  assert.deepEqual(results.map((r) => r.id), ['a', 'b']);
});

test('composite: a toolId returned by BOTH shards is admitted exactly once (sealed wins), never double-counted', () => {
  const sealed = fakeShard([
    { id: 'sealed-1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) },
  ]);
  const overlay = fakeShard([
    // Same toolId as sealed — must never happen by the overlay: prefix
    // convention, but the merge must still be safe if it did.
    { id: 'overlay-1', score: 0.99, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) },
  ]);
  const composite = new CompositeEdgeShard(sealed, () => overlay, ALWAYS_LIVE);
  const results = composite.query(REQUEST, 'tenant-a');
  assert.equal(results.length, 1, 'exactly one row for the collided toolId — RankFusion must never see two rows for one id in one leg');
  assert.equal(results[0].id, 'sealed-1', 'sealed shard wins a collision (queried first, higher authority)');
});

test('composite: malformed (no-toolId) points from both shards pass through unmolested, never coalesced', () => {
  const sealed = fakeShard([
    { id: 'm1', score: 0.4, version: 1 }, // no payload at all
  ]);
  const overlay = fakeShard([
    { id: 'm2', score: 0.3, version: 1, payloadJson: '{not json' },
  ]);
  const composite = new CompositeEdgeShard(sealed, () => overlay, ALWAYS_LIVE);
  const results = composite.query(REQUEST, 'tenant-a');
  assert.equal(results.length, 2, 'two distinct malformed points must both survive the merge for HybridRetriever to account for');
  assert.deepEqual(results.map((r) => r.id).sort(), ['m1', 'm2']);
});

test('composite: limit truncation applies AFTER the merge, not per-shard', () => {
  const sealed = fakeShard([
    { id: 's1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'a:one' }) },
    { id: 's2', score: 0.8, version: 1, payloadJson: JSON.stringify({ toolId: 'a:two' }) },
  ]);
  const overlay = fakeShard([
    { id: 'o1', score: 0.95, version: 1, payloadJson: JSON.stringify({ toolId: 'overlay:t:a:three' }) },
  ]);
  const composite = new CompositeEdgeShard(sealed, () => overlay, ALWAYS_LIVE);
  const results = composite.query({ ...REQUEST, limit: 2 }, 'tenant-a');
  assert.equal(results.length, 2);
  // Highest score first: overlay's 0.95 beats both sealed rows.
  assert.equal(results[0].id, 'o1');
});

test('composite: write operations are refused fail-closed, never a silent no-op', () => {
  const composite = new CompositeEdgeShard(fakeShard([]), () => fakeShard([]), ALWAYS_LIVE);
  assert.throws(() => composite.upsert('[]'), /read-only/);
  assert.throws(() => composite.flush(), /read-only/);
});

test('composite: no tenantId is an exact pass-through — the overlay provider is never even called', () => {
  const sealedPoints: NativeScoredPoint[] = [
    { id: '1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'b:tool' }) },
    { id: '2', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'a:tool' }) },
  ];
  const sealed = fakeShard(sealedPoints);
  let providerCalls = 0;
  const composite = new CompositeEdgeShard(sealed, () => { providerCalls++; return fakeShard([]); }, ALWAYS_LIVE);
  const results = composite.query(REQUEST);
  assert.equal(results, sealedPoints, 'no-tenant path must return the exact same array reference — byte-identical to pre-overlay behavior');
  assert.equal(providerCalls, 0, 'the overlay provider must never be invoked when no tenantId is supplied');
});

test('composite: a tenant with no overlay (provider returns null) is sealed-only, byte-identical to no-tenant', () => {
  const sealedPoints: NativeScoredPoint[] = [
    { id: '1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'b:tool' }) },
  ];
  const sealed = fakeShard(sealedPoints);
  const composite = new CompositeEdgeShard(sealed, () => null, ALWAYS_LIVE);
  const results = composite.query(REQUEST, 'tenant-with-no-overlay');
  assert.equal(results, sealedPoints);
});

test('composite: CROSS-TENANT ISOLATION — tenant B never sees tenant A\'s overlay tools (gate finding D1)', () => {
  const sealed = fakeShard([]);
  const overlayByTenant = new Map<string, NativeEdgeShard>([
    ['tenant-a', fakeShard([{ id: 'x1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'overlay:tenant-a:acme:secret_tool' }) }])],
    ['tenant-b', fakeShard([{ id: 'x2', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'overlay:tenant-b:other:public_tool' }) }])],
  ]);
  let requestedTenant: string | undefined;
  const composite = new CompositeEdgeShard(sealed, (tenantId) => {
    requestedTenant = tenantId;
    return overlayByTenant.get(tenantId) ?? null;
  }, ALWAYS_LIVE);

  const resultsForB = composite.query(REQUEST, 'tenant-b');
  assert.equal(requestedTenant, 'tenant-b', 'the provider must be asked for exactly the requesting tenant, never another');
  assert.equal(resultsForB.length, 1);
  assert.equal(JSON.parse(resultsForB[0].payloadJson!).toolId, 'overlay:tenant-b:other:public_tool');
  assert.ok(
    !resultsForB.some((r) => JSON.parse(r.payloadJson!).toolId === 'overlay:tenant-a:acme:secret_tool'),
    'tenant B\'s query result must never contain tenant A\'s overlay tool',
  );

  const resultsForA = composite.query(REQUEST, 'tenant-a');
  assert.equal(requestedTenant, 'tenant-a');
  assert.equal(resultsForA.length, 1);
  assert.equal(JSON.parse(resultsForA[0].payloadJson!).toolId, 'overlay:tenant-a:acme:secret_tool');
});

test('composite: pointsCount reports the sealed shard only (per-tenant overlay counts are not summable here)', () => {
  const composite = new CompositeEdgeShard(fakeShard([{ id: '1', score: 1, version: 1 }]), () => fakeShard([
    { id: '2', score: 1, version: 1 }, { id: '3', score: 1, version: 1 },
  ]), ALWAYS_LIVE);
  assert.equal(composite.pointsCount(), 1);
});

// ── 9. E1(b) — a stale overlay point is dropped before merge/sort/slice ────

test('E1(b): a stale overlay point (toolId not in the live set) is dropped even though it outscores everything', () => {
  const sealed = fakeShard([
    { id: 's1', score: 0.5, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) },
  ]);
  const staleToolId = 'overlay:tenant-a:acme:revoked_tool';
  const liveToolId = 'overlay:tenant-a:acme:live_tool';
  const overlay = fakeShard([
    // Highest score of the three — would win the top-k if not filtered.
    { id: 'o-stale', score: 0.99, version: 1, payloadJson: JSON.stringify({ toolId: staleToolId }) },
    { id: 'o-live', score: 0.6, version: 1, payloadJson: JSON.stringify({ toolId: liveToolId }) },
  ]);
  const liveSet = new Set([liveToolId]); // staleToolId deliberately absent
  const composite = new CompositeEdgeShard(sealed, () => overlay, () => liveSet);

  const results = composite.query(REQUEST, 'tenant-a');
  const ids = results.map((r) => JSON.parse(r.payloadJson!).toolId);
  assert.ok(!ids.includes(staleToolId), 'the stale (revoked) tool must never appear, regardless of its score');
  assert.ok(ids.includes(liveToolId), 'the live tool must still appear');
  assert.ok(ids.includes('stripe:create_invoice'));
  assert.equal(results.length, 2, 'exactly the sealed tool and the live overlay tool — the stale one is gone, not just re-ranked');
});

// ── 10. E1(b) — null liveness answer fails closed ──────────────────────────

test('E1(b): a null live-toolIds answer drops every checkable overlay point (fail-closed, never trust unverified freshness)', () => {
  const sealed = fakeShard([
    { id: 's1', score: 0.5, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) },
  ]);
  const overlay = fakeShard([
    { id: 'o1', score: 0.99, version: 1, payloadJson: JSON.stringify({ toolId: 'overlay:tenant-a:acme:some_tool' }) },
  ]);
  const composite = new CompositeEdgeShard(sealed, () => overlay, () => null);

  const results = composite.query(REQUEST, 'tenant-a');
  assert.equal(results.length, 1);
  assert.equal(JSON.parse(results[0].payloadJson!).toolId, 'stripe:create_invoice');
});

// ── 11. E1(b) — malformed overlay points are not staleness-checked ─────────

test('E1(b): a malformed (no-toolId) overlay point is NOT staleness-checked — passes through regardless of the live set', () => {
  const sealed = fakeShard([]);
  const overlay = fakeShard([
    { id: 'o-malformed', score: 0.9, version: 1 }, // no payload at all
  ]);
  // Empty live set — if this point were (wrongly) staleness-checked, it
  // would be dropped; it must survive because it has no toolId to check.
  const composite = new CompositeEdgeShard(sealed, () => overlay, () => new Set());

  const results = composite.query(REQUEST, 'tenant-a');
  assert.equal(results.length, 1);
  assert.equal(results[0].id, 'o-malformed');
});
