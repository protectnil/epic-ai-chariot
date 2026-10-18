/**
 * Adversarial eval: ToolPreFilter's §8.6a overlay: candidate resolution
 * (BIEN::§9::14, CHARIOT-SPEC.md:767) — the last hook of row 1.33.
 *
 * `HybridRetriever` (fused via a `CompositeEdgeShard`-backed shard, see
 * `overlay/CompositeEdgeShard.ts`) can surface an `overlay:<tenantId>:
 * <adapterId>:<toolName>` candidate id inside `outcome.rankedIds` — an id
 * `this.toolIdMap` (built once, at index time, from DECLARED adapters only)
 * never contains. `ToolPreFilter.resolveToolForId` closes that gap by
 * falling back to `resolveOverlayTool`, which asks the wired
 * `TenantOverlayToolRegistryReader.resolveForTenant(id, tenantId)` for the
 * customer-verified tool and builds the SAME `Tool` shape declared tools
 * use (`server = adapterId`, `parameters = inputSchema`).
 *
 * Every fixture below also seeds a lexically-matching declared tool
 * alongside the overlay candidate. This is NOT incidental: an overlay
 * candidate's only fusion source is the dense leg (BM25 never scores it —
 * it was never indexed via `f.index()`), so a query whose fused TOP-1 is
 * the overlay candidate itself has zero lexical corroboration for that
 * top-1 and legitimately trips the UNRELATED CH-49 absolute-relevance-floor
 * abstention gate (`confidence.ts::relevanceSignal` — "a dense/sparse-only
 * candidate with no rerank and no lexical overlap scores 0 and abstains"),
 * which empties the ENTIRE shortlist for a reason that has nothing to do
 * with overlay resolution. Confirmed empirically (a throwaway harness
 * against the compiled dist/ reproduced `abstain: true` for a shard holding
 * ONLY the overlay point, and `abstain: false` once a second, lexically-
 * matched declared point was added so the fused top-1 carries a real BM25
 * fusionSource). Every fixture here therefore includes a `stripe:
 * create_invoice` declared point too, so the thing actually under test —
 * overlay resolution — is isolated from that separate, correctly-behaving
 * CH-49 mechanism.
 *
 * Failure classes proven here:
 *  1. An overlay candidate resolves to a real Tool for ITS OWN tenant.
 *  2. The SAME candidate under a DIFFERENT requesting tenant is dropped —
 *     never a crash, never the wrong tenant's tool
 *     (`TenantOverlayToolRegistry.resolveForTenant`'s own cross-tenant
 *     refusal, exercised here through the REAL class, not a stub).
 *  3. No registry wired at all → dropped (byte-identical to the pre-§8.6a
 *     behavior: `toolIdMap.get(id)` alone would already miss it).
 *  4. A malformed overlay id (too few colon-delimited segments) → dropped.
 *  5. A declared (non-overlay) candidate in the SAME query is completely
 *     unaffected — proves the overlay path is additive, not a detour every
 *     candidate now goes through.
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/ToolPreFilter.overlay-tool-resolution.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ToolPreFilter } from './ToolPreFilter.js';
import { TenantOverlayToolRegistry } from './TenantOverlayToolRegistry.js';
import { HybridRetriever } from '../retrieval/HybridRetriever.js';
import { overlayToolId } from '../retrieval/overlay/OverlayEmbedder.js';
import type { NativeEdgeShard, NativeScoredPoint } from '../retrieval/nativeEdge.js';
import type { Tool } from '../types/index.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeTool(server: string, name: string, description: string): Tool {
  return {
    server,
    name,
    description,
    parameters: { type: 'object', properties: {} },
    tier: 'direct',
  };
}

function makeShard(points: NativeScoredPoint[]): NativeEdgeShard {
  return {
    upsert() { throw new Error('not used in this fixture'); },
    flush() { throw new Error('not used in this fixture'); },
    pointsCount() { return points.length; },
    snapshotManifestJson() { return '{}'; },
    query() { return points; },
  };
}

function retrieverFor(points: NativeScoredPoint[]): HybridRetriever {
  return new HybridRetriever({
    shard: makeShard(points),
    serializeQuery: (q: string) => q,
    denseEncoder: { embed: (xs: string[]) => xs.map(() => [1, 2, 3]) },
    sparseEncoder: null,
    reranker: null,
  });
}

/** Same async-safe temp-dir helper as OverlayEmbedder.test.ts (see that
 * file's own comment for why a naive try/finally is wrong for an async fn). */
function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'toolprefilter-overlay-test-'));
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  let result: T;
  try {
    result = fn(dir);
  } catch (err) {
    cleanup();
    throw err;
  }
  if (result instanceof Promise) {
    return result.then(
      (value) => { cleanup(); return value; },
      (err) => { cleanup(); throw err; },
    ) as unknown as T;
  }
  cleanup();
  return result;
}

const WIDGET_SCHEMA = { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] };
const QUERY = 'create invoice widget lookup';

/** The lexically-matching declared point every fixture below includes so
 * the fused top-1 carries a real BM25 fusionSource (see file header) —
 * isolates the overlay-resolution assertions from the unrelated CH-49
 * abstention floor. */
function declaredPoint(): NativeScoredPoint {
  return { id: 'declared-1', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) };
}

// ── 1. resolves for its own tenant ──────────────────────────────────────────

test('overlay resolution: an overlay: candidate resolves to a Tool for its own tenant', async () => {
  await withTempDir(async (dir) => {
    const registry = new TenantOverlayToolRegistry({ rootDir: dir });
    await registry.recordTools('tenant-a', 'acme', [
      { name: 'widget_lookup', description: 'Look up a widget', inputSchema: WIDGET_SCHEMA },
    ]);

    const toolId = overlayToolId('tenant-a', 'acme', 'widget_lookup');
    const filter = new ToolPreFilter();
    filter.index([makeTool('stripe', 'create_invoice', 'create a stripe invoice for a customer')]);
    filter.setHybridRetriever(retrieverFor([
      { id: '1', score: 0.95, version: 1, payloadJson: JSON.stringify({ toolId }) },
      declaredPoint(),
    ]));
    filter.setOverlayToolRegistry(registry);

    const verdict = filter.selectWithVerdict(QUERY, { tenantId: 'tenant-a' });
    const resolved = verdict.tools.find((t) => t.name === 'widget_lookup');
    assert.ok(resolved, `expected the overlay tool in the shortlist, got: ${JSON.stringify(verdict.tools)}`);
    assert.equal(resolved!.server, 'acme');
    assert.equal(resolved!.description, 'Look up a widget');
    assert.deepEqual(resolved!.parameters, WIDGET_SCHEMA);
  });
});

// ── 2. cross-tenant refusal ──────────────────────────────────────────────────

test('overlay resolution: the SAME candidate under ANOTHER requesting tenant is dropped, never returned', async () => {
  await withTempDir(async (dir) => {
    const registry = new TenantOverlayToolRegistry({ rootDir: dir });
    await registry.recordTools('tenant-a', 'acme', [
      { name: 'widget_lookup', description: 'Look up a widget', inputSchema: WIDGET_SCHEMA },
    ]);

    const toolId = overlayToolId('tenant-a', 'acme', 'widget_lookup');
    const filter = new ToolPreFilter();
    filter.index([makeTool('stripe', 'create_invoice', 'create a stripe invoice for a customer')]);
    filter.setHybridRetriever(retrieverFor([
      { id: '1', score: 0.95, version: 1, payloadJson: JSON.stringify({ toolId }) },
      declaredPoint(),
    ]));
    filter.setOverlayToolRegistry(registry);

    const verdict = filter.selectWithVerdict(QUERY, { tenantId: 'tenant-b' });
    assert.ok(
      !verdict.tools.some((t) => t.name === 'widget_lookup'),
      'tenant B must never receive tenant A\'s overlay tool',
    );
    // Sanity: the fixture itself is not degenerate — the declared tool DOES
    // come through, so "widget_lookup" absent above is the refusal working,
    // not an accidentally-empty (e.g. abstaining) shortlist.
    assert.ok(verdict.tools.some((t) => t.name === 'create_invoice'), 'fixture sanity: the declared tool must still be present');
  });
});

// ── 3. no registry wired ────────────────────────────────────────────────────

test('overlay resolution: no registry wired at all → the overlay candidate is dropped, never a crash', () => {
  const toolId = overlayToolId('tenant-a', 'acme', 'widget_lookup');
  const filter = new ToolPreFilter();
  filter.index([makeTool('stripe', 'create_invoice', 'create a stripe invoice for a customer')]);
  filter.setHybridRetriever(retrieverFor([
    { id: '1', score: 0.95, version: 1, payloadJson: JSON.stringify({ toolId }) },
    declaredPoint(),
  ]));
  // setOverlayToolRegistry deliberately never called.

  assert.doesNotThrow(() => {
    const verdict = filter.selectWithVerdict(QUERY, { tenantId: 'tenant-a' });
    assert.ok(!verdict.tools.some((t) => t.name === 'widget_lookup'));
    assert.ok(verdict.tools.some((t) => t.name === 'create_invoice'), 'fixture sanity: the declared tool must still be present');
  });
});

// ── 4. malformed overlay id ─────────────────────────────────────────────────

test('overlay resolution: a malformed overlay: id (too few segments) is dropped, never a crash', async () => {
  await withTempDir(async (dir) => {
    const registry = new TenantOverlayToolRegistry({ rootDir: dir });
    await registry.recordTools('tenant-a', 'acme', [
      { name: 'widget_lookup', description: 'Look up a widget', inputSchema: WIDGET_SCHEMA },
    ]);

    const filter = new ToolPreFilter();
    filter.index([makeTool('stripe', 'create_invoice', 'create a stripe invoice for a customer')]);
    filter.setHybridRetriever(retrieverFor([
      // Only 2 colon-delimited segments after 'overlay' — parseOverlayToolId
      // requires >= 4 parts total ('overlay', tenantId, adapterId, toolName).
      { id: '1', score: 0.95, version: 1, payloadJson: JSON.stringify({ toolId: 'overlay:tenant-a' }) },
      declaredPoint(),
    ]));
    filter.setOverlayToolRegistry(registry);

    assert.doesNotThrow(() => {
      const verdict = filter.selectWithVerdict(QUERY, { tenantId: 'tenant-a' });
      assert.ok(verdict.tools.some((t) => t.name === 'create_invoice'), 'fixture sanity: the declared tool must still be present');
    });
  });
});

// ── 5. declared tools unaffected ────────────────────────────────────────────

test('overlay resolution: a declared (non-overlay) candidate in the SAME query is completely unaffected', async () => {
  await withTempDir(async (dir) => {
    const registry = new TenantOverlayToolRegistry({ rootDir: dir });
    await registry.recordTools('tenant-a', 'acme', [
      { name: 'widget_lookup', description: 'Look up a widget', inputSchema: WIDGET_SCHEMA },
    ]);
    const overlayId = overlayToolId('tenant-a', 'acme', 'widget_lookup');

    const filter = new ToolPreFilter();
    filter.index([makeTool('stripe', 'create_invoice', 'create a stripe invoice for a customer')]);
    filter.setHybridRetriever(retrieverFor([
      { id: '1', score: 0.95, version: 1, payloadJson: JSON.stringify({ toolId: overlayId }) },
      { id: '2', score: 0.9, version: 1, payloadJson: JSON.stringify({ toolId: 'stripe:create_invoice' }) },
    ]));
    filter.setOverlayToolRegistry(registry);

    const verdict = filter.selectWithVerdict(QUERY, { tenantId: 'tenant-a' });
    const declared = verdict.tools.find((t) => t.name === 'create_invoice');
    assert.ok(declared, 'the declared tool must still resolve exactly as before');
    assert.equal(declared!.server, 'stripe');
    assert.equal(declared!.description, 'create a stripe invoice for a customer');
    const overlay = verdict.tools.find((t) => t.name === 'widget_lookup');
    assert.ok(overlay, 'the overlay tool must ALSO resolve, alongside the declared one');
  });
});
