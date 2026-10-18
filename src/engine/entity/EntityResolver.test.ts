/**
 * Adversarial evals for EntityResolver fixes from 35f8710.
 *
 * Covers:
 *   P1 — RBAC fan-out fail-closed: ctx=undefined previously spread to {}
 *        producing a synthetic permissive context. Now throws.
 *   P2 — maxAdapters < 1: negative → wrong slice; 0 → silent no_source.
 *        Now throws RangeError with a diagnostic message.
 *
 * No mocked dependencies. Real EntityResolver class under real call paths.
 *
 * Run: node --test dist/engine/entity/EntityResolver.test.js
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { EntityResolver } from './EntityResolver.js';
import type { ChariotState } from '../server/ChariotState.js';
import type { CallContext } from '../server/toolHandlers.js';

// Minimal state stub: EntityResolver.resolve() reads allAdapters,
// adapterById, and (inside the loop) calls handleCall which accesses
// more state fields. With an empty adapter list the loop body never
// runs, so only the fields accessed before the loop are required.
function emptyState(): ChariotState {
  return {
    allAdapters: [],
    adapterById: new Map(),
    credentials: {},
    configuredAdapterIds: new Set(),
    // Fields below are never accessed in the resolve() paths we test
    // (empty adapter list → loop is skipped or throws before loop).
    toolPreFilter: null as unknown as ChariotState['toolPreFilter'],
    fullCatalogFilter: null as unknown as ChariotState['fullCatalogFilter'],
    loadedAt: new Date().toISOString(),
    getConfiguredAdapters: () => [],
    packageRoot: '/nonexistent',
  } as unknown as ChariotState;
}

// A minimal valid CallContext that satisfies the localMode trust opt-in.
const localCtx: CallContext = { localMode: true, tenantId: 'test-tenant' };

// ─── RBAC fan-out fail-closed (P1 fix) ───────────────────────────────────────
describe('EntityResolver — RBAC fan-out fail-closed (P1)', () => {

  test('resolve() with ctx=undefined throws — not a silent bypass', async () => {
    const resolver = new EntityResolver(emptyState());
    await assert.rejects(
      () => resolver.resolve('anything', {}, undefined),
      (err: unknown) => {
        assert.ok(err instanceof Error, 'must throw an Error');
        assert.ok(
          err.message.includes('ctx is required') ||
          err.message.includes('RBAC') ||
          err.message.includes('denied'),
          `unexpected message: ${(err as Error).message}`,
        );
        return true;
      },
      'ctx=undefined must cause resolve() to throw (fail-closed), not fabricate a permissive context',
    );
  });

  test('resolve() with real ctx succeeds — no false-positives on the guard', async () => {
    // With a real ctx and an empty adapter list the resolver returns
    // no_source. It must NOT throw the ctx guard error.
    const resolver = new EntityResolver(emptyState());
    const result = await resolver.resolve('test-entity', {}, localCtx);
    assert.strictEqual(result.status, 'no_source', 'empty adapters → no_source');
    assert.strictEqual(result.sourceCount, 0, 'sourceCount must be 0');
  });
});

// ─── maxAdapters validation (P2 fix) ─────────────────────────────────────────
describe('EntityResolver — maxAdapters guard (P2)', () => {

  test('maxAdapters=-1 throws RangeError', async () => {
    const resolver = new EntityResolver(emptyState());
    await assert.rejects(
      () => resolver.resolve('x', { maxAdapters: -1 }, localCtx),
      (err: unknown) => {
        assert.ok(err instanceof RangeError, `expected RangeError, got ${(err as Error)?.constructor?.name}`);
        assert.ok(
          (err as RangeError).message.includes('maxAdapters') &&
          (err as RangeError).message.includes('-1'),
          `RangeError message must name the bad value; got: ${(err as RangeError).message}`,
        );
        return true;
      },
      'negative maxAdapters must throw RangeError, not silently probe wrong count',
    );
  });

  test('maxAdapters=0 throws RangeError', async () => {
    const resolver = new EntityResolver(emptyState());
    await assert.rejects(
      () => resolver.resolve('x', { maxAdapters: 0 }, localCtx),
      (err: unknown) => {
        assert.ok(err instanceof RangeError, `expected RangeError, got ${(err as Error)?.constructor?.name}`);
        assert.ok(
          (err as RangeError).message.includes('maxAdapters') &&
          (err as RangeError).message.includes('0'),
          `RangeError message must name the bad value; got: ${(err as RangeError).message}`,
        );
        return true;
      },
      'maxAdapters=0 must throw RangeError, not silently return empty no_source',
    );
  });

  test('maxAdapters=1 (minimum valid) — does not throw', async () => {
    // Boundary: exactly 1 is valid.
    const resolver = new EntityResolver(emptyState());
    // May still return no_source (no adapters), but must not throw.
    const result = await resolver.resolve('x', { maxAdapters: 1 }, localCtx);
    assert.strictEqual(result.status, 'no_source');
  });

  test('negative maxAdapters throws before ctx check — ordering is stable', async () => {
    // RangeError happens before the ctx guard (pre-loop); verify both
    // fire correctly when ctx is undefined too: RangeError wins.
    const resolver = new EntityResolver(emptyState());
    await assert.rejects(
      () => resolver.resolve('x', { maxAdapters: -5 }, undefined),
      RangeError,
      'RangeError must be thrown even when ctx is also absent',
    );
  });
});

// ─── whitespace/empty query rejected as no-input (CHARIOT::§23.2::70) ─
describe('EntityResolver — empty/whitespace query gate', () => {

  test('whitespace-only query resolves as no_source without probing', async () => {
    // "   " has non-zero length; before the fix it sailed past the emptiness
    // gate into the fan-out and a permissive adapter falsely became a source.
    const resolver = new EntityResolver(emptyState());
    const r = await resolver.resolve('   ', {}, localCtx);
    assert.strictEqual(r.status, 'no_source', 'whitespace query must be no_source');
    assert.strictEqual(r.sourceCount, 0, 'no fabricated source');
    assert.strictEqual(r.probedAdapters, 0, 'no adapter is probed for empty input');
    // canonicalId echoes the raw input VERBATIM (contract): not trimmed.
    assert.strictEqual(r.canonicalId, '   ', 'canonicalId must stay verbatim');
    assert.strictEqual(r.displayName, null, 'no display name for no-input');
  });

  test('empty-string query resolves as no_source', async () => {
    const resolver = new EntityResolver(emptyState());
    const r = await resolver.resolve('', {}, localCtx);
    assert.strictEqual(r.status, 'no_source');
    assert.strictEqual(r.sourceCount, 0);
    assert.strictEqual(r.canonicalId, '');
  });

  test('whitespace compare is no_comparison (never resolvedAsSame)', async () => {
    // Two whitespace ghosts previously compared at similarity 1.0 /
    // resolvedAsSame:true off identical empty scaffolding.
    const resolver = new EntityResolver(emptyState());
    const c = await resolver.compare('   ', '  ', {}, localCtx);
    assert.strictEqual(c.status, 'no_comparison');
    assert.strictEqual(c.similarityScore, null);
    assert.strictEqual(c.resolvedAsSame, false);
  });
});
