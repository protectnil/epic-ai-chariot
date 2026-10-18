/**
 * CHARIOT::§16.1 Federation (CHARIOT-SPEC.md:1347, rulings item
 * 91/105/112(a)/121) — the kill-list retirement event. Ruling 112(a):
 * KillListWatcher's own `@deprecated` module comment (about the upstream
 * FEED being retired since v1.2.0) does NOT make the class dead code — a
 * caller can still construct and start it against a self-hosted kill-list
 * endpoint (`CHARIOT_KILL_LIST_URL`), and that IS the live runtime
 * retirement path. Ruling 121: this event's type-level name (and this
 * file's own name) was renamed from the spec's original wording because
 * that wording collides with a repo leak-denylist pattern for internal
 * catalog-lifecycle vocabulary; customer-facing semantics are unchanged —
 * the kill list retires an adapter from the tenant's catalog.
 *
 * REAL BEHAVIORAL test: constructs a real `KillListWatcher` against a
 * stubbed `fetch` (no live network) with `verifySignature: false` (this
 * module's own documented opt-out — see its header comment: "Consumers
 * who explicitly want to opt out of kill-list verification set
 * verifySignature: false") so no Ed25519 signature needs to be forged,
 * and a stand-in `FederationManager` (matching
 * `KillListWatcher.no-feed.test.ts`'s established fixture pattern).
 *
 * Run (after tsc): node --test dist/engine/federation/KillListWatcher.retired.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KillListWatcher } from './KillListWatcher.js';
import type { FederationManager } from './FederationManager.js';
import { chariotEmitter, type ChariotEvent } from '../../observability/emitter.js';

function fakeFederation(unloadResult: { success: boolean }): FederationManager {
  return {
    serverNames: () => ['evil-adapter', 'safe-adapter'],
    unloadAdapter: async () => ({
      success: unloadResult.success,
      reason: 'kill_list: contradiction_detected',
      quiescent: true,
      inFlightAtClose: 0,
      durationMs: 5,
    }),
  } as unknown as FederationManager;
}

function captureEvents(): { events: ChariotEvent[]; stop: () => void } {
  const events: ChariotEvent[] = [];
  const cb = (e: ChariotEvent) => events.push(e);
  chariotEmitter.on(cb);
  return { events, stop: () => chariotEmitter.off(cb) };
}

function stubFetch(body: unknown): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
  ) as typeof fetch;
  return () => { globalThis.fetch = original; };
}

test('§16.1 Federation: a kill-list unload emits adapter.retired with the entry\'s adapter id and demotedAt', async () => {
  const restoreFetch = stubFetch({
    version: 'test-1',
    generatedAt: new Date().toISOString(),
    entries: [{ adapter_id: 'evil-adapter', reason: 'contradiction_detected', ruleId: 'FAB-003', demotedAt: '2026-04-11T11:58:42Z' }],
  });
  const { events, stop } = captureEvents();
  try {
    const watcher = new KillListWatcher({
      federation: fakeFederation({ success: true }),
      url: 'https://example.test/killlist',
      verifySignature: false,
    });
    await watcher.pollNow();

    const evt = events.find((e) => e.type === 'adapter.retired');
    assert.ok(evt, 'expected adapter.retired');
    assert.equal(evt!.data.adapterId, 'evil-adapter');
    assert.equal(evt!.data.demotedAt, '2026-04-11T11:58:42Z');
    assert.equal(evt!.data.ruleId, 'FAB-003');
    assert.equal(evt!.data.success, true);
  } finally {
    stop();
    restoreFetch();
  }
});

test('§16.1 Federation: adapter.retired fires even when the unload itself fails (a retirement decision was made and acted on regardless)', async () => {
  const restoreFetch = stubFetch({
    version: 'test-2',
    generatedAt: new Date().toISOString(),
    entries: [{ adapter_id: 'evil-adapter', reason: 'contradiction_detected' }], // no demotedAt
  });
  const { events, stop } = captureEvents();
  try {
    const watcher = new KillListWatcher({
      federation: fakeFederation({ success: false }),
      url: 'https://example.test/killlist',
      verifySignature: false,
    });
    await watcher.pollNow();

    const evt = events.find((e) => e.type === 'adapter.retired');
    assert.ok(evt, 'expected adapter.retired even for a failed teardown');
    assert.equal(evt!.data.success, false);
    assert.equal(evt!.data.demotedAt, null, 'an entry with no demotedAt field must report null, not undefined or a fabricated timestamp');
  } finally {
    stop();
    restoreFetch();
  }
});

test('§16.1 Federation: an adapter NOT currently connected is never retired (no unnecessary event for a no-op poll)', async () => {
  const restoreFetch = stubFetch({
    version: 'test-3',
    generatedAt: new Date().toISOString(),
    entries: [{ adapter_id: 'not-connected-adapter', reason: 'x', demotedAt: '2026-01-01T00:00:00Z' }],
  });
  const { events, stop } = captureEvents();
  try {
    const watcher = new KillListWatcher({
      federation: fakeFederation({ success: true }),
      url: 'https://example.test/killlist',
      verifySignature: false,
    });
    await watcher.pollNow();

    assert.equal(events.filter((e) => e.type === 'adapter.retired').length, 0);
  } finally {
    stop();
    restoreFetch();
  }
});
