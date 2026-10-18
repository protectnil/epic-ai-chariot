/**
 * CHARIOT::§16.1 Catalog (CHARIOT-SPEC.md:1351, rulings item 91) — "Catalog:
 * `catalog.signature_verified`, `catalog.signature_failed`,
 * `catalog.stale_warning`, `catalog.refresh_completed`."
 *
 * Proves `VerifiedCatalog.markVerified()`/`markFailed()` emit the pinned
 * `catalog.signature_verified`/`catalog.signature_failed` events on
 * `chariotEmitter`, real end-to-end (subscribe, call the real method,
 * assert the real subscriber saw it) — not a source-text check, since this
 * class is pure (no DB/network I/O) and fully unit-testable directly.
 *
 * Run (after tsc): node --test dist/catalog/VerifiedCatalog.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { VerifiedCatalog } from './VerifiedCatalog.js';
import { chariotEmitter, type ChariotEvent } from '../observability/emitter.js';

function captureEvents(): { events: ChariotEvent[]; stop: () => void } {
  const events: ChariotEvent[] = [];
  const cb = (e: ChariotEvent) => events.push(e);
  chariotEmitter.on(cb);
  return { events, stop: () => chariotEmitter.off(cb) };
}

test('§16.1 Catalog: markVerified() emits catalog.signature_verified with the adapter name', () => {
  const { events, stop } = captureEvents();
  try {
    const catalog = new VerifiedCatalog();
    catalog.markVerified('my-adapter');
    const found = events.find((e) => e.type === 'catalog.signature_verified');
    assert.ok(found, 'expected a catalog.signature_verified event');
    assert.equal(found!.data.adapterName, 'my-adapter');
  } finally {
    stop();
  }
});

test('§16.1 Catalog: markFailed() emits catalog.signature_failed with the adapter name and reason, and is alertWorthy/urgent', () => {
  const { events, stop } = captureEvents();
  try {
    const catalog = new VerifiedCatalog();
    catalog.markFailed('bad-adapter', 'signature mismatch');
    const found = events.find((e) => e.type === 'catalog.signature_failed');
    assert.ok(found, 'expected a catalog.signature_failed event');
    assert.equal(found!.data.adapterName, 'bad-adapter');
    assert.equal(found!.data.reason, 'signature mismatch');
    assert.equal(found!.severity, 'urgent');
    assert.equal(found!.alertWorthy, true, 'a signature-verification failure must surface to the admin via the alert queue');
  } finally {
    stop();
  }
});

test('§16.1 Catalog: markFailed() reports the correct consecutiveFailures count across repeated failures for the same adapter', () => {
  const { events, stop } = captureEvents();
  try {
    const catalog = new VerifiedCatalog();
    catalog.markFailed('flaky-adapter', 'first failure');
    catalog.markFailed('flaky-adapter', 'second failure');
    const failures = events.filter((e) => e.type === 'catalog.signature_failed');
    assert.equal(failures.length, 2);
    assert.equal(failures[0]!.data.consecutiveFailures, 1);
    assert.equal(failures[1]!.data.consecutiveFailures, 2);
  } finally {
    stop();
  }
});

test('§16.1 Catalog: markVerified() throws on an invalid verifiedAt timestamp BEFORE emitting anything', () => {
  const { events, stop } = captureEvents();
  try {
    const catalog = new VerifiedCatalog();
    assert.throws(() => catalog.markVerified('bad-timestamp-adapter', 'not-a-date'));
    assert.equal(events.length, 0, 'a rejected markVerified() call must not emit catalog.signature_verified');
  } finally {
    stop();
  }
});
