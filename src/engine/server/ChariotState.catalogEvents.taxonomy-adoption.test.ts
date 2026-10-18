/**
 * CHARIOT::§16.1 Catalog (CHARIOT-SPEC.md:1350, rulings item 91/105) —
 * "Catalog: `catalog.signature_verified`, `catalog.signature_failed`,
 * `catalog.stale_warning`, `catalog.refresh_completed`."
 * (signature_verified/signature_failed were wired in a prior unit — see
 * src/catalog/VerifiedCatalog.taxonomy-adoption.test.ts. This file covers
 * the remaining two.)
 *
 * SOURCE INSPECTION (this repo's established convention): exercising
 * `loadAllAdaptersWithState()` behaviorally requires a real signed
 * adapter-catalog bundle on disk (Ed25519-signed, same class of
 * constraint documented in loader.invalidate-cache.test.ts's header
 * comment for a different module) — no test-key override exists for the
 * catalog signature verifier either.
 *
 * Run (after tsc): node --test dist/engine/server/ChariotState.catalogEvents.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('./ChariotState.js', import.meta.url)), 'utf8');

test('§16.1 Catalog: catalog.stale_warning is emitted ALONGSIDE (not instead of) the pre-existing adapter-catalog.state_stale WARN log', () => {
  const staleLogIdx = src.indexOf("log.warn('adapter-catalog.state_stale'");
  assert.ok(staleLogIdx >= 0, 'the pre-existing WARN log must still exist');
  const emitIdx = src.indexOf("chariotEmitter.send('catalog.stale_warning'", staleLogIdx);
  assert.ok(emitIdx > staleLogIdx && emitIdx < staleLogIdx + 500, 'catalog.stale_warning must be emitted immediately after the WARN log, inside the same `if (catalogStateResult.state === \'stale\')` branch');
});

test('§16.1 Catalog: catalog.refresh_completed fires at the single shared success-path return of loadAllAdaptersWithState', () => {
  const fnStart = src.indexOf('async function loadAllAdaptersWithState');
  assert.ok(fnStart >= 0);
  const emitIdx = src.indexOf("chariotEmitter.send('catalog.refresh_completed'", fnStart);
  const returnIdx = src.indexOf('effectiveCatalogEntries(catalogStateResult.state, kept)', fnStart);
  assert.ok(emitIdx > fnStart, 'catalog.refresh_completed must be emitted inside loadAllAdaptersWithState');
  assert.ok(returnIdx > emitIdx - 50 && returnIdx < emitIdx + 400, 'must sit immediately beside the shared success-path return statement');
});

test('§16.1 Catalog: catalog.refresh_completed is NOT reachable from the early-return failure branches (signature/parse failures)', () => {
  const fnStart = src.indexOf('async function loadAllAdaptersWithState');
  // `export async function loadAllAdapters(` in compiled output — "export
  // " sits between the newline and "async", so a literal
  // '\nasync function loadAllAdapters(' search never matches.
  const fnEndMatch = /\n(?:export\s+)?async function loadAllAdapters\(/.exec(src.slice(fnStart));
  const fnEnd = fnEndMatch ? fnStart + fnEndMatch.index : -1;
  const emitIdx = src.indexOf("chariotEmitter.send('catalog.refresh_completed'", fnStart);
  const firstEarlyReturnIdx = src.indexOf('stateReason: `${result.reason}', fnStart);
  assert.ok(fnEnd > fnStart && emitIdx > fnStart && emitIdx < fnEnd);
  assert.ok(firstEarlyReturnIdx > fnStart && firstEarlyReturnIdx < emitIdx, 'the signature/parse-failure early returns must appear in source BEFORE the refresh_completed emit, so those branches truly bypass it (they each contain their own `return`, never falling through)');
});
