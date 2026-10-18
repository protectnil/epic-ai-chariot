/**
 * C4AMD::§8::6 (traceability.spec_nodes): "Consent state SHALL be
 * tenant-scoped, auditable, versioned, and revocable."
 * C4AMD::§8::4: "Customer authorization to use an adapter SHALL NOT imply
 * telemetry permission."
 *
 * Read-path behavior (getCurrentConsent's default-disabled state) is
 * proven by real execution against the repo's fake-Mongo fixture. The
 * write-path/versioning/revocation CONTRACT is proven by source
 * inspection — this repo's established convention for Mongo-write-path
 * IAM services with no live/fake insertOne+CAS harness available (see
 * audit.gap-detection.test.ts and admin.audit-logs-export.test.ts: "this
 * repo has no supertest/mongodb-memory-server dependency for colocated
 * unit tests"; the shared testFakes/fakeMongoCollection.ts fixture
 * supports findOne/updateOne only, not insertOne, so it cannot execute
 * audit.ts's append-only insertOne write path).
 *
 * Run (after tsc): node --test dist/iam/services/telemetry-consent.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const { getCurrentConsent } = await import('./telemetry-consent.js');
const { setMongoClient } = await import('../db.js');
const { makeFakeCollection, makeFakeMongoClient } = await import('../testFakes/fakeMongoCollection.js');

const src = readFileSync(fileURLToPath(new URL('./telemetry-consent.js', import.meta.url)), 'utf8');

// ── real execution: default state ───────────────────────────────────────────

test('§8::2/§8::6: getCurrentConsent on a tenant with no history returns disabled, version 0', async () => {
  setMongoClient(makeFakeMongoClient({ iam_audit_events: makeFakeCollection([]) }), 'chariot');
  const state = await getCurrentConsent('brand-new-tenant');
  assert.strictEqual(state.enabled, false);
  assert.strictEqual(state.version, 0);
  assert.strictEqual(state.tenantId, 'brand-new-tenant');
});

// ── source inspection: versioning is delegated to audit.ts's own seq ───────

test('§8::6: setConsent appends via audit.log (insert-only), never updates/deletes a document', () => {
  const fn = src.slice(src.indexOf('async function setConsent'), src.indexOf('async function revokeConsent'));
  assert.match(fn, /audit\.log\(/, 'setConsent must append via audit.log');
  assert.doesNotMatch(fn, /\bupdateOne\(/, 'setConsent must never call updateOne directly');
  assert.doesNotMatch(fn, /\bdeleteOne\(|\.remove\(|\bfindOneAndDelete\(/, 'setConsent must never delete');
  assert.match(fn, /version:\s*event\.seq/, 'the returned version must be the appended event\'s own seq (audit.ts\'s monotonic per-tenant counter)');
});

test('§8::6: revokeConsent is literally setConsent(..., false, ...) — a new version, never a delete', () => {
  const fn = src.slice(src.indexOf('async function revokeConsent'), src.indexOf('async function getCurrentConsent'));
  assert.match(fn, /setConsent\(\s*tenantId\s*,\s*false\s*,\s*actorId\s*\)/, 'revokeConsent must delegate to setConsent with enabled:false');
  assert.doesNotMatch(fn, /\bdeleteOne\(|\.remove\(|\bfindOneAndDelete\(/, 'revokeConsent must never delete a prior version');
});

test('§8::6: no function in this module ever deletes or mutates a prior consent record', () => {
  assert.doesNotMatch(src, /\bdeleteOne\(|\bfindOneAndDelete\(|\.remove\(|\bupdateOne\(|\bfindOneAndUpdate\(/, 'telemetry-consent.ts must be append-only: no delete/update anywhere in the file');
});

test('§8::6: getConsentHistory returns the FULL append-only history via audit.query, not just the latest', () => {
  const fn = src.slice(src.indexOf('async function getConsentHistory'));
  assert.match(fn, /audit\.query\(/, 'history must be read via audit.query (the full per-tenant log)');
  assert.doesNotMatch(fn, /audit\.queryLatest/, 'getConsentHistory must not silently narrow to only the latest version');
});

// ── §8::4 independence: no cross-reference to adapter-authorization code ──

test('§8::4: telemetry-consent.ts imports nothing from adapter-authorization modules', () => {
  for (const forbidden of ['./tenant.js', './oauth', './id-jag', './scim.js', './mapping.js']) {
    assert.ok(
      !src.includes(`from '${forbidden}`) && !src.includes(`from "${forbidden}`),
      `telemetry-consent.ts must not import ${forbidden} — granting adapter access must never imply telemetry consent`,
    );
  }
});
