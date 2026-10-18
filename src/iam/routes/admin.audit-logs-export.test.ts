/**
 * Prove-on-revert for CHARIOT::§9.6::1 and CHARIOT::§9.8.3::4 on the
 * GET /audit-logs export route.
 *
 * Spec, CHARIOT-SPEC.md §9.6:
 *   "The implemented export endpoint is GET /enterprise/{tenantId}/admin/
 *   audit-logs ... It accepts since, until, eventType, and actor filters
 *   and returns JSON. Streaming is implemented at the response body so
 *   very large windows do not buffer in memory."
 * Spec, CHARIOT-SPEC.md §9.8.3 (quoted in full in
 * length-attestation.reconcile.test.ts): reconcile currentLength against
 * attestedLength on export and halt on tail truncation.
 *
 * Defect this catches: the route accepted only an email-shaped
 * `actorEmail` filter (no generic `actor`), and read the full matching
 * page via `.toArray()` into a single in-memory array before a single
 * `res.json(...)` call — the literal opposite of "so very large windows do
 * not buffer in memory". It also never consulted the length-attestation
 * subsystem at all, so a truncated chain was served with no detection.
 *
 * Behavioral coverage against a live Mongo + Express server lives in the
 * infra-gated eval harness (this repo has no supertest/mongodb-memory-server
 * dependency for colocated unit tests — see admin.tenant-crud.test.ts for
 * the established source-inspection convention this file follows); this
 * file asserts the contract by source inspection, without Mongo.
 *
 * Run (after tsc): node --test dist/iam/routes/admin.audit-logs-export.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const adminSrc = readFileSync(fileURLToPath(new URL('./admin.js', import.meta.url)), 'utf8');

function routeBody(src: string): string {
  const start = src.indexOf("router.get('/audit-logs'");
  assert.ok(start >= 0, 'GET /audit-logs route must exist');
  // Grab up to the next router.<verb>( declaration (or EOF) as the route body.
  const rest = src.slice(start + 1);
  const nextRouteRel = rest.search(/\nrouter\.(get|post|put|delete|patch)\(/);
  return nextRouteRel === -1 ? rest : rest.slice(0, nextRouteRel);
}

test('CHARIOT::§9.6::1 — the audit query schema accepts a generic actor filter, not just actorEmail', () => {
  const body = routeBody(adminSrc);
  assert.match(body, /actor:\s*z\.string\(/, 'a generic `actor` filter must be accepted');
  assert.match(body, /actorEmail:\s*z\.string\(\)\.email\(/, 'the existing actorEmail filter must remain');
  assert.match(body, /query\.actorId\s*=\s*actor/, 'the actor filter must map onto the actorId field');
});

test('CHARIOT::§9.6::1 — the response body is streamed via the Mongo cursor, not buffered via .toArray()+res.json', () => {
  const body = routeBody(adminSrc);
  assert.doesNotMatch(
    body,
    /\.toArray\(\)/,
    'the events cursor must not be materialized into an array before responding',
  );
  assert.match(body, /for await\s*\(\s*const event of cursor\s*\)/, 'events must be streamed via cursor iteration');
  assert.match(body, /res\.write\(/, 'the response body must be written incrementally');
});

test('CHARIOT::§9.8.3::4 — the export path reconciles chain length and halts on truncation', () => {
  const body = routeBody(adminSrc);
  assert.match(body, /reconcileChainLength\(/, 'the export path must call reconcileChainLength');
  assert.match(
    body,
    /chariotEmitter\.send\(\s*'audit\.tail_truncation_detected'/,
    'a detected truncation must emit audit.tail_truncation_detected',
  );
  assert.match(body, /severity:\s*'critical'/, 'the truncation alert must be CRITICAL severity');
  assert.match(body, /return;/, 'export must halt (return) after emitting the truncation alert');
});

test('CHARIOT::§9.8.3::4 — reconciliation runs against the FULL unfiltered chain length, not the filtered page count', () => {
  const body = routeBody(adminSrc);
  const reconcileIdx = body.indexOf('reconcileChainLength(');
  const beforeReconcile = body.slice(0, reconcileIdx);
  assert.match(
    beforeReconcile,
    /countDocuments\(\{\s*tenantId\s*\}\)/,
    'currentLength must come from an UNFILTERED per-tenant count computed before reconciliation',
  );
});

test('CHARIOT::§9.8.3::4 — attested-but-unverifiable chains halt export (fail closed) and alert CRITICAL', () => {
  const body = routeBody(adminSrc);
  assert.match(body, /reconciliation\.unverifiable/, 'the export path must check the unverifiable flag');
  assert.match(
    body,
    /chariotEmitter\.send\(\s*'audit\.attestation_unverifiable'/,
    'an unverifiable attestation set must emit audit.attestation_unverifiable',
  );
  const idx = body.indexOf("'audit.attestation_unverifiable'");
  assert.match(body.slice(idx, idx + 1200), /res\.status\(409\)/, 'export must halt with 409 when attestations are unverifiable');
});

test('production logging in the admin routes goes through the project logger, never console.*', () => {
  assert.doesNotMatch(adminSrc, /console\.(error|log|warn|info)\(/, 'no console.* logging in src/iam/routes/admin.ts');
  assert.match(adminSrc, /createLogger\('iam-admin'\)/, 'a module logger must be created');
});
