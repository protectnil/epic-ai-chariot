/**
 * Prove-on-revert for CHARIOT §10.5 (rulings item 106, W3839-B5c) —
 * populate path for the confidential-client `clientId`/`clientSecret`
 * fields `POST /:id/connect` accepts.
 *
 * Ruling text: "extend POST /:id/connect ... with optional body fields
 * clientId and clientSecret (validated: strings, length-bounded,
 * control-char rejected like the existing credential fields; both-or-
 * neither), written through the same encryptFields path so clientSecret
 * never lands in plaintext; the connect response never echoes the
 * secret; audit event carries only the presence flag."
 *
 * Defect this catches: before this unit, `clientId`/`clientSecret` had a
 * type declaration (B5b, `AdapterCredentialDocument.clientId` /
 * credentials.ts's decrypt-side read) but no route accepted them — no
 * live credential could ever carry confidential-client auth.
 *
 * `connectAdapterSchemaWithClientAuth` (the zod validator) is exported and
 * pure — genuinely behaviorally testable with real inputs, no Mongo/crypto
 * needed. The route HANDLER's Mongo-write behavior (encryption, audit
 * detail shape, response shape) follows this file's own established
 * precedent for that class of dependency (see
 * adapters.credential-owner.test.ts: "Behavioral route coverage
 * (auth+Mongo) lives in the infra-gated harness; this asserts ... via
 * source") — source-inspection for those specific assertions.
 *
 * Run (after tsc): node --test dist/iam/routes/adapters.client-auth.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { connectAdapterSchemaWithClientAuth as schema } from './adapters.js';

const VALID_BASE = { apiKey: 'sf-access-token-abc123' };

// ── Schema validation (real behavioral tests) ────────────────────────────

test('rulings item 106: apiKey alone (no clientId/clientSecret) still validates — existing connect behavior unchanged', () => {
  const result = schema.safeParse(VALID_BASE);
  assert.equal(result.success, true, JSON.stringify(result.success ? null : result.error.issues));
});

test('rulings item 106: apiKey + apiSecret + credentialType (pre-existing shape) still validates unchanged', () => {
  const result = schema.safeParse({ ...VALID_BASE, apiSecret: 'refresh-token-xyz', credentialType: 'oauth2' });
  assert.equal(result.success, true, JSON.stringify(result.success ? null : result.error.issues));
});

test('rulings item 106: BOTH clientId and clientSecret present -> accepted', () => {
  const result = schema.safeParse({ ...VALID_BASE, clientId: 'my-vendor-client-id', clientSecret: 'my-vendor-client-secret' });
  assert.equal(result.success, true, JSON.stringify(result.success ? null : result.error.issues));
  if (result.success) {
    assert.equal(result.data.clientId, 'my-vendor-client-id');
    assert.equal(result.data.clientSecret, 'my-vendor-client-secret');
  }
});

test('rulings item 106: clientId WITHOUT clientSecret -> rejected (both-or-neither)', () => {
  const result = schema.safeParse({ ...VALID_BASE, clientId: 'only-the-id' });
  assert.equal(result.success, false);
  if (!result.success) {
    assert.match(result.error.issues.map((i) => i.message).join('; '), /both.*provided.*omitted|clientId.*clientSecret/i);
  }
});

test('rulings item 106: clientSecret WITHOUT clientId -> rejected (both-or-neither)', () => {
  const result = schema.safeParse({ ...VALID_BASE, clientSecret: 'only-the-secret' });
  assert.equal(result.success, false);
});

test('rulings item 106: NEITHER clientId nor clientSecret -> accepted (both optional, "neither" is a valid state)', () => {
  const result = schema.safeParse(VALID_BASE);
  assert.equal(result.success, true);
});

test('rulings item 106: an empty-string clientId is rejected (min(1), same bound as apiKey/apiSecret)', () => {
  const result = schema.safeParse({ ...VALID_BASE, clientId: '', clientSecret: 'sec' });
  assert.equal(result.success, false);
});

test('rulings item 106: a clientSecret over 4096 chars is rejected (same bound as apiKey/apiSecret)', () => {
  const result = schema.safeParse({ ...VALID_BASE, clientId: 'id', clientSecret: 'x'.repeat(4097) });
  assert.equal(result.success, false);
});

test('rulings item 106: a control character (e.g. CRLF) in clientId is rejected — must never reach an HTTP Basic Authorization header unsanitized', () => {
  const result = schema.safeParse({ ...VALID_BASE, clientId: 'id\r\nX-Injected: evil', clientSecret: 'sec' });
  assert.equal(result.success, false);
  if (!result.success) {
    assert.match(result.error.issues.map((i) => i.message).join('; '), /control character/i);
  }
});

test('rulings item 106: a control character (e.g. NUL byte) in clientSecret is rejected', () => {
  const result = schema.safeParse({ ...VALID_BASE, clientId: 'id', clientSecret: 'sec\x00ret' });
  assert.equal(result.success, false);
  if (!result.success) {
    assert.match(result.error.issues.map((i) => i.message).join('; '), /control character/i);
  }
});

test('rulings item 106: a legitimate clientId/clientSecret containing ordinary punctuation is NOT rejected (control-char check is not over-broad)', () => {
  const result = schema.safeParse({ ...VALID_BASE, clientId: 'abc-123_XYZ.def', clientSecret: 'p@ssw0rd!$%^&*()' });
  assert.equal(result.success, true, JSON.stringify(result.success ? null : result.error.issues));
});

// ── Route wiring (source inspection — Mongo/crypto-bound, per this file's ─
// established precedent, see adapters.credential-owner.test.ts) ──────────

const src = readFileSync(fileURLToPath(new URL('./adapters.js', import.meta.url)), 'utf8');

function connectRouteBody(): string {
  const start = src.indexOf("router.post('/:id/connect'");
  assert.ok(start >= 0, 'expected the POST /:id/connect route');
  const end = src.indexOf("router.delete('/:id/disconnect'", start);
  assert.ok(end > start, 'expected the route to end before DELETE /:id/disconnect');
  return src.slice(start, end);
}

test('rulings item 106: the per-user connect route uses the client-auth-extended schema', () => {
  const body = connectRouteBody();
  assert.match(body, /connectAdapterSchemaWithClientAuth\.safeParse/, 'POST /:id/connect must validate against the extended schema, not the base connectAdapterSchema');
});

test('rulings item 106: clientSecret is encrypted via the SAME encryptFields call as apiKey/apiSecret (one blob, never a separate plaintext field)', () => {
  const body = connectRouteBody();
  // Match against COMPILED JS (this reads adapters.js, per the file-level
  // doc comment) — TypeScript's `: Record<string, string | undefined>`
  // type annotation is erased by tsc, so the regex must not require it.
  const fieldsMatch = body.match(/const fields\s*=\s*\{[^}]*\}/);
  assert.ok(fieldsMatch, 'expected the fields object passed to encryptFields');
  assert.match(fieldsMatch![0], /apiKey/, 'fields object must still include apiKey');
  assert.match(fieldsMatch![0], /clientSecret/, 'fields object must include clientSecret — encrypted in the same call');
  // No separate $set of a plaintext clientSecret anywhere in this route.
  const setBlocks = body.match(/\$set:\s*\{[^}]*\}|doc = \{[\s\S]*?\};/g) ?? [];
  for (const block of setBlocks) {
    // "doc = {...}" may legitimately reference `clientId` (plain field);
    // it must NEVER reference `clientSecret`.
    assert.doesNotMatch(block, /\bclientSecret\s*:/, `clientSecret must never appear as a plaintext key in a Mongo write block: ${block.slice(0, 200)}`);
  }
});

test('rulings item 106: a reconnect that omits clientId explicitly $unsets any prior stale clientId (not just skips setting it)', () => {
  const body = connectRouteBody();
  assert.match(body, /clientId !== undefined[\s\S]{0,60}\$set:\s*\{\s*\.\.\.doc,\s*clientId\s*\}/, 'when clientId IS provided, it must be $set alongside the rest of the document');
  assert.match(body, /\$unset:\s*\{\s*clientId:\s*['"]{2}\s*\}/, 'when clientId is NOT provided, the update must $unset any prior clientId — otherwise a stale client_id could survive paired with a re-encrypted blob that no longer carries a matching clientSecret, a silently-broken confidential-client credential');
});

test('rulings item 106: the response never echoes clientId, clientSecret, apiKey, or apiSecret', () => {
  const body = connectRouteBody();
  const responseMatch = body.match(/res\.status\(201\)\.json\(\{[^}]*\}\)/);
  assert.ok(responseMatch, 'expected the 201 response');
  const response = responseMatch![0];
  for (const secretField of ['clientId', 'clientSecret', 'apiKey', 'apiSecret']) {
    assert.doesNotMatch(response, new RegExp(`\\b${secretField}\\b`), `the connect response must not echo ${secretField}`);
  }
});

test('rulings item 106: the audit event carries only a hasClientAuth presence flag, never clientId or clientSecret', () => {
  const body = connectRouteBody();
  const auditMatch = body.match(/audit\.log\([\s\S]*?\}\);/);
  assert.ok(auditMatch, 'expected an audit.log call in the connect route');
  const auditCall = auditMatch![0];
  assert.match(auditCall, /hasClientAuth:\s*clientId\s*!==\s*undefined/, 'the audit detail must carry a boolean presence flag derived from clientId, not the values themselves');
  // Check the ACTUAL detail payload only, not the whole call span — tsc
  // preserves comments in compiled output, and the explanatory comment
  // directly above this call legitimately discusses "clientId or
  // clientSecret" in prose; asserting against the whole call would false-
  // positive on that comment rather than on the real audit payload.
  const detailMatch = auditCall.match(/detail:\s*\{[^}]*\}/);
  assert.ok(detailMatch, 'expected a detail: {...} object in the audit.log call');
  assert.doesNotMatch(detailMatch![0], /\bclientSecret\b/, 'the audit detail payload must never reference clientSecret at all');
  // `clientId` legitimately appears once, inside the `hasClientAuth:
  // clientId !== undefined` presence-check expression (asserted above) —
  // that is deriving a boolean, not leaking the value. It must not appear
  // a SECOND time (which would mean the raw clientId value was also
  // included as its own key, e.g. `clientId,` alongside hasClientAuth).
  const clientIdOccurrences = (detailMatch![0].match(/\bclientId\b/g) ?? []).length;
  assert.equal(clientIdOccurrences, 1, `clientId must appear exactly once (inside the hasClientAuth presence check), found ${clientIdOccurrences} in: ${detailMatch![0]}`);
});

test('rulings item 106: the admin shared-connect route is UNCHANGED — still uses the base schema, no clientId/clientSecret wiring', () => {
  // The bare path string "/admin/:id/connect-shared" appears TWICE: once
  // in this file's header doc comment (the route listing near the top),
  // and once in the actual `router.post('/admin/:id/connect-shared', ...)`
  // registration — indexOf() without anchoring to the registration itself
  // finds the comment first and over-captures from there through most of
  // the rest of the file. Anchor to the literal registration call instead.
  const sharedStart = src.indexOf("router.post('/admin/:id/connect-shared'");
  assert.ok(sharedStart >= 0, 'expected the router.post(...) registration for /admin/:id/connect-shared');
  const sharedBody = src.slice(sharedStart, src.indexOf('router.delete', sharedStart) === -1 ? src.length : src.indexOf('router.delete', sharedStart));
  assert.doesNotMatch(sharedBody, /connectAdapterSchemaWithClientAuth/, 'the shared-connect route must keep using the base connectAdapterSchema — this unit was scoped to /:id/connect only, not /admin/:id/connect-shared');
});
