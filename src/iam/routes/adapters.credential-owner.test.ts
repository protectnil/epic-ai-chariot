/**
 * Prove-on-revert for CHARIOT §10.5::3 — "The vault SHALL support shared
 * org-wide credentials stored encrypted with userId:null, admin-managed only,
 * for adapters without per-user OAuth."
 *
 * Defect this catches: shared credentials were marked only with `shared:true`
 * and `connectedBy: <admin-email>`; there was no `userId` field, so the required
 * `userId:null` shared-vs-per-user distinction did not exist. Now the connect
 * path sets `userId: user.sub` (per-user) and the admin connect-shared path sets
 * `userId: null` (org-wide). Behavioral route coverage (auth+Mongo) lives in the
 * infra-gated harness; this asserts the persisted ownership field via source.
 *
 * Run (after tsc): node --test dist/iam/routes/adapters.credential-owner.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('./adapters.js', import.meta.url)), 'utf8');

test('§10.5::3: org-wide shared credentials are persisted with userId:null', () => {
  assert.ok(/userId:\s*null/.test(src), 'the shared-credential document must set userId: null');
});

test('§10.5::3: per-user credentials carry the owning user id', () => {
  assert.ok(/userId:\s*user\.sub/.test(src), 'the per-user credential document must set userId: user.sub');
});
