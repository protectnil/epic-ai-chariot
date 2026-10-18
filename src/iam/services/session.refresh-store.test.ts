/**
 * Prove-on-revert for CHARIOT §10.6::6 — "Refresh tokens SHALL be server-side
 * state in Mongo (iam_refresh_tokens), single-use, each refresh issuing a new
 * token and invalidating the previous."
 *
 * Defect this catches: refresh tokens were stored in Redis (`ent:refresh:` +
 * `ent:user-refresh:` index), consumed via `getDel`. The spec requires the
 * durable Mongo `iam_refresh_tokens` store. This asserts the store + the atomic
 * single-use consume by inspecting the compiled module (behavioral coverage
 * that needs a live Mongo lives in the infra-gated security-fix eval harness).
 *
 * Run (after tsc): node --test dist/iam/services/session.refresh-store.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('./session.js', import.meta.url)), 'utf8');

test('§10.6::6: refresh tokens are stored in the Mongo iam_refresh_tokens collection', () => {
  assert.ok(src.includes('iam_refresh_tokens'), 'refresh tokens must be persisted in iam_refresh_tokens');
});

test('§10.6::6: single-use consume is an atomic findOneAndDelete', () => {
  assert.ok(src.includes('findOneAndDelete'), 'consume must atomically delete-on-read for single use');
});

test('§10.6::6: the Redis refresh-token store is fully removed (no getDel / ent:refresh keys)', () => {
  assert.ok(!src.includes('getDel'), 'the Redis getDel refresh path must be gone');
  assert.ok(!src.includes('ent:refresh:'), 'the Redis ent:refresh: key must be gone');
  assert.ok(!src.includes('ent:user-refresh:'), 'the Redis per-user refresh index must be gone');
});
