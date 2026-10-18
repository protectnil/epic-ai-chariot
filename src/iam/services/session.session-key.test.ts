/**
 * Prove-on-revert for CHARIOT §3.4::1 — "WHEN enterprise Redis is used the
 * system SHALL maintain ent:session:{jti} (session→user mapping) with a
 * session-length TTL."
 *
 * Spec table, CHARIOT-SPEC.md line 230:
 *   | `ent:session:{jti}` | session TTL | Maps session ID → user ID |
 *
 * Defect this catches: session.ts carried `ent:session:revoked:`,
 * `ent:session:active:` and `ent:session:idjag-subject:` but NO bare
 * `ent:session:{jti}` key — the session→user mapping the spec requires simply
 * did not exist. It is written at issuance with the token's own lifetime
 * (TOKEN_EXPIRY_SECONDS, NOT the 30h used by the §3.4::3 user-sessions set)
 * and deleted on every revocation path so it cannot outlive its session.
 *
 * Behavioral coverage needing a live Redis lives in the infra-gated eval
 * harness; this asserts the key/TTL contract and the delete-on-revoke
 * invariant by source inspection, without Redis.
 *
 * Run (after tsc): node --test dist/iam/services/session.session-key.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { TOKEN_EXPIRY_SECONDS } from './session.js';

const src = readFileSync(fileURLToPath(new URL('./session.js', import.meta.url)), 'utf8');

test('§3.4::1: the bare ent:session: prefix exists and is distinct from the suffixed keys', () => {
  assert.match(
    src,
    /KEY_SESSION\s*=\s*['"]ent:session:['"]/,
    "session.ts must define the bare 'ent:session:' prefix (session→user mapping)",
  );
});

test('§3.4::1: the mapping is written at issuance with the session-length TTL', () => {
  const writes = src
    .split('\n')
    .filter((l) => /\$\{KEY_SESSION\}/.test(l) && /\.set\(/.test(l));
  assert.equal(writes.length, 1, `expected exactly one ent:session:{jti} write; found ${writes.length}`);
  const [write] = writes;
  assert.ok(
    write.includes('TOKEN_EXPIRY_SECONDS'),
    `the mapping must use the session-length TTL constant: ${write.trim()}`,
  );
  // Must NOT reuse the 30h ent:user-sessions TTL (§3.4::3) — that would let the
  // mapping outlive the 8h session it describes.
  assert.ok(
    !/EX:\s*30\s*\*\s*3600/.test(write),
    `the mapping must not use the 30h user-sessions TTL: ${write.trim()}`,
  );
});

test('§3.4::1: session TTL constant is the token lifetime (8h), not 30h', () => {
  assert.equal(TOKEN_EXPIRY_SECONDS, 8 * 3600);
  assert.notEqual(TOKEN_EXPIRY_SECONDS, 30 * 3600);
});

test('§3.4::1: the mapping is deleted on every revocation path', () => {
  const deletes = src
    .split('\n')
    .filter((l) => /\$\{KEY_SESSION\}/.test(l) && /\.del\(/.test(l));
  // revokeSession, revokeAllUserSessions pipeline, missing-activity branch,
  // idle-timeout branch.
  assert.ok(
    deletes.length >= 4,
    `the session→user mapping must be deleted on every revocation path; found ${deletes.length}`,
  );
});
