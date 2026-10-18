/**
 * Prove-on-revert for CHARIOT §3.4::2 — "WHEN enterprise Redis is used the system
 * SHALL maintain ent:session:revoked:{jti} as a revocation marker with a 24h TTL."
 *
 * Defect this catches: every `ent:session:revoked:{jti}` write used `EX 30*3600`
 * (30h), conflating the revocation marker with the §3.4::3 `ent:user-sessions`
 * set (which is legitimately 30h). The marker only needs to outlive the 8h
 * access token; the spec pins it at 24h. Fixed to a single named constant.
 *
 * (Behavioral revoke-path coverage that needs a live Redis lives in the
 * infra-gated security-fix eval harness; this asserts the TTL contract and that
 * no revoked-marker write regresses to a 30h literal — both without Redis.)
 *
 * Run (after tsc): node --test dist/iam/services/session.revocation-ttl.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { SESSION_REVOKED_TTL_SECONDS } from './session.js';

test('§3.4::2: the revoked-marker TTL constant is exactly 24h', () => {
  assert.equal(SESSION_REVOKED_TTL_SECONDS, 24 * 3600, 'ent:session:revoked:{jti} must carry a 24h TTL');
  assert.equal(SESSION_REVOKED_TTL_SECONDS, 86400);
  assert.notEqual(
    SESSION_REVOKED_TTL_SECONDS,
    30 * 3600,
    'must not reuse the 30h ent:user-sessions set TTL (§3.4::3) for the revocation marker',
  );
});

test('§3.4::2: every ent:session:revoked write uses the 24h constant, never a 30h literal', () => {
  // Inspect the compiled source of session.ts (this test sits beside it in dist).
  const srcPath = fileURLToPath(new URL('./session.js', import.meta.url));
  const src = readFileSync(srcPath, 'utf8');
  const revokedWrites = src
    .split('\n')
    .filter((line) => line.includes('KEY_SESSION_REVOKED') && /\.set\(/.test(line));
  assert.ok(revokedWrites.length >= 3, `expected the revoked-marker to be written in multiple paths; found ${revokedWrites.length}`);
  for (const line of revokedWrites) {
    assert.ok(
      line.includes('SESSION_REVOKED_TTL_SECONDS'),
      `a revoked-marker write must use the 24h constant, not a hardcoded TTL: ${line.trim()}`,
    );
    assert.ok(!/EX:\s*30\s*\*\s*3600/.test(line), `a revoked-marker write must not use the 30h literal: ${line.trim()}`);
  }
});
