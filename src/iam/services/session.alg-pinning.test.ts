/**
 * Prove-on-revert for CHARIOT §10.6::1 — "Sessions SHALL use HS256."
 *
 * Defect this catches: `verifySession` called `jwt.verify(token, secret)` with
 * NO `algorithms` option, so jsonwebtoken honoured the `alg` declared in the
 * attacker-supplied token header instead of the one algorithm the system
 * actually signs with (CWE-347, algorithm confusion). Sessions are the primary
 * enterprise auth credential, and this was the ONLY unpinned jwt.verify in the
 * codebase — dpop.ts, id-jag-validator.ts and oauth.ts all already pin.
 *
 * Both sides are now pinned: sign states `algorithm: 'HS256'` rather than
 * relying on the library's string-secret default, so signer and verifier cannot
 * drift apart across a dependency upgrade.
 *
 * Run (after tsc): node --test dist/iam/services/session.alg-pinning.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('./session.js', import.meta.url)), 'utf8');

// tsc preserves comments into the emitted dist/*.js, so a bare
// indexOf('jwt.sign') matches a COMMENT that merely mentions the call and the
// window never reaches the real invocation. Strip comments first and anchor on
// the actual call signature so no comment can satisfy these assertions.
test('§10.6::1: jwt.verify pins the accepted algorithm', () => {
  const code = src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g, '');
  const match = code.match(
    /jwt\.verify\s*\(\s*token\s*,\s*secret\s*,\s*\{[\s\S]{0,200}?algorithms:\s*\[\s*'HS256'\s*\]/,
  );

  assert.ok(
    match,
    "jwt.verify(token, secret, { algorithms: ['HS256'] }) is required",
  );
});

test('§10.6::1: jwt.sign states HS256 explicitly, not by library default', () => {
  const code = src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g, '');
  const match = code.match(
    /jwt\.sign\s*\(\s*payload\s*,\s*secret\s*,\s*\{[\s\S]{0,200}?algorithm:\s*'HS256'/,
  );

  assert.ok(
    match,
    "jwt.sign(payload, secret, { algorithm: 'HS256' }) is required",
  );
});

test('§10.6::1: no asymmetric or none algorithm is accepted for sessions', () => {
  const idx = src.indexOf('jwt.verify');
  const region = src.slice(idx, idx + 200);
  for (const bad of ['RS256', 'ES256', 'none', 'HS384', 'HS512']) {
    assert.ok(
      !region.includes(bad),
      `the session verifier must accept HS256 only; found ${bad}`,
    );
  }
});
