/**
 * CHARIOT::§18.3 — "Redis unreachable | ControlPlane degrades to
 * in-process; ApprovalQueue degrades to in-memory; sessions fall back to
 * JWT-signature-only revocation (8h max stale window)." (CHARIOT-SPEC.md:1480)
 *
 * Wave-3a gate round 2 (P1): src/iam/services/session.ts's "missing
 * activity key MUST fail closed" rule (verifyToken(), SOC-2 idle-timeout
 * block — comment preserved verbatim in the non-degraded branch below)
 * means every token issued before a Redis outage has no activity record
 * once the in-process shim (empty) is substituted in — so EVERY existing
 * session was rejected, not "falls back to JWT-signature-only revocation"
 * as the clause requires. Fixed via setSessionRedisDegraded() /
 * isSessionRedisDegraded(): while degraded, a missing activity key no
 * longer fail-closes — jwt.verify()'s own signature+exp check (which runs
 * unconditionally, before any Redis access, and rejects on either failure)
 * becomes the only enforcement, exactly as the clause names, bounded by
 * TOKEN_EXPIRY_SECONDS (8h).
 *
 * Failure enumeration (matches the clause's own scenario plus a
 * regression guard for the pre-existing, unchanged non-degraded case):
 * (a) degraded + valid, unexpired token + no activity record -> ACCEPTED;
 * (b) degraded + expired token -> REJECTED (jwt.verify() catches this
 *     before any Redis access — proves the "8h max stale window" bound
 *     holds even in degraded mode: nothing about the degrade extends a
 *     token's life past its own exp);
 * (c) degraded + bad signature (token re-signed with a different secret)
 *     -> REJECTED (same jwt.verify() gate, proves degrade never weakens
 *     signature enforcement);
 * (d) NOT degraded + no activity record -> REJECTED (regression guard —
 *     the pre-existing fail-closed rule is untouched when not degraded);
 * (e) the degrade WARN is emitted exactly once across two consecutive
 *     setSessionRedisDegraded(true) calls (not per verifyToken() call,
 *     not per redundant degrade-state transition);
 * (f) degraded + a per-session revocation marker PRESENT in the local shim
 *     -> still ACCEPTED. Gate-round-3 finding: this is "JWT-signature-only
 *     revocation" per the clause's own words, not "consult whatever the
 *     local shim happens to hold" — see the block comment above the
 *     `if (!isSessionRedisDegraded())` guard in session.ts for the full
 *     reasoning (per-process degrade means a revoke-while-degraded write
 *     is invisible to every OTHER instance behind a load balancer, so
 *     honoring it on THIS instance only produces an inconsistent,
 *     instance-dependent revocation guarantee — worse than a uniform
 *     signature-only fallback);
 * (g) degraded + a STALE user-revocation-version in the local shim (the
 *     token's stamped userVer is behind the shim's current counter) ->
 *     still ACCEPTED, same reasoning as (f);
 * (h) NOT degraded + a per-session revocation marker present -> REJECTED
 *     (regression guard for the same check family as (d), covering the
 *     round-3 fix instead of the round-2 fix).
 *
 * Run (after tsc): node --test dist/iam/services/session.redis-degraded.test.js
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import jwt from 'jsonwebtoken';
import type { RedisClientType } from 'redis';

import {
  setRedisClient,
  setSessionRedisDegraded,
  isSessionRedisDegraded,
  verifyToken,
  revokeSession,
  revokeAllUserSessions,
  TOKEN_EXPIRY_SECONDS,
} from './session.js';
import { createInProcessRedisShim } from '../inProcessRedisShim.js';

const JWT_SECRET = randomBytes(48).toString('base64'); // > 32 chars, not a weak default

function signToken(overrides?: { expiresInSeconds?: number; secret?: string }): { token: string; jti: string } {
  const jti = randomUUID();
  const nowSeconds = Math.floor(Date.now() / 1000);
  const payload = {
    sub: 'user-1',
    tenantId: 'tenant-1',
    userId: 'user-1',
    email: 'a@example.com',
    displayName: 'A',
    groups: [],
    allowedAdapterIds: [],
    adapterIds: [],
    allowedOperations: {},
    isAdmin: false,
    mfaVerified: true,
    jti,
    iat: nowSeconds,
    iatMs: Date.now(),
    userVer: 0,
  };
  const secret = overrides?.secret ?? JWT_SECRET;
  const expiresIn = overrides?.expiresInSeconds ?? TOKEN_EXPIRY_SECONDS;
  const token = jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn });
  return { token, jti };
}

let origEnvSecret: string | undefined;
let shim: RedisClientType;
// Mirrors KEY_SESSION_ACTIVITY in session.ts (module-private): the SOC-2 idle-timeout marker.
const KEY_SESSION_ACTIVITY = 'ent:session:active:';

beforeEach(() => {
  origEnvSecret = process.env.ENTERPRISE_JWT_SECRET;
  process.env.ENTERPRISE_JWT_SECRET = JWT_SECRET;
  shim = createInProcessRedisShim() as unknown as RedisClientType;
  setRedisClient(shim);
  setSessionRedisDegraded(false);
});

afterEach(() => {
  if (origEnvSecret !== undefined) process.env.ENTERPRISE_JWT_SECRET = origEnvSecret;
  else delete process.env.ENTERPRISE_JWT_SECRET;
  setSessionRedisDegraded(false);
});

test('CHARIOT::§18.3 (a): degraded + valid unexpired token + no activity record -> accepted', async () => {
  setSessionRedisDegraded(true, 'test: simulated Redis outage');
  assert.equal(isSessionRedisDegraded(), true);
  const { token } = signToken();
  const result = await verifyToken(token);
  assert.notEqual(result, null);
  assert.equal(result?.tenantId, 'tenant-1');
});

test('CHARIOT::§18.3 (b): degraded + expired token -> rejected', async () => {
  setSessionRedisDegraded(true, 'test: simulated Redis outage');
  const { token } = signToken({ expiresInSeconds: -1 }); // already expired
  const result = await verifyToken(token);
  assert.equal(result, null);
});

test('CHARIOT::§18.3 (c): degraded + bad signature -> rejected', async () => {
  setSessionRedisDegraded(true, 'test: simulated Redis outage');
  const { token } = signToken({ secret: randomBytes(48).toString('base64') }); // signed with a DIFFERENT secret
  const result = await verifyToken(token);
  assert.equal(result, null);
});

test('CHARIOT::§18.3 (d): NOT degraded + no activity record -> rejected (regression guard — unchanged pre-existing fail-closed rule)', async () => {
  setSessionRedisDegraded(false);
  assert.equal(isSessionRedisDegraded(), false);
  const { token } = signToken();
  const result = await verifyToken(token);
  assert.equal(result, null);
});

test('CHARIOT::§18.3 (e): the degrade WARN is emitted exactly once across two consecutive true transitions', () => {
  setSessionRedisDegraded(false); // ensure starting state is false so the first true call IS a transition
  const originalWrite = process.stderr.write.bind(process.stderr);
  const lines: string[] = [];
  process.stderr.write = ((chunk: string | Uint8Array): boolean => {
    lines.push(typeof chunk === 'string' ? chunk : chunk.toString());
    return true;
  }) as typeof process.stderr.write;
  try {
    setSessionRedisDegraded(true, 'first outage');
    setSessionRedisDegraded(true, 'still degraded — redundant call'); // NOT a false->true transition; must not warn again
  } finally {
    process.stderr.write = originalWrite;
  }
  const degradeWarnLines = lines.filter((l) => l.includes('Redis degraded'));
  assert.equal(degradeWarnLines.length, 1, `expected exactly one degrade WARN line, got ${degradeWarnLines.length}: ${JSON.stringify(lines)}`);
});

test('CHARIOT::§18.3 (f): degraded + a per-session revocation marker present in the shim -> still accepted (signature-only, not "consult the shim")', async () => {
  setSessionRedisDegraded(true, 'test: simulated Redis outage');
  const { token, jti } = signToken();
  // Revoke it via the real, public revocation API — this write lands in
  // the SAME in-process shim verifyToken() will read from (single process,
  // single injected client), so if the checks below were merely "skip
  // Redis reads that come back empty" rather than an unconditional skip,
  // this specific case (present, non-empty marker) would still reject.
  await revokeSession(jti);
  const result = await verifyToken(token);
  assert.notEqual(result, null, 'a present revocation marker must NOT be consulted while degraded — signature+exp only');
});

test('CHARIOT::§18.3 (g): degraded + a stale user-revocation-version in the shim -> still accepted', async () => {
  setSessionRedisDegraded(true, 'test: simulated Redis outage');
  // Bumps ent:user-rev:tenant-1:user-1 to 1 in the shim (this test's
  // beforeEach wires a fresh shim, so it starts at 0/unset).
  await revokeAllUserSessions('tenant-1', 'user-1');
  const { token } = signToken(); // signToken() stamps userVer: 0 — now stale relative to the bumped counter
  const result = await verifyToken(token);
  assert.notEqual(result, null, 'a stale user-revocation-version must NOT be consulted while degraded — signature+exp only');
});

test('CHARIOT::§18.3 (h): NOT degraded + a per-session revocation marker present -> rejected (regression guard)', async () => {
  setSessionRedisDegraded(false);
  const { token, jti } = signToken();
  await revokeSession(jti);
  const result = await verifyToken(token);
  assert.equal(result, null);
});

test('CHARIOT::§18.3 (i): degraded + a STALE activity marker present in the shim (older than the idle window) -> still accepted', async () => {
  setSessionRedisDegraded(true, 'test: simulated Redis outage');
  const { token, jti } = signToken();
  // A marker 48h old — far beyond ENTERPRISE_IDLE_TIMEOUT_MINUTES (default 30m).
  // Not degraded, this token would be idle-revoked; degraded, the idle-timeout
  // check is Redis-backed session state and is not consulted (signature+exp only).
  await (shim as unknown as { set(k: string, v: string, o?: unknown): Promise<unknown> }).set(`${KEY_SESSION_ACTIVITY}${jti}`, String(Date.now() - 48 * 3600 * 1000), { EX: 30 * 3600 });
  const result = await verifyToken(token);
  assert.notEqual(result, null, 'a stale activity marker must NOT reject a degraded token — signature+exp only');
});

test('CHARIOT::§18.3 (j): NOT degraded + a STALE activity marker present -> rejected (regression guard — idle timeout unchanged)', async () => {
  setSessionRedisDegraded(false);
  const { token, jti } = signToken();
  await (shim as unknown as { set(k: string, v: string, o?: unknown): Promise<unknown> }).set(`${KEY_SESSION_ACTIVITY}${jti}`, String(Date.now() - 48 * 3600 * 1000), { EX: 30 * 3600 });
  const result = await verifyToken(token);
  assert.equal(result, null);
});
