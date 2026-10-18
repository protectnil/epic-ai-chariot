/**
 * CHARIOT::§8.2::3 — "WHEN an MFA-required tool is dispatched the
 * generator instance for that turn SHALL be bound to the MFA assertion,
 * and a revoked MFA SHALL invalidate the generator without affecting the
 * rest of the agent state."
 *
 * Unit-level coverage of the new assertion-epoch primitives themselves
 * (mintMfaAssertion/revokeMfaAssertion/isMfaAssertionValid), backed by the
 * in-process Redis shim (session.ts's own already-blessed Redis-absent
 * test double — see session.redis-degraded.test.ts for the precedent of
 * testing degraded-mode behavior without a live Redis). Orchestrator-level
 * integration (bind-on-dispatch, invalidation-before-synthesis, isolation
 * across turns) is covered separately in
 * Orchestrator.mfa-generator-invalidation.test.ts.
 *
 * Run (after tsc):
 *   node --test dist/iam/services/mfa.assertion-epoch.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { RedisClientType } from 'redis';

import { mintMfaAssertion, revokeMfaAssertion, isMfaAssertionValid } from './mfa.js';
import { setRedisClient, setSessionRedisDegraded } from './session.js';
import { createInProcessRedisShim } from '../inProcessRedisShim.js';

test('§8.2::3: a freshly minted assertion is valid immediately (never pre-invalidated)', async () => {
  setRedisClient(createInProcessRedisShim() as unknown as RedisClientType);

  const assertion = await mintMfaAssertion();
  const valid = await isMfaAssertionValid(assertion.assertionId, assertion.epochAtBindMs);

  assert.equal(valid, true, 'a bind is never pre-invalidated by a missing/stale key');
});

test('§8.2::3: revokeMfaAssertion invalidates that assertion', async () => {
  setRedisClient(createInProcessRedisShim() as unknown as RedisClientType);

  const assertion = await mintMfaAssertion();
  assert.equal(await isMfaAssertionValid(assertion.assertionId, assertion.epochAtBindMs), true);

  await revokeMfaAssertion(assertion.assertionId);

  assert.equal(await isMfaAssertionValid(assertion.assertionId, assertion.epochAtBindMs), false, 'revoked assertion must be invalid');
});

test('§8.2::3: ISOLATION — revoking one assertion never invalidates a different assertion', async () => {
  setRedisClient(createInProcessRedisShim() as unknown as RedisClientType);

  const a = await mintMfaAssertion();
  const b = await mintMfaAssertion();

  await revokeMfaAssertion(a.assertionId);

  assert.equal(await isMfaAssertionValid(a.assertionId, a.epochAtBindMs), false, 'A is revoked');
  assert.equal(await isMfaAssertionValid(b.assertionId, b.epochAtBindMs), true, 'B is untouched by A\'s revocation — "without affecting the rest of the agent state"');
});

test('§8.2::3: a never-minted assertionId is INVALID (fail-closed on missing key) — NOT the tenant/user epoch "missing = never revoked" convention', async () => {
  setRedisClient(createInProcessRedisShim() as unknown as RedisClientType);

  const valid = await isMfaAssertionValid('never-minted-id', Date.now());
  assert.equal(valid, false, 'a security-scoped revocation channel must fail closed on an anomalous missing key, unlike session.ts tenant/user epochs');
});

test('§8.2::3: degraded Redis mode mirrors session.ts posture — checks are skipped (return true), not fail-closed', async () => {
  setRedisClient(createInProcessRedisShim() as unknown as RedisClientType);
  setSessionRedisDegraded(true, 'test');

  try {
    // Even a never-minted id passes while degraded — same posture as the
    // rest of session-revocation during a documented Redis outage.
    const valid = await isMfaAssertionValid('never-minted-id', Date.now());
    assert.equal(valid, true, 'degraded mode must not introduce a stricter posture than the rest of session-revocation');
  } finally {
    setSessionRedisDegraded(false);
  }
});
