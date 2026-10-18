/**
 * CHARIOT::§18.2::2 — "Enterprise mode ... optionally uses Redis (in-process
 * fallback if absent)." (CHARIOT-SPEC.md:1467-1469)
 *
 * CHARIOT::§18.3::4 — "Redis unreachable | ControlPlane degrades to
 * in-process; ApprovalQueue degrades to in-memory; sessions fall back to
 * JWT-signature-only revocation (8h max stale window)." (CHARIOT-SPEC.md:1480)
 *
 * Wave-3a gate finding (P1-1): src/iam/bootstrap.ts and
 * src/engine/bin/setup.ts each threw on a REDIS_URL that was configured but
 * unreachable at boot, refusing to bind /mcp / start enterprise mode
 * entirely — the clause says "degrades", not "fails closed", and does not
 * carve out "configured" as harder than "unset". Both call sites now share
 * resolveEnterpriseRedisClient() (this module), so proving its behavior
 * here proves both call sites by construction.
 *
 * Failure enumeration:
 * (a) redisUrl undefined -> in-process shim, no warn call;
 * (b) redisUrl empty string -> in-process shim, no warn call (same as
 *     unset — trims to empty, matches bootstrap.ts's own `redisUrl.trim()
 *     !== ''` gate);
 * (c) redisUrl pointing at a port nothing listens on (ECONNREFUSED) ->
 *     degrades to in-process shim WITHIN A BOUNDED TIME (proves the fix for
 *     the node-redis default reconnectStrategy hang found while
 *     implementing this: node-redis v4's default reconnectStrategy retries
 *     the INITIAL connect() indefinitely against a refusing port unless
 *     disabled — verified live against 127.0.0.1:1 before this fix: connect()
 *     did not settle within an 8s timeout budget; this test bounds it to
 *     well under that). The client's 'error' event AND the connect()
 *     rejection both fire on ECONNREFUSED (node-redis emits both), so
 *     warn() is called at least once (once from the catch-block degrade
 *     message, optionally once from the runtime 'error' relay) — never
 *     zero times, and the degrade message specifically appears exactly
 *     once. No warn() call's message contains the raw redisUrl;
 * (d) redisUrl unreachable, EVERY warn() call's payload/message carries
 *     only the REDACTED form when the URL contains userinfo (credentials
 *     never logged raw, including from the 'error' event relay).
 *
 * Run (after tsc): node --test dist/iam/resolveEnterpriseRedis.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:net';

import { resolveEnterpriseRedisClient } from './resolveEnterpriseRedis.js';

test('CHARIOT::§18.2::2 (a): redisUrl undefined -> in-process shim, no warn', async () => {
  const warnCalls: Array<[string, Record<string, unknown> | undefined]> = [];
  const { redisMode, degraded } = await resolveEnterpriseRedisClient(undefined, (m, d) => warnCalls.push([m, d]));
  assert.equal(redisMode, 'in-process-shim');
  assert.equal(degraded, false, 'REDIS_URL unset is the documented default, not a degrade');
  assert.equal(warnCalls.length, 0);
});

test('CHARIOT::§18.2::2 (b): redisUrl empty string -> in-process shim, no warn', async () => {
  const warnCalls: Array<[string, Record<string, unknown> | undefined]> = [];
  const { redisMode, degraded } = await resolveEnterpriseRedisClient('', (m, d) => warnCalls.push([m, d]));
  assert.equal(redisMode, 'in-process-shim');
  assert.equal(degraded, false, 'empty REDIS_URL is treated the same as unset, not a degrade');
  assert.equal(warnCalls.length, 0);
});

test('CHARIOT::§18.3::4 (c): unreachable REDIS_URL degrades to in-process shim within a bounded time, warns exactly once, without hanging', async () => {
  // A TCP listener bound then immediately closed frees a real ephemeral
  // port that nothing is listening on — ECONNREFUSED, not a black hole.
  const probe: Server = createServer();
  const port: number = await new Promise((resolve) => {
    probe.listen(0, '127.0.0.1', () => {
      const addr = probe.address();
      resolve(typeof addr === 'object' && addr ? addr.port : 0);
    });
  });
  await new Promise<void>((resolve) => probe.close(() => resolve()));

  const warnCalls: Array<[string, Record<string, unknown> | undefined]> = [];
  const start = Date.now();
  const { redisMode, degraded } = await resolveEnterpriseRedisClient(
    `redis://127.0.0.1:${port}`,
    (m, d) => warnCalls.push([m, d]),
  );
  const elapsedMs = Date.now() - start;

  assert.equal(redisMode, 'in-process-shim');
  assert.equal(degraded, true, 'a configured-but-unreachable REDIS_URL must report degraded:true — this is exactly what session.ts\'s setSessionRedisDegraded() gates on');
  // Generous bound (node-redis's connectTimeout default is 5000ms; an
  // ECONNREFUSED settles in single-digit ms) — proves this resolves, it
  // does not retry indefinitely per the reconnectStrategy:false fix.
  assert.ok(elapsedMs < 4000, `expected a bounded failure, took ${elapsedMs}ms`);
  assert.ok(warnCalls.length >= 1, `expected at least one warn() call, got ${warnCalls.length}`);
  const degradeCalls = warnCalls.filter(([m]) => /Redis unreachable at startup/.test(m));
  assert.equal(degradeCalls.length, 1, `expected exactly one degrade-message warn() call, got ${degradeCalls.length} (all calls: ${JSON.stringify(warnCalls)})`);
  for (const [message, data] of warnCalls) {
    assert.ok(!message.includes('127.0.0.1'), `warn message should reference the client only via the redacted redisUrl field, not embed a raw host string: ${message}`);
    void data;
  }
});

test('CHARIOT::§18.3::4 (d): warn() never receives the raw redisUrl — only the redacted form', async () => {
  const probe: Server = createServer();
  const port: number = await new Promise((resolve) => {
    probe.listen(0, '127.0.0.1', () => {
      const addr = probe.address();
      resolve(typeof addr === 'object' && addr ? addr.port : 0);
    });
  });
  await new Promise<void>((resolve) => probe.close(() => resolve()));

  const rawUrl = `redis://user:s3cr3t-password@127.0.0.1:${port}`;
  const warnCalls: Array<[string, Record<string, unknown> | undefined]> = [];
  await resolveEnterpriseRedisClient(rawUrl, (m, d) => warnCalls.push([m, d]));

  assert.ok(warnCalls.length >= 1);
  for (const [message, data] of warnCalls) {
    const payload = message + JSON.stringify(data ?? {});
    assert.ok(!payload.includes('s3cr3t-password'), `warn() call leaked the password: ${payload}`);
  }
  const degradeCall = warnCalls.find(([m]) => /Redis unreachable at startup/.test(m));
  assert.ok(degradeCall, 'expected the degrade-message warn() call');
  const degradePayload = JSON.stringify(degradeCall![1]);
  // rulings item 126 (W-IAM-REDACT): redactConnectionString() builds the
  // output manually (not via `new URL(...).toString()`), so the literal
  // '<redacted>' marker is never percent-encoded — still accept the
  // percent-encoded form too, in case a future redaction implementation
  // round-trips through URL serialization again.
  assert.ok(
    degradePayload.includes('<redacted>') || degradePayload.includes('%3Credacted%3E'),
    `degrade warn() payload did not carry the redacted marker: ${degradePayload}`,
  );
});
