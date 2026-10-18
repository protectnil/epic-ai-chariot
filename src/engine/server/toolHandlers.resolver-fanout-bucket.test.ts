/**
 * Prove-on-revert for resolver fan-out rate-bucket isolation — the internal
 * EntityResolver fan-out uses a SEPARATE per-tenant rate bucket from the
 * user-facing bucket.
 *
 * toolHandlers.ts:1503-1516 (handleCallImpl, per-tenant rate limit):
 *
 *   const rateLimitKey = context?.internalResolverFanout
 *     ? `__resolver_fanout__::${tenantId}`
 *     : tenantId;
 *   const rate = consumeTenantToken(rateLimitKey, callsPerMinute);
 *
 * Before this fix, every call (fan-out or user-facing) was charged to the
 * same `tenantId` bucket, so a single EntityResolver fan-out (many probes
 * under the caller's tenant) could drain the tenant's USER-FACING budget and
 * self-starve subsequent real calls for ~60s.
 *
 * The invariant locked in here: exhausting the user-facing bucket (calls
 * WITHOUT context.internalResolverFanout) must NOT block a fan-out call
 * (context.internalResolverFanout=true) for the SAME tenant, and exhausting
 * the fan-out bucket must NOT block the user-facing bucket — they are
 * independent buckets keyed distinctly (`tenantId` vs.
 * `__resolver_fanout__::${tenantId}`).
 *
 * The target tool has no executable transport, so calls that pass the rate
 * gate fail later for an unrelated reason (no transport) — this isolates
 * the assertion to "did RATE_LIMIT_EXCEEDED fire", which is exactly the
 * fix's contract; the tests do not depend on live adapters, Mongo, or Redis.
 *
 * Run (after tsc): node --test dist/engine/server/toolHandlers.resolver-fanout-bucket.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { handleCall, __resetTenantBuckets } from './toolHandlers.js';
import type { CallContext } from './toolHandlers.js';
import type { ChariotState } from './ChariotState.js';
import { CHARIOT_ERROR_CODES } from '../types/index.js';

function makeStateWithEcho(adapterId: string): ChariotState {
  const adapter = { id: adapterId, name: adapterId, type: 'rest', category: 'test' };
  return {
    allAdapters: [adapter],
    adapterById: new Map([[adapterId, adapter]]),
    configuredAdapterIds: new Set([adapterId]),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [adapter],
    loadedAt: new Date(),
  } as unknown as ChariotState;
}

function codeOf(result: { content: string }): unknown {
  return (JSON.parse(result.content) as { code?: unknown }).code;
}

test('resolver-fanout: exhausting the user-facing bucket does not block a resolver fan-out call for the same tenant', async () => {
  __resetTenantBuckets();
  const state = makeStateWithEcho('echo');
  const tenantId = 'tenant-fanout-1';
  const callsPerMinute = 2;
  const userCtx: CallContext = { tenantId, callsPerMinute, localMode: true };

  for (let i = 0; i < callsPerMinute; i++) {
    const r = await handleCall({ adapter: 'echo', tool: 'noop', args: {} }, state, userCtx);
    assert.notEqual(codeOf(r), CHARIOT_ERROR_CODES.RATE_LIMIT_EXCEEDED,
      `user-facing call ${i + 1}/${callsPerMinute} must not be rate-limited, got ${r.content}`);
  }
  const userBlocked = await handleCall({ adapter: 'echo', tool: 'noop', args: {} }, state, userCtx);
  assert.equal(codeOf(userBlocked), CHARIOT_ERROR_CODES.RATE_LIMIT_EXCEEDED,
    `user-facing bucket must be exhausted, got ${userBlocked.content}`);

  // Same tenant, fan-out bucket: must NOT be rate-limited despite the
  // user-facing bucket above being fully drained.
  const fanoutCtx: CallContext = { tenantId, callsPerMinute, localMode: true, internalResolverFanout: true };
  const fanoutResult = await handleCall({ adapter: 'echo', tool: 'noop', args: {} }, state, fanoutCtx);
  assert.notEqual(codeOf(fanoutResult), CHARIOT_ERROR_CODES.RATE_LIMIT_EXCEEDED,
    `fan-out bucket must be independent of the exhausted user-facing bucket, got ${fanoutResult.content}`);
});

test('resolver-fanout: exhausting the resolver fan-out bucket does not block the user-facing bucket for the same tenant', async () => {
  __resetTenantBuckets();
  const state = makeStateWithEcho('echo');
  const tenantId = 'tenant-fanout-2';
  const callsPerMinute = 2;
  const fanoutCtx: CallContext = { tenantId, callsPerMinute, localMode: true, internalResolverFanout: true };

  for (let i = 0; i < callsPerMinute; i++) {
    const r = await handleCall({ adapter: 'echo', tool: 'noop', args: {} }, state, fanoutCtx);
    assert.notEqual(codeOf(r), CHARIOT_ERROR_CODES.RATE_LIMIT_EXCEEDED,
      `fan-out call ${i + 1}/${callsPerMinute} must not be rate-limited, got ${r.content}`);
  }
  const fanoutBlocked = await handleCall({ adapter: 'echo', tool: 'noop', args: {} }, state, fanoutCtx);
  assert.equal(codeOf(fanoutBlocked), CHARIOT_ERROR_CODES.RATE_LIMIT_EXCEEDED,
    `fan-out bucket must be exhausted, got ${fanoutBlocked.content}`);

  const userCtx: CallContext = { tenantId, callsPerMinute, localMode: true };
  const userResult = await handleCall({ adapter: 'echo', tool: 'noop', args: {} }, state, userCtx);
  assert.notEqual(codeOf(userResult), CHARIOT_ERROR_CODES.RATE_LIMIT_EXCEEDED,
    `user-facing bucket must be independent of the exhausted fan-out bucket, got ${userResult.content}`);
});

test('resolver-fanout: fan-out calls are keyed per-tenant, not shared across tenants', async () => {
  __resetTenantBuckets();
  const state = makeStateWithEcho('echo');
  const callsPerMinute = 1;
  const fanoutCtxA: CallContext = { tenantId: 'tenant-fanout-A', callsPerMinute, localMode: true, internalResolverFanout: true };
  const fanoutCtxB: CallContext = { tenantId: 'tenant-fanout-B', callsPerMinute, localMode: true, internalResolverFanout: true };

  const aFirst = await handleCall({ adapter: 'echo', tool: 'noop', args: {} }, state, fanoutCtxA);
  assert.notEqual(codeOf(aFirst), CHARIOT_ERROR_CODES.RATE_LIMIT_EXCEEDED);
  const aBlocked = await handleCall({ adapter: 'echo', tool: 'noop', args: {} }, state, fanoutCtxA);
  assert.equal(codeOf(aBlocked), CHARIOT_ERROR_CODES.RATE_LIMIT_EXCEEDED,
    `tenant A's fan-out bucket must be exhausted, got ${aBlocked.content}`);

  const bFirst = await handleCall({ adapter: 'echo', tool: 'noop', args: {} }, state, fanoutCtxB);
  assert.notEqual(codeOf(bFirst), CHARIOT_ERROR_CODES.RATE_LIMIT_EXCEEDED,
    `tenant B's fan-out bucket must not inherit tenant A's exhaustion, got ${bFirst.content}`);
});
