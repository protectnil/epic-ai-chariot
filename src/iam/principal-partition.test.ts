/**
 * @epicai/chariot — Principal-kind partition enforcement test (gap #3, Wiz 2)
 *
 * Proves the human/agent/service partition is ENFORCED, not just modeled:
 *
 *   1. An agent (and a service) principal is DENIED an adapter granted
 *      only via a mapping marked `principalScope: ['human']`, at the real
 *      request-authz call site (adapterFilterMiddleware), with the
 *      decision produced by the native RBAC surface.
 *   2. A human principal keeps that access unchanged.
 *   3. A principalType-ABSENT session behaves exactly as before the
 *      partition existed — same allowed list, and the mapping store is
 *      never even read on that path.
 *   4. CHARIOT::§2.1::2 — when the native RBAC decision surface is
 *      unavailable (no binding, or a binding predating the
 *      `resolveUserAdaptersForPrincipal` export), the request is REFUSED
 *      (fails closed) rather than the decision being computed in
 *      TypeScript. There is no TS mirror of the Rust algorithm to test —
 *      unavailability is a hard refusal, not a fallback.
 *
 * Also pins the derivation rules in engine/trust/TenantContext.ts:
 * mTLS cert → 'service'; JWT explicit principal_type claim honored;
 * absent/unknown → 'human'; dev context → 'human'.
 *
 * Run after `tsc`: node --test dist/iam/principal-partition.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Request, Response, NextFunction } from 'express';
import { adapterFilterMiddleware } from './middleware.js';
import {
  filterAdapterIdsForPrincipal,
  resolveNativeFromBinding,
  NativeRbacUnavailableError,
  type PrincipalScopedMapping,
  type NativeRbacResolver,
  type NativeResolveAdaptersFn,
} from './services/principal-partition.js';
import {
  contextFromCert,
  contextFromJWT,
  createDevContext,
  parsePrincipalType,
} from '../engine/trust/TenantContext.js';

const TENANT = 't1';

/**
 * Test double standing in for the native `resolveUserAdaptersForPrincipal`
 * export (native/src/rbac.rs) — used ONLY to make tests deterministic
 * across hosts that may or may not have the platform binary built. This
 * is NOT a TypeScript fallback: production `filterAdapterIdsForPrincipal`
 * never uses this; it is wired in exclusively via the `resolveNative` test
 * seam (see AdapterFilterOptions.resolveNative / the function's own
 * default-parameter override), and the CHARIOT::§2.1::2 refusal tests
 * below prove the production default takes no such detour when the real
 * decision surface is unavailable. Mirrors the native contract described
 * in src/license/binding.ts's `resolveUserAdaptersForPrincipal` doc: group
 * ids match case-insensitively, a non-empty `principalScope` not
 * containing the caller's kind is skipped, and a matching mapping with
 * empty `adapterIds` is an explicit deny (empty result) overriding every
 * permissive mapping.
 */
function fakeNativeResolve(): NativeResolveAdaptersFn {
  return (_tenantId, principalType, userGroups, mappingsJson) => {
    const parsed = JSON.parse(mappingsJson) as PrincipalScopedMapping[];
    const userGroupSet = new Set(userGroups.map((g) => g.toLowerCase()));
    const allowed = new Set<string>();
    for (const mapping of parsed) {
      if (!userGroupSet.has(mapping.groupId.toLowerCase())) continue;
      const scope = mapping.principalScope;
      if (Array.isArray(scope) && scope.length > 0) {
        const matches = scope.some(
          (s) => typeof s === 'string' && s.toLowerCase() === principalType,
        );
        if (!matches) continue;
      }
      if (mapping.adapterIds.length === 0) return []; // explicit deny
      for (const id of mapping.adapterIds) allowed.add(id);
    }
    return [...allowed];
  };
}

/** Test-double resolver: simulates the native decision surface being present. */
function fakeNativeAvailable(): NativeRbacResolver {
  return () => ({ fn: fakeNativeResolve() });
}

/** Test-double resolver: simulates no platform binary loaded at all. */
function fakeNativeAbsent(): NativeRbacResolver {
  return () => ({
    reason: 'the native Chariot binary is not loaded (no platform binding found for this install)',
  });
}

/** Test-double resolver: simulates a binding loaded but missing the export. */
function fakeNativeStale(): NativeRbacResolver {
  return () => ({
    reason: 'the loaded native Chariot binary predates the resolveUserAdaptersForPrincipal export',
  });
}

/**
 * Fixture: 'ledger' is granted ONLY via a human-only mapping;
 * 'shared-crm' is granted via an unscoped (legacy-shaped) mapping.
 */
const MAPPINGS: PrincipalScopedMapping[] = [
  { tenantId: TENANT, groupId: 'finance', adapterIds: ['ledger'], principalScope: ['human'] },
  { tenantId: TENANT, groupId: 'eng', adapterIds: ['shared-crm'] },
];

interface FakeUserOpts {
  principalType?: string;
  adapterIds?: string[];
  allowedAdapterIds?: string[];
  groups?: string[];
}

function fakeReq(opts: FakeUserOpts): Request {
  return {
    tenantId: TENANT,
    enterpriseUser: {
      sub: 'u1',
      tenantId: TENANT,
      userId: 'u1',
      email: 'u1@example.com',
      displayName: 'U One',
      groups: opts.groups ?? ['finance', 'eng'],
      allowedAdapterIds: opts.allowedAdapterIds ?? [],
      adapterIds: opts.adapterIds ?? ['ledger', 'shared-crm'],
      isAdmin: false,
      jti: 'jti-1',
      iat: 0,
      exp: 0,
      ...(opts.principalType !== undefined ? { principalType: opts.principalType } : {}),
    },
  } as unknown as Request;
}

function fakeRes(): Response & { statusCode?: number; jsonBody?: unknown } {
  const res = {
    statusCode: undefined as number | undefined,
    jsonBody: undefined as unknown,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: unknown) {
      res.jsonBody = body;
      return res;
    },
  };
  return res as unknown as Response & { statusCode?: number; jsonBody?: unknown };
}

/**
 * Run the (async) middleware to completion. Defaults to the fake
 * NATIVE-AVAILABLE resolver so tests exercise the real decision-shaped
 * data flow deterministically; pass `resolveNative` to exercise the
 * refusal path instead.
 */
async function run(
  req: Request,
  loadCalls: { count: number },
  mappings: PrincipalScopedMapping[] = MAPPINGS,
  resolveNative: NativeRbacResolver = fakeNativeAvailable(),
): Promise<{ res: ReturnType<typeof fakeRes>; nextCalled: boolean }> {
  const res = fakeRes();
  let nextCalled = false;
  const next: NextFunction = () => { nextCalled = true; };
  const middleware = adapterFilterMiddleware({
    loadMappings: async (tenantId: string) => {
      loadCalls.count += 1;
      assert.equal(tenantId, TENANT);
      return mappings;
    },
    resolveNative,
  });
  await middleware(req, res, next);
  return { res, nextCalled };
}

// ---------------------------------------------------------------------------
// 1. Agent / service principals are DENIED the human-only grant
// ---------------------------------------------------------------------------

test('agent principal is stripped of the human-only grant but keeps unscoped grants', async () => {
  const loadCalls = { count: 0 };
  const req = fakeReq({ principalType: 'agent' });
  const { res, nextCalled } = await run(req, loadCalls);

  assert.equal(nextCalled, true, 'request with a surviving grant proceeds');
  assert.equal(res.statusCode, undefined);
  assert.deepEqual(
    req.allowedAdapterIds,
    ['shared-crm'],
    'ledger (human-only mapping) must be stripped for an agent principal',
  );
  assert.equal(loadCalls.count, 1, 'mapping store consulted exactly once for the agent path');
});

test('service principal is stripped of the human-only grant identically', async () => {
  const loadCalls = { count: 0 };
  const req = fakeReq({ principalType: 'service' });
  const { res, nextCalled } = await run(req, loadCalls);

  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, undefined);
  assert.deepEqual(req.allowedAdapterIds, ['shared-crm']);
});

test('agent whose ONLY grants are human-only gets the standard 403', async () => {
  const loadCalls = { count: 0 };
  const req = fakeReq({ principalType: 'agent', adapterIds: ['ledger'], groups: ['finance'] });
  const { res, nextCalled } = await run(req, loadCalls);

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.match(String((res.jsonBody as { error?: string }).error), /No adapters configured/);
});

test('mapping-store failure on the agent path fails CLOSED (503), never the unfiltered list', async () => {
  const req = fakeReq({ principalType: 'agent' });
  const res = fakeRes();
  let nextCalled = false;
  const middleware = adapterFilterMiddleware({
    loadMappings: async () => { throw new Error('mongo down'); },
  });
  await middleware(req, res, () => { nextCalled = true; });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 503);
  assert.equal(req.allowedAdapterIds, undefined, 'no adapter list may be attached on failure');
});

// ---------------------------------------------------------------------------
// 1b. CHARIOT::§2.1::2 — native RBAC decision surface unavailable → REFUSED,
//     never computed in TypeScript. Two distinct failure classes: no
//     binding loaded at all, and a binding loaded that predates the
//     principal-aware export.
// ---------------------------------------------------------------------------

test('no native binding loaded: agent request is refused (503), never falls back to a TS-computed decision', async () => {
  const loadCalls = { count: 0 };
  const req = fakeReq({ principalType: 'agent' });
  const { res, nextCalled } = await run(req, loadCalls, MAPPINGS, fakeNativeAbsent());

  assert.equal(nextCalled, false, 'refused request must not proceed to the handler');
  assert.equal(res.statusCode, 503);
  assert.equal(req.allowedAdapterIds, undefined, 'no adapter list — not even a TS-computed one — may be attached');
  assert.equal(loadCalls.count, 1, 'the mapping store IS read before the native-decision check (order: load, then decide)');
});

test('native binding loaded but missing resolveUserAdaptersForPrincipal: service request is refused (503)', async () => {
  const loadCalls = { count: 0 };
  const req = fakeReq({ principalType: 'service' });
  const { res, nextCalled } = await run(req, loadCalls, MAPPINGS, fakeNativeStale());

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 503);
  assert.equal(req.allowedAdapterIds, undefined);
});

test('filterAdapterIdsForPrincipal itself throws NativeRbacUnavailableError naming the missing binary when unavailable', async () => {
  await assert.rejects(
    () => filterAdapterIdsForPrincipal(
      TENANT,
      'agent',
      ['finance', 'eng'],
      ['ledger', 'shared-crm'],
      async () => MAPPINGS,
      fakeNativeAbsent(),
    ),
    (err: unknown) => {
      assert.ok(err instanceof NativeRbacUnavailableError);
      assert.match(
        (err as Error).message,
        /native Chariot binary is not loaded/,
        'the error must name the specific missing capability, not a generic failure',
      );
      assert.match((err as Error).message, /CHARIOT::§2\.1::2/);
      return true;
    },
  );
});

test('filterAdapterIdsForPrincipal throws distinctly when the binding is stale (present but missing the export)', async () => {
  await assert.rejects(
    () => filterAdapterIdsForPrincipal(
      TENANT,
      'service',
      ['eng'],
      ['shared-crm'],
      async () => MAPPINGS,
      fakeNativeStale(),
    ),
    (err: unknown) => {
      assert.ok(err instanceof NativeRbacUnavailableError);
      assert.match((err as Error).message, /predates the resolveUserAdaptersForPrincipal export/);
      return true;
    },
  );
});

test('resolveNativeFromBinding (production default): reflects the ACTUAL host binding — present + exports the function, or a named reason otherwise', () => {
  const resolved = resolveNativeFromBinding();
  if ('fn' in resolved) {
    // This host has the platform binary built with the principal-aware
    // export (true in this dev/CI environment — native/chariot-native.node
    // is present and exports resolveUserAdaptersForPrincipal). Exercise it
    // against real mapping shapes to prove the production default is wired
    // to a callable, not a stub.
    const out = resolved.fn(TENANT, 'agent', ['finance'], JSON.stringify(MAPPINGS));
    assert.ok(Array.isArray(out), 'native export must return an array');
  } else {
    // No platform binary on this host — the reason must name which
    // failure class applies, never a generic message.
    assert.match(
      resolved.reason,
      /native Chariot binary is not loaded|predates the resolveUserAdaptersForPrincipal export/,
    );
  }
});

// ---------------------------------------------------------------------------
// 2. Human principal keeps access
// ---------------------------------------------------------------------------

test('human principal keeps the human-only grant and the mapping store is not re-read', async () => {
  const loadCalls = { count: 0 };
  const req = fakeReq({ principalType: 'human' });
  const { res, nextCalled } = await run(req, loadCalls);

  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, undefined);
  assert.deepEqual(req.allowedAdapterIds, ['ledger', 'shared-crm']);
  assert.equal(loadCalls.count, 0, 'human path must not touch the mapping store');
});

// ---------------------------------------------------------------------------
// 3. principalType-absent (legacy) sessions behave exactly as before
// ---------------------------------------------------------------------------

test('principalType-absent session is byte-identical to pre-partition behavior', async () => {
  const loadCalls = { count: 0 };
  const req = fakeReq({});
  const { res, nextCalled } = await run(req, loadCalls);

  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, undefined);
  assert.deepEqual(req.allowedAdapterIds, ['ledger', 'shared-crm']);
  assert.equal(loadCalls.count, 0, 'legacy path must not touch the mapping store');
});

test('unrecognized principalType value falls back to the human (unchanged) path', async () => {
  const loadCalls = { count: 0 };
  const req = fakeReq({ principalType: 'robot' });
  const { nextCalled } = await run(req, loadCalls);

  assert.equal(nextCalled, true);
  assert.deepEqual(req.allowedAdapterIds, ['ledger', 'shared-crm']);
  assert.equal(loadCalls.count, 0);
});

test('agent with no groups on the tenant-ceiling path keeps the ceiling (no per-grant scope exists there)', async () => {
  const loadCalls = { count: 0 };
  const req = fakeReq({
    principalType: 'agent',
    adapterIds: [],
    groups: [],
    allowedAdapterIds: ['ceiling-adapter'],
  });
  const { nextCalled } = await run(req, loadCalls);

  assert.equal(nextCalled, true);
  assert.deepEqual(req.allowedAdapterIds, ['ceiling-adapter']);
  assert.equal(loadCalls.count, 0, 'ceiling path is not principal-filtered');
});

// ---------------------------------------------------------------------------
// Decision-shape coverage through filterAdapterIdsForPrincipal + the fake
// native resolver (CHARIOT::§2.1::2 — the real algorithm lives ONLY in
// native/src/rbac.rs; these tests pin the TS↔native JSON contract and the
// caller's interpretation of the native result, not a TS-computed decision).
// ---------------------------------------------------------------------------

test('case-insensitive group match: human-only mapping withheld from agent, granted to human', async () => {
  const agentOut = await filterAdapterIdsForPrincipal(
    TENANT, 'agent', ['FINANCE', 'ENG'], ['ledger', 'shared-crm'],
    async () => MAPPINGS, fakeNativeAvailable(),
  );
  assert.deepEqual(agentOut.sort(), ['shared-crm']);

  const mixedCaseScopeOut = await filterAdapterIdsForPrincipal(
    TENANT, 'agent', ['finance', 'eng'], ['ledger', 'shared-crm'],
    async () => [
      { tenantId: TENANT, groupId: 'finance', adapterIds: ['ledger'], principalScope: ['Human'] },
      { tenantId: TENANT, groupId: 'eng', adapterIds: ['shared-crm'] },
    ],
    fakeNativeAvailable(),
  );
  assert.deepEqual(mixedCaseScopeOut, ['shared-crm'], 'scope value "Human" (mixed case) still excludes agent');
});

test('explicit deny (empty adapterIds) on a matching-scope mapping overrides every other grant', async () => {
  const withDeny: PrincipalScopedMapping[] = [
    { tenantId: TENANT, groupId: 'eng', adapterIds: ['shared-crm'] },
    { tenantId: TENANT, groupId: 'contractors', adapterIds: [], principalScope: ['agent'] },
  ];
  const agentOut = await filterAdapterIdsForPrincipal(
    TENANT, 'agent', ['eng', 'contractors'], ['shared-crm'],
    async () => withDeny, fakeNativeAvailable(),
  );
  assert.deepEqual(agentOut, [], 'agent holds the deny-scoped group — explicit deny overrides the eng grant');

  const humanOut = await filterAdapterIdsForPrincipal(
    TENANT, 'agent' /* still non-human to exercise this code path */, ['eng', 'contractors'], ['shared-crm'],
    async () => [{ tenantId: TENANT, groupId: 'eng', adapterIds: ['shared-crm'] }],
    fakeNativeAvailable(),
  );
  assert.deepEqual(humanOut, ['shared-crm'], 'without the deny-scoped mapping present, the grant survives');
});

test('unrecognized principalScope value grants nothing to any principal kind (fails closed, not open)', async () => {
  const weird: PrincipalScopedMapping[] = [
    { tenantId: TENANT, groupId: 'g', adapterIds: ['a1'], principalScope: ['robot'] },
  ];
  for (const kind of ['agent', 'service'] as const) {
    const out = await filterAdapterIdsForPrincipal(
      TENANT, kind, ['g'], ['a1'], async () => weird, fakeNativeAvailable(),
    );
    assert.deepEqual(out, [], `principalScope ['robot'] must grant nothing to '${kind}'`);
  }
});

// ---------------------------------------------------------------------------
// Derivation — engine/trust/TenantContext.ts
// ---------------------------------------------------------------------------

test('derivation: mTLS client cert is a service principal', () => {
  const ctx = contextFromCert({ subject: { CN: 'workload.tenant-a' } });
  assert.equal(ctx.principalType, 'service');
});

test('derivation: JWT honors an explicit principal_type claim, defaults to human otherwise', () => {
  assert.equal(contextFromJWT({ sub: 'x', principal_type: 'agent' }).principalType, 'agent');
  assert.equal(contextFromJWT({ sub: 'x', principalType: 'SERVICE' }).principalType, 'service');
  assert.equal(contextFromJWT({ sub: 'x' }).principalType, 'human');
  assert.equal(contextFromJWT({ sub: 'x', principal_type: 'droid' }).principalType, 'human');
  assert.equal(contextFromJWT({ sub: 'x', principal_type: 42 }).principalType, 'human');
});

test('derivation: dev context is human; parsePrincipalType guards the value space', () => {
  assert.equal(createDevContext().principalType, 'human');
  assert.equal(parsePrincipalType('agent'), 'agent');
  assert.equal(parsePrincipalType('Service'), 'service');
  assert.equal(parsePrincipalType('admin'), undefined);
  assert.equal(parsePrincipalType(null), undefined);
});
