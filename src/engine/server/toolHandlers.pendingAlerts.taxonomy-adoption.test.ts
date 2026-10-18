/**
 * CHARIOT::§16.2 step 4 (CHARIOT-SPEC.md:1363, rulings item 91(2)/115) —
 * "Conversational queue: surfaced at the start of the admin's next AI
 * conversation." Rulings item 115: (a) the delivery surface is the FIRST
 * `chariot_query`/`chariot_list` response of a new MCP session whose
 * principal is an admin; (b) `CallContext.auth`'s Pick widened to include
 * `isAdmin`; (c) tenant scoping via `chariotAlertQueue.getPending(tenantId)`
 * — a tenant's own alerts plus process-wide (no-tenantId) operational
 * alerts, never crossing tenants.
 *
 * REAL BEHAVIORAL test: drives the real, exported `handleQuery`/
 * `handleList` against a minimal synthetic `ChariotState` (matching
 * `QueryExpander.call-site-opt-in.test.ts`'s established fixture pattern
 * for this exact function) and the real `chariotAlertQueue` singleton
 * (enqueuing real events into it, not a mock).
 *
 * Run (after tsc): node --test dist/engine/server/toolHandlers.pendingAlerts.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { handleQuery, handleList } from './toolHandlers.js';
import type { ChariotState, AdapterEntry } from './ChariotState.js';
import { createSessionSurfaceState } from './sessionSurfaceState.js';
import { chariotAlertQueue } from '../../observability/alerts.js';
import type { ChariotEvent } from '../../observability/emitter.js';

function emptySelect() {
  return {
    select: async () => [],
    selectWithVerdict: () => ({ tools: [], confidence: 0, abstain: true, degraded: false, legsUsed: [] }),
  };
}

function makeState(): ChariotState {
  const adapters: AdapterEntry[] = [];
  return {
    allAdapters: adapters,
    adapterById: new Map(),
    configuredAdapterIds: new Set(),
    credentials: {},
    fullCatalogFilter: emptySelect(),
    toolPreFilter: emptySelect(),
    getConfiguredAdapters: () => adapters,
    loadedAt: new Date().toISOString(),
    sessionSurfaceState: createSessionSurfaceState(),
  } as unknown as ChariotState;
}

function alertEvent(tenantId: string | undefined, suffix: string): ChariotEvent {
  return {
    type: 'adapter.connected',
    timestamp: new Date(),
    severity: 'warning',
    data: tenantId === undefined ? { note: suffix } : { tenantId, note: suffix },
    alertWorthy: true,
    message: `test alert ${suffix}`,
  };
}

test('§16.2 step 4: an admin session\'s FIRST chariot_query response carries pendingAlerts, and the entries are marked presented', async () => {
  const tenantId = `tenant-${randomUUID()}`;
  const sessionId = `session-${randomUUID()}`;
  const alert = chariotAlertQueue.enqueue(alertEvent(tenantId, 'first-call-test'));
  assert.ok(alert, 'sanity: the alert must have actually been enqueued');
  const state = makeState();

  try {
    const result = await handleQuery({ query: 'anything' }, state, { sessionId, tenantId, isAdmin: true }) as Record<string, unknown>;
    assert.ok(typeof result.pendingAlerts === 'string' && (result.pendingAlerts as string).includes('test alert first-call-test'), `expected pendingAlerts to be present, got: ${JSON.stringify(result)}`);

    const stillPending = chariotAlertQueue.getPending(tenantId).find((a) => a.id === alert!.id);
    assert.ok(stillPending?.presented, 'the alert must be marked presented after being surfaced');
  } finally {
    chariotAlertQueue.resolve(alert!.id, 'test-cleanup');
  }
});

test('§16.2 step 4: a SECOND chariot_query call in the SAME session never repeats the block, even with new alerts pending', async () => {
  const tenantId = `tenant-${randomUUID()}`;
  const sessionId = `session-${randomUUID()}`;
  const state = makeState();
  const alert1 = chariotAlertQueue.enqueue(alertEvent(tenantId, 'once-per-session-1'));

  try {
    const first = await handleQuery({ query: 'first' }, state, { sessionId, tenantId, isAdmin: true }) as Record<string, unknown>;
    assert.ok(typeof first.pendingAlerts === 'string');

    // A brand-new alert arrives mid-conversation.
    const alert2 = chariotAlertQueue.enqueue(alertEvent(tenantId, 'once-per-session-2'));
    try {
      const second = await handleQuery({ query: 'second' }, state, { sessionId, tenantId, isAdmin: true }) as Record<string, unknown>;
      assert.equal(second.pendingAlerts, undefined, 'the block must not repeat in the same session, even for a genuinely new alert — §16.2 step 4 is "at the START of the conversation"');
    } finally {
      if (alert2) chariotAlertQueue.resolve(alert2.id, 'test-cleanup');
    }
  } finally {
    if (alert1) chariotAlertQueue.resolve(alert1.id, 'test-cleanup');
  }
});

test('§16.2 step 4: a NON-admin session never sees pendingAlerts, even with real alerts pending for its own tenant', async () => {
  const tenantId = `tenant-${randomUUID()}`;
  const sessionId = `session-${randomUUID()}`;
  const state = makeState();
  const alert = chariotAlertQueue.enqueue(alertEvent(tenantId, 'non-admin-must-not-see'));

  try {
    const result = await handleQuery({ query: 'anything' }, state, { sessionId, tenantId, isAdmin: false }) as Record<string, unknown>;
    assert.equal(result.pendingAlerts, undefined);
    // Also never marked presented — a non-admin call must not consume the
    // alert's "unpresented" state on behalf of the admin who never saw it.
    const stillPending = chariotAlertQueue.getPending(tenantId).find((a) => a.id === alert!.id);
    assert.equal(stillPending?.presented, false);
  } finally {
    if (alert) chariotAlertQueue.resolve(alert.id, 'test-cleanup');
  }
});

test('§16.2 step 4: an isAdmin session with NO sessionId or NO tenantId never sees pendingAlerts (fail-closed gating)', async () => {
  const tenantId = `tenant-${randomUUID()}`;
  const state = makeState();
  const alert = chariotAlertQueue.enqueue(alertEvent(tenantId, 'missing-context-must-not-see'));
  try {
    const noSession = await handleQuery({ query: 'x' }, state, { tenantId, isAdmin: true }) as Record<string, unknown>;
    assert.equal(noSession.pendingAlerts, undefined, 'no sessionId -> no block');

    const noTenant = await handleQuery({ query: 'x' }, state, { sessionId: `s-${randomUUID()}`, isAdmin: true }) as Record<string, unknown>;
    assert.equal(noTenant.pendingAlerts, undefined, 'no tenantId -> no block (fail-closed, never "show everything")');
  } finally {
    if (alert) chariotAlertQueue.resolve(alert.id, 'test-cleanup');
  }
});

test('§16.2 step 4 tenant scoping: tenant A\'s alert never appears in tenant B\'s admin session', async () => {
  const tenantA = `tenant-a-${randomUUID()}`;
  const tenantB = `tenant-b-${randomUUID()}`;
  const state = makeState();
  const alertA = chariotAlertQueue.enqueue(alertEvent(tenantA, 'belongs-to-tenant-a-only'));

  try {
    const resultB = await handleQuery({ query: 'x' }, state, { sessionId: `s-${randomUUID()}`, tenantId: tenantB, isAdmin: true }) as Record<string, unknown>;
    if (typeof resultB.pendingAlerts === 'string') {
      assert.ok(!(resultB.pendingAlerts as string).includes('belongs-to-tenant-a-only'), 'tenant B must never see tenant A\'s alert text');
    }
    // The authoritative proof: tenant A's alert must still be unpresented
    // (tenant B's call must not have consumed it).
    const stillPending = chariotAlertQueue.getPending(tenantA).find((a) => a.id === alertA!.id);
    assert.equal(stillPending?.presented, false, 'tenant B\'s session must not mark tenant A\'s alert as presented');
  } finally {
    if (alertA) chariotAlertQueue.resolve(alertA.id, 'test-cleanup');
  }
});

test('§16.2 step 4 tenant scoping: a process-scoped alert (no tenantId — e.g. mongo.unreachable) appears in BOTH tenant A and tenant B admin sessions', async () => {
  const tenantA = `tenant-a-${randomUUID()}`;
  const tenantB = `tenant-b-${randomUUID()}`;
  const processAlert = chariotAlertQueue.enqueue(alertEvent(undefined, 'process-scoped-both-tenants'));
  assert.ok(processAlert, 'sanity: process-scoped alert enqueued');

  try {
    const resultA = await handleQuery({ query: 'x' }, makeState(), { sessionId: `s-${randomUUID()}`, tenantId: tenantA, isAdmin: true }) as Record<string, unknown>;
    assert.ok(typeof resultA.pendingAlerts === 'string' && (resultA.pendingAlerts as string).includes('process-scoped-both-tenants'), 'tenant A admin must see the process-scoped alert');

    const resultB = await handleQuery({ query: 'x' }, makeState(), { sessionId: `s-${randomUUID()}`, tenantId: tenantB, isAdmin: true }) as Record<string, unknown>;
    assert.ok(typeof resultB.pendingAlerts === 'string' && (resultB.pendingAlerts as string).includes('process-scoped-both-tenants'), 'tenant B admin must ALSO see the same process-scoped alert');

    // Direct proof of PER-TENANT presented tracking (chariot-verify-wave6
    // finding): both tenants independently marked it presented — neither
    // call's markPresented() hid it from the other tenant.
    assert.ok(processAlert!.presentedToTenants.has(tenantA), 'tenant A must be recorded in presentedToTenants');
    assert.ok(processAlert!.presentedToTenants.has(tenantB), 'tenant B must ALSO be recorded in presentedToTenants — not overwritten by tenant A\'s call');
  } finally {
    chariotAlertQueue.resolve(processAlert!.id, 'test-cleanup');
  }
});

test('§16.2 step 4: handleList (chariot_list) ALSO surfaces pendingAlerts on an admin session\'s first call', async () => {
  const tenantId = `tenant-${randomUUID()}`;
  const sessionId = `session-${randomUUID()}`;
  const state = makeState();
  const alert = chariotAlertQueue.enqueue(alertEvent(tenantId, 'via-chariot-list'));

  try {
    const result = await handleList({}, state, { sessionId, tenantId, isAdmin: true }) as Record<string, unknown>;
    assert.ok(typeof result.pendingAlerts === 'string' && (result.pendingAlerts as string).includes('via-chariot-list'));
  } finally {
    if (alert) chariotAlertQueue.resolve(alert.id, 'test-cleanup');
  }
});
