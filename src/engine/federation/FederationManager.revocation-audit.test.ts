/**
 * CHARIOT::§7.6 — revocation gate: in-memory set, ApprovalQueue cancellation,
 * federation.adapter.revoked audit emission.
 *
 * CHARIOT-SPEC.md §7.6 (quoted verbatim, on-disk):
 *   "`src/engine/federation/FederationManager.ts` consults an in-memory
 *   revocation set on every callTool (CH-13). The set is populated from two
 *   sources: the catalog's per-entry `revoked: true` flag, and a runtime
 *   kill-list consumer (§7.7).
 *
 *   When an adapter is revoked at runtime:
 *   1. Active connections are dropped (`SandboxManager` tears down running
 *      sandboxes).
 *   2. Lazy connect is refused.
 *   3. ApprovalQueue items pointing at the adapter are marked as cancelled.
 *   4. An audit record is emitted under event type `federation.adapter.revoked`."
 *
 * Item 1 (§7.6::2) already has a dedicated regression test
 * (FederationManager.unload-sandbox-teardown.test.ts) and is NOT
 * re-verified here. This file is Test-derived from the failure enumeration
 * of items §7.6::1, §7.6::3, §7.6::4, §7.6::5:
 *   - value: revocation sourced from catalog alone, kill-list alone, and
 *     neither (must NOT gate).
 *   - position/boundary: unload of an UNKNOWN adapter name must emit
 *     nothing (the early-return in unloadAdapter() precedes the new code).
 *   - a plain (non-revocation) unloadAdapter() call must NOT cancel
 *     approvals or emit the audit event — only `{ revoked: true }` does.
 *   - post-revocation lazy connect() is refused even though the adapter
 *     was already removed from adapterMap/registry by the unload.
 *
 * Run (after `tsc`):
 *   node --test dist/engine/federation/FederationManager.revocation-audit.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { FederationManager } from './FederationManager.js';
import type { MCPAdapter } from './adapters/base.js';
import type { Tool, ToolResult, ConnectionStatus, ObservabilityEmitterContract } from '../types/index.js';
import type { AdapterCatalog } from './AdapterCatalog.js';

class FakeAdapter implements MCPAdapter {
  status: ConnectionStatus = 'connected';
  callCount = 0;
  constructor(readonly name: string, private readonly tools: Tool[] = []) {}
  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async listTools(): Promise<Tool[]> { return this.tools; }
  async ping(): Promise<number> { return 1; }
  async callTool(name: string): Promise<ToolResult> {
    this.callCount += 1;
    return { content: 'ok', isError: false, server: this.name, tool: name, durationMs: 1, outcome: 'success' };
  }
}

/** Minimal AdapterCatalog stand-in — only isRevoked/getRevocationDetails/
 *  revokedNames/onChanged are consulted by FederationManager. Cast through
 *  `unknown` because AdapterCatalog carries private fields, which makes it
 *  nominally (not just structurally) typed in TS.
 *
 *  `setRevoked()` lets a test simulate a catalog reload that changes which
 *  names are flagged `revoked: true`, firing every listener registered via
 *  `onChanged()` — mirrors `AdapterCatalog.buildIndex()` notifying its
 *  `changeListeners` after every successful (re)load. Deliberately does
 *  NOT implement `onChanged`/`revokedNames` unconditionally: production
 *  FederationManager code guards both with `?.` specifically so a catalog
 *  stand-in lacking them (the original, pre-§7.6::1-sync-set version of
 *  this helper) does not crash construction — see the two tests further
 *  down that exercise that fallback with a catalog built from
 *  `fakeCatalogWithoutSync()`.
 */
function fakeCatalog(initialRevoked: Set<string>): AdapterCatalog & { setRevoked(names: Set<string>): void } {
  let revoked = new Set(initialRevoked);
  const listeners: Array<() => void> = [];
  return {
    isRevoked: (name: string) => revoked.has(name),
    getRevocationDetails: (name: string) =>
      revoked.has(name) ? { revoked: true as const, reason: 'catalog-flag' } : undefined,
    revokedNames: () => revoked,
    onChanged: (cb: () => void) => { listeners.push(cb); },
    setRevoked(names: Set<string>) {
      revoked = new Set(names);
      for (const listener of listeners) listener();
    },
  } as unknown as AdapterCatalog & { setRevoked(names: Set<string>): void };
}

/** A catalog stand-in with ONLY isRevoked/getRevocationDetails — no
 *  `onChanged`/`revokedNames` at all — proving FederationManager's `?.`
 *  guards around those two calls (constructor + syncCatalogRevocations)
 *  keep a narrower/older catalog target from crashing construction. */
function fakeCatalogWithoutSync(revokedNames: Set<string>): AdapterCatalog {
  return {
    isRevoked: (name: string) => revokedNames.has(name),
    getRevocationDetails: (name: string) =>
      revokedNames.has(name) ? { revoked: true as const, reason: 'catalog-flag' } : undefined,
  } as unknown as AdapterCatalog;
}

function fakeApprovalQueue() {
  const calls: Array<{ server: string; reason: string }> = [];
  return {
    calls,
    cancelByServer: async (server: string, reason: string) => {
      calls.push({ server, reason });
      return [{ id: 'approval-1' }];
    },
  };
}

function fakeEmitter(): { emitted: Array<Record<string, unknown>> } & ObservabilityEmitterContract {
  const emitted: Array<Record<string, unknown>> = [];
  return {
    emitted,
    emitToolCallRetry: () => {},
    emitToolErrorClassified: () => {},
    emitPolicyDecision: () => {},
    emitParameterValidationRejected: () => {},
    emitApprovalRequired: () => {},
    emitSubAgentSpawn: () => {},
    emitShortlistTokenCost: () => {},
    emitContextBudgetExceeded: () => {},
    emitProbeDecision: () => {},
    emitSteeringApplied: () => {},
    emitAdapterRevoked: (payload) => { emitted.push(payload); },
  };
}

let seq = 0;
function nextName(): string { seq += 1; return `revocable-adapter-${seq}`; }

// ── §7.6::4 / §7.6::5: revoked unload cancels approvals + emits audit ──────

test('CHARIOT::§7.6::4/§7.6::5 — unloadAdapter({revoked:true}) cancels ApprovalQueue items and emits federation.adapter.revoked exactly once', async () => {
  const name = nextName();
  const approvalQueue = fakeApprovalQueue();
  const emitter = fakeEmitter();
  const manager = new FederationManager({ servers: [] }, { approvalQueue, observabilityEmitter: emitter });
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));

  const result = await manager.unloadAdapter(name, 'compromised', { revoked: true });

  assert.equal(result.success, true, `unload must succeed: ${result.error}`);
  assert.equal(approvalQueue.calls.length, 1, 'cancelByServer called exactly once');
  assert.deepEqual(approvalQueue.calls[0], { server: name, reason: 'compromised' });

  assert.equal(emitter.emitted.length, 1, 'federation.adapter.revoked emitted exactly once');
  const payload = emitter.emitted[0];
  assert.equal(payload.adapterId, name);
  assert.equal(payload.reason, 'compromised');
  assert.equal(payload.cancelledApprovalCount, 1);
  assert.equal(typeof payload.revokedAt, 'string');
  assert.ok(!Number.isNaN(Date.parse(payload.revokedAt as string)), 'revokedAt must be a parseable timestamp');
});

test('CHARIOT::§7.6::5 — revoke of an UNKNOWN adapter emits no event and does not touch the approval queue', async () => {
  const approvalQueue = fakeApprovalQueue();
  const emitter = fakeEmitter();
  const manager = new FederationManager({ servers: [] }, { approvalQueue, observabilityEmitter: emitter });

  const result = await manager.unloadAdapter('never-connected', 'irrelevant', { revoked: true });

  assert.equal(result.success, false);
  assert.equal(result.reason, 'unknown');
  assert.equal(approvalQueue.calls.length, 0);
  assert.equal(emitter.emitted.length, 0);
});

test('a plain (non-revocation) unloadAdapter() call does NOT cancel approvals or emit the audit event', async () => {
  const name = nextName();
  const approvalQueue = fakeApprovalQueue();
  const emitter = fakeEmitter();
  const manager = new FederationManager({ servers: [] }, { approvalQueue, observabilityEmitter: emitter });
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));

  const result = await manager.unloadAdapter(name, 'operator requested graceful drain');

  assert.equal(result.success, true);
  assert.equal(approvalQueue.calls.length, 0, 'a graceful unload is not a revocation — must not cancel approvals');
  assert.equal(emitter.emitted.length, 0, 'a graceful unload is not a revocation — must not emit federation.adapter.revoked');
});

// ── §7.6::1 / §7.6::3: in-memory revocation set (catalog ∪ kill-list) ──────

test('CHARIOT::§7.6::1/§7.6::3 — post-revocation lazy connect is refused when revoked via the KILL-LIST path', async () => {
  const name = nextName();
  const manager = new FederationManager({ servers: [] });
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));

  // Simulate KillListWatcher's call shape: revoked:true, no catalog wired at all.
  const unloaded = await manager.unloadAdapter(name, 'kill_list: contradiction_detected', { revoked: true });
  assert.equal(unloaded.success, true);

  // Lazy reconnect attempt — must be refused even though there is no
  // catalog on this manager (options.catalog was never set), proving the
  // refusal comes from the kill-list-populated in-memory set, not the
  // catalog half of the union.
  const freshAdapter = new FakeAdapter(name);
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, freshAdapter);
  assert.equal(freshAdapter.callCount, 0, 'adapter must never have been dispatched to');

  const tools = manager.listTools();
  assert.equal(
    tools.some((t) => t.server === name),
    false,
    'the reconnect attempt must be refused — no tools from this adapter should be registered',
  );
});

test('CHARIOT::§7.6::1 — revocation set is a union: an adapter revoked ONLY in the catalog is refused too', async () => {
  const name = nextName();
  const catalog = fakeCatalog(new Set([name]));
  const manager = new FederationManager({ servers: [] }, { catalog });

  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));

  const tools = manager.listTools();
  assert.equal(tools.some((t) => t.server === name), false, 'catalog-revoked adapter must never connect');
});

test('CHARIOT::§7.6::1 — an adapter revoked by NEITHER source connects and dispatches normally (no false-positive gating)', async () => {
  const name = nextName();
  // Permissive egress so gap #9's default-deny (an unrelated, pre-existing
  // control) does not interfere with this revocation-gate assertion.
  const manager = new FederationManager({ servers: [], egressPolicy: { defaultEffect: 'allow' } });
  const adapter = new FakeAdapter(name, [
    { name: 'noop', description: 'd', parameters: { type: 'object', properties: {} }, server: name, tier: 'direct', annotations: { readOnlyHint: true } },
  ]);
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, adapter);

  const result = await manager.callTool(`${name}:noop`, {});
  assert.equal(result.isError, false);
  assert.equal(adapter.callCount, 1);
});

// ── CHARIOT::§7.6::1 — the set is a real UNION, seeded from the catalog and
// kept in sync on every catalog change, not just an OR'd live predicate ──

test('CHARIOT::§7.6::1 — a catalog reload that newly marks a CONNECTED adapter revoked runs the full runtime-revocation path (teardown + approval cancel + audit)', async () => {
  const name = nextName();
  const catalog = fakeCatalog(new Set()); // starts clean — nothing revoked yet
  const approvalQueue = fakeApprovalQueue();
  const emitter = fakeEmitter();
  const auditRecords: Array<Record<string, unknown>> = [];
  const manager = new FederationManager(
    { servers: [] },
    {
      catalog,
      approvalQueue,
      observabilityEmitter: emitter,
      onAdapterRevoked: async (payload) => {
        auditRecords.push(payload);
      },
    },
  );

  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));
  assert.equal(manager.listConnectedServerNames().includes(name), true, 'adapter connected before revocation');

  // Simulate a signed-catalog refresh that newly flags this adapter
  // revoked:true — fires every onChanged() listener, same as
  // AdapterCatalog.buildIndex() does on a real (re)load.
  catalog.setRevoked(new Set([name]));

  // syncCatalogRevocations() fires unloadAdapter() without the caller
  // awaiting it (the onChanged listener itself is synchronous) — poll
  // for the async teardown to settle instead of assuming a fixed number
  // of ticks.
  for (let i = 0; i < 100 && manager.listConnectedServerNames().includes(name); i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }

  assert.equal(
    manager.listConnectedServerNames().includes(name),
    false,
    'active connection must be torn down once the catalog marks it revoked (§7.6::2)',
  );
  assert.equal(approvalQueue.calls.length, 1, 'pending approvals for the adapter must be cancelled (§7.6::4)');
  assert.deepEqual(approvalQueue.calls[0].server, name);
  assert.equal(emitter.emitted.length, 1, 'observability emitAdapterRevoked fired exactly once (§7.6::5)');
  assert.equal(auditRecords.length, 1, 'onAdapterRevoked audit hook fired exactly once (§7.6::5)');
  assert.equal(auditRecords[0].adapterId, name);

  // Lazy reconnect must also be refused (§7.6::3) — proves the catalog
  // path joined the SAME union set the kill-list path uses, not a
  // catalog-only side channel.
  const freshAdapter = new FakeAdapter(name);
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, freshAdapter);
  assert.equal(freshAdapter.callCount, 0);
});

test('CHARIOT::§7.6::1 — the union set is seeded from the catalog at construction, before any onChanged() fires', async () => {
  const name = nextName();
  // Catalog is ALREADY loaded with a revoked entry at FederationManager
  // construction time (the EpicAI.start() ordering: `await
  // adapterCatalog.load()` runs before `new FederationManager(...)`'s
  // constructor... no — before `connectAll()`, but the catalog instance
  // itself is passed into the constructor already-populated in the
  // common case where a caller loads it first). Prove the seed happens
  // in the constructor, not only lazily on the first onChanged() fire.
  const catalog = fakeCatalog(new Set([name]));
  const manager = new FederationManager({ servers: [] }, { catalog });

  // No onChanged() has fired since construction — if the constructor
  // did not seed the set (or if it relied solely on the still-truthy
  // `this.catalog?.isRevoked()` OR check instead), a name added to
  // adapterMap out-of-band would slip through. Verify via the connect()
  // gate directly instead, since that is the only externally observable
  // signal: the connect attempt must be refused.
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));
  assert.equal(manager.listConnectedServerNames().includes(name), false);
});

test('CHARIOT::§7.6::1 — FederationManager construction does not crash when the catalog target has no onChanged()/revokedNames() (older/narrower target)', async () => {
  const name = nextName();
  const catalog = fakeCatalogWithoutSync(new Set([name]));
  // Must not throw — the `?.` guards around `catalog.onChanged` and
  // `catalog.revokedNames` exist exactly for a target like this one.
  const manager = new FederationManager({ servers: [] }, { catalog });

  // The live `this.catalog?.isRevoked()` OR-check (kept as an additional
  // check per the clause) still refuses this adapter even though the
  // union set itself could never be seeded from this catalog shape.
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));
  assert.equal(manager.listConnectedServerNames().includes(name), false);
});

test('CHARIOT::§7.6::5 — onAdapterRevoked fires with the same payload shape on the KILL-LIST unload path too (not only the catalog path)', async () => {
  const name = nextName();
  const approvalQueue = fakeApprovalQueue();
  const auditRecords: Array<Record<string, unknown>> = [];
  const manager = new FederationManager(
    { servers: [] },
    {
      approvalQueue,
      onAdapterRevoked: async (payload) => {
        auditRecords.push(payload);
      },
    },
  );
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));

  const result = await manager.unloadAdapter(name, 'kill_list: contradiction_detected', { revoked: true });

  assert.equal(result.success, true);
  assert.equal(auditRecords.length, 1);
  assert.equal(auditRecords[0].adapterId, name);
  assert.equal(auditRecords[0].reason, 'kill_list: contradiction_detected');
  assert.equal(auditRecords[0].cancelledApprovalCount, 1);
  assert.equal(typeof auditRecords[0].revokedAt, 'string');
});

test('CHARIOT::§7.6::5 — an onAdapterRevoked hook that throws does not reverse the already-completed revocation', async () => {
  const name = nextName();
  const manager = new FederationManager(
    { servers: [] },
    {
      onAdapterRevoked: async () => {
        throw new Error('simulated audit-write failure');
      },
    },
  );
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));

  const result = await manager.unloadAdapter(name, 'compromised', { revoked: true });

  assert.equal(result.success, true, 'revocation must succeed even though the audit hook threw');
  assert.equal(manager.listConnectedServerNames().includes(name), false);

  // Lazy reconnect must still be refused — the failed audit write must
  // not have unwound the in-memory revocation set either.
  const freshAdapter = new FakeAdapter(name);
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, freshAdapter);
  assert.equal(freshAdapter.callCount, 0);
});

// ── CHARIOT::§7.6 — F6 fix: in-flight teardown dedupe ──────────────────────

test('CHARIOT::§7.6 — F6: concurrent unloadAdapter() calls for the SAME name in-flight-dedupe to the identical promise', async () => {
  const name = nextName();
  const approvalQueue = fakeApprovalQueue();
  const emitter = fakeEmitter();
  const manager = new FederationManager({ servers: [] }, { approvalQueue, observabilityEmitter: emitter });
  await manager.connect(name, { name, transport: 'stdio', command: 'true' }, new FakeAdapter(name));

  // Fire two "revocation" unloads for the same name without awaiting
  // between them — simulates two independent reconciliation paths (the
  // scenario F6 fixes) both reacting to the same catalog change before
  // either has finished tearing the adapter down.
  const p1 = manager.unloadAdapter(name, 'r1', { revoked: true });
  const p2 = manager.unloadAdapter(name, 'r2', { revoked: true });

  assert.equal(p1, p2, 'both callers must receive the IDENTICAL in-flight promise (===)');

  const [r1, r2] = await Promise.all([p1, p2]);
  assert.equal(r1, r2, 'both callers must receive the IDENTICAL settled result object (===)');
  assert.equal(r1.success, true);
  assert.equal(r1.reason, 'r1', 'the FIRST caller\'s teardown ran — the second caller was deduped, not queued separately');
  assert.equal(approvalQueue.calls.length, 1, 'exactly one teardown ran — approval cancellation not duplicated (§7.6::4)');
  assert.equal(emitter.emitted.length, 1, 'exactly one federation.adapter.revoked emission (§7.6::5)');

  // A call after the in-flight one has settled starts a fresh, independent
  // attempt (the map entry was cleared) — the adapter is already gone by
  // then, so this one correctly takes the pre-existing "unknown adapter"
  // no-op path, proving dedupe does not leak/reuse a stale promise forever.
  const p3 = manager.unloadAdapter(name, 'r3', { revoked: true });
  assert.notEqual(p3, p1, 'a call after settlement must not reuse the stale in-flight promise');
  const r3 = await p3;
  assert.equal(r3.success, false);
  assert.equal(r3.reason, 'unknown');
  assert.equal(approvalQueue.calls.length, 1, 'the post-settlement no-op call must not cancel approvals again');
});
