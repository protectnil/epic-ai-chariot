/**
 * CHARIOT::§7.6::1 / §7.5::1 — F6 fix: the catalog-change reconciliation
 * (FederationManager.syncCatalogRevocations() vs. RegistryLoader.reload())
 * must be serialized against a single queue, not run as two independent
 * listeners on the same `AdapterCatalog.onChanged()` event.
 *
 * CHARIOT-SPEC.md:631 (§7.6, quoted verbatim, on-disk):
 *   "`src/engine/federation/FederationManager.ts` consults an in-memory
 *   revocation set on every callTool (CH-13)."
 * CHARIOT-SPEC.md:627 (§7.5, quoted verbatim, on-disk):
 *   "It instantiates each catalog-listed adapter, wires it into the pool,
 *   registers its tools with `ToolPreFilter`, and exposes a `reload()`
 *   for runtime adapter unload."
 *
 * Before this fix, `EpicAI.start()` registered TWO independent
 * `catalog.onChanged()` listeners: FederationManager's own (active
 * teardown of anything newly revoked) and EpicAI's (RegistryLoader
 * .reload() — full add/remove reconciliation against the registry, which
 * also unloads any name no longer present in the loaded result — a
 * revoked entry is filtered out of `load()`'s result by RegistryLoader's
 * own catalog check). Both listeners fire synchronously off the same
 * event; both could observe `adapterMap.has(name) === true` before
 * either had finished tearing it down, double-running teardown, approval
 * cancellation, and the `federation.adapter.revoked` audit emission.
 *
 * The fix (EpicAI.ts): FederationManager is constructed with
 * `autoSyncCatalogRevocations: false` so it does NOT self-register a
 * listener; `syncCatalogRevocations()` is now a PUBLIC method; EpicAI
 * registers exactly ONE listener that chains
 * `syncCatalogRevocations().then(() => reload())` on a promise queue.
 * This file replicates that exact production wiring pattern directly
 * against the real `FederationManager`/`RegistryLoader` classes (EpicAI
 * itself constructs both internally with no injection seam, and its
 * `AdapterCatalog` reads a real signed bundle file — not controllable
 * from a test — so this is the smallest real seam available per Method
 * step 5: real classes, real coordination code, a hand-built fake
 * catalog standing in only for AdapterCatalog's on-disk I/O).
 *
 * Run (after `tsc`):
 *   node --test dist/engine/federation/FederationManager.catalog-reconcile-serialization.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { FederationManager } from './FederationManager.js';
import { RegistryLoader, type RegistryLoadResult } from './RegistryLoader.js';
import type { MCPAdapter } from './adapters/base.js';
import type { Tool, ToolResult, ConnectionStatus, ObservabilityEmitterContract } from '../types/index.js';
import type { AdapterCatalog } from './AdapterCatalog.js';

class FakeAdapter implements MCPAdapter {
  status: ConnectionStatus = 'connected';
  constructor(readonly name: string) {}
  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async listTools(): Promise<Tool[]> { return []; }
  async ping(): Promise<number> { return 1; }
  async callTool(name: string): Promise<ToolResult> {
    return { content: 'ok', isError: false, server: this.name, tool: name, durationMs: 1, outcome: 'success' };
  }
}

/** Same shape as FederationManager.revocation-audit.test.ts's fakeCatalog
 *  helper — duplicated locally (each test file in this suite owns its
 *  fixtures rather than sharing a helper module, matching the existing
 *  pattern in this directory). `setRevoked()` fires every `onChanged()`
 *  listener synchronously, mirroring `AdapterCatalog.buildIndex()`. */
function fakeCatalog(): AdapterCatalog & { setRevoked(names: Set<string>): void } {
  let revoked = new Set<string>();
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

function connection(name: string) {
  return { name, transport: 'stdio' as const, command: 'true' };
}

function resultFor(names: string[]): RegistryLoadResult {
  return {
    loaded: names.map((n) => ({
      connection: connection(n),
      connectionType: 'mcp' as const,
      entry: { id: n, name: n, description: 'd', category: 'productivity', keywords: [], type: 'mcp' as const },
    })),
    skipped: [],
    totalInRegistry: names.length,
  };
}

/** Registers EpicAI's exact production reconciliation pattern
 *  (EpicAI.ts's single `adapterCatalog.onChanged()` listener) against the
 *  given real FederationManager + RegistryLoader instances. Returns a
 *  function that resolves once the CURRENT queue tail settles, so the
 *  test can wait for a triggered reconciliation to fully finish. */
function wireReconciliation(
  catalog: AdapterCatalog,
  manager: FederationManager,
  loader: RegistryLoader,
  order: string[],
): () => Promise<void> {
  let queue: Promise<void> = Promise.resolve();
  catalog.onChanged(() => {
    queue = queue
      .then(async () => {
        order.push('sync-start');
        await manager.syncCatalogRevocations();
        order.push('sync-end');
      })
      .then(async () => {
        order.push('reload-start');
        await loader.reload();
        order.push('reload-end');
      })
      .catch((err) => {
        order.push(`error:${err instanceof Error ? err.message : String(err)}`);
      });
  });
  return () => queue;
}

let seq = 0;
function nextName(): string { seq += 1; return `catalog-reconcile-${seq}`; }

test('CHARIOT::§7.6::1/§7.5::1 — F6: a catalog change that both revokes AND removes a connected adapter runs teardown exactly once, sync fully before reload', async () => {
  const name = nextName();
  const catalog = fakeCatalog();
  const approvalQueue = fakeApprovalQueue();
  const emitter = fakeEmitter();
  const auditRecords: Array<Record<string, unknown>> = [];

  const manager = new FederationManager(
    { servers: [] },
    {
      catalog,
      autoSyncCatalogRevocations: false, // F6 fix — EpicAI owns the reaction
      approvalQueue,
      observabilityEmitter: emitter,
      onAdapterRevoked: async (payload) => { auditRecords.push(payload); },
    },
  );
  await manager.connect(name, connection(name), new FakeAdapter(name));
  assert.equal(manager.listConnectedServerNames().includes(name), true, 'precondition: adapter connected');

  const loader = new RegistryLoader({ catalog, federation: manager });
  // Seam injection (RegistryLoader.wire-and-reload.test.ts's documented
  // technique): fix `load()`'s result so `loadAndWire()`/`reload()`
  // reconcile against a controlled registry instead of a real signed
  // bundle. Adapter starts present...
  let loadResult = resultFor([name]);
  (loader as unknown as { load: () => RegistryLoadResult }).load = () => loadResult;
  await loader.loadAndWire();
  assert.deepEqual([...manager.listConnectedServerNames()], [name]);

  const order: string[] = [];
  const waitForQueue = wireReconciliation(catalog, manager, loader, order);

  // Simulate a real signed-catalog refresh: the adapter is now revoked
  // (so `isRevoked()` flips true) AND, consistent with that, is no
  // longer present in the freshly-reconciled registry result (a real
  // RegistryLoader.load() filters revoked catalog entries out — this
  // fake mirrors that outcome directly rather than re-deriving it).
  loadResult = resultFor([]);
  catalog.setRevoked(new Set([name]));

  await waitForQueue();

  assert.equal(
    manager.listConnectedServerNames().includes(name),
    false,
    'adapter must be torn down after the catalog change (§7.6::2)',
  );
  assert.equal(approvalQueue.calls.length, 1, 'exactly ONE teardown ran — approval cancellation not duplicated (§7.6::4)');
  assert.equal(emitter.emitted.length, 1, 'exactly ONE federation.adapter.revoked observability emission (§7.6::5)');
  assert.equal(auditRecords.length, 1, 'exactly ONE onAdapterRevoked audit hook invocation (§7.6::5)');
  assert.equal(auditRecords[0].adapterId, name);

  assert.deepEqual(
    order,
    ['sync-start', 'sync-end', 'reload-start', 'reload-end'],
    'syncCatalogRevocations() must fully complete (both its start and end) before reload() starts — proves the serialization, not just the outcome',
  );
});

test('CHARIOT::§7.6::1/§7.5::1 — F6: two catalog-change notifications fired back-to-back (no await between) still produce two fully non-interleaved reconciliation passes', async () => {
  const nameA = nextName();
  const nameB = nextName();
  const catalog = fakeCatalog();
  const approvalQueue = fakeApprovalQueue();

  const manager = new FederationManager(
    { servers: [] },
    { catalog, autoSyncCatalogRevocations: false, approvalQueue },
  );
  await manager.connect(nameA, connection(nameA), new FakeAdapter(nameA));
  await manager.connect(nameB, connection(nameB), new FakeAdapter(nameB));

  const loader = new RegistryLoader({ catalog, federation: manager });
  // `catalog.onChanged()` listeners fire SYNCHRONOUSLY inside
  // `setRevoked()`, but each listener only SCHEDULES its async
  // sync/reload chain (`queue.then(...)`) — nothing in it actually runs
  // until the current synchronous block yields. So by the time either
  // chain's body executes, `catalog.revokedNames()` already reflects the
  // FINAL state below (both names) — this test is deliberately about
  // that ordering property (does a second rapid-fire notification wait
  // for the first reconciliation to finish, never interleaving with it),
  // not about staging distinct intermediate registry states per trigger.
  (loader as unknown as { load: () => RegistryLoadResult }).load = () => resultFor([]);
  await loader.loadAndWire();

  const order: string[] = [];
  const waitForQueue = wireReconciliation(catalog, manager, loader, order);

  // Two rapid-fire catalog-change notifications, back to back, with no
  // await between — queues two reconciliation passes without letting
  // either run first.
  catalog.setRevoked(new Set([nameA]));
  catalog.setRevoked(new Set([nameA, nameB]));

  await waitForQueue();

  assert.equal(manager.listConnectedServerNames().includes(nameA), false);
  assert.equal(manager.listConnectedServerNames().includes(nameB), false);
  assert.equal(
    approvalQueue.calls.length,
    2,
    'each adapter torn down exactly once total across both queued reconciliation passes — never duplicated',
  );
  // Two full sync/reload pairs, never interleaved: each 4-entry group is
  // internally complete (its own reload-start/-end) before the next
  // group's sync-start appears anywhere in the log.
  assert.equal(order.length, 8, 'exactly two full reconciliation passes ran');
  for (let i = 0; i < order.length; i += 4) {
    assert.deepEqual(order.slice(i, i + 4), ['sync-start', 'sync-end', 'reload-start', 'reload-end']);
  }
});
