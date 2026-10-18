/**
 * CHARIOT::§7.5::1 — "RegistryLoader SHALL instantiate each catalog-listed
 * adapter, wire it into the pool, register its tools with ToolPreFilter,
 * and expose reload() for runtime adapter unload." (CHARIOT-SPEC.md §7.5,
 * quoted verbatim above the node text, on-disk.)
 *
 * Prior to this change RegistryLoader.load() only built ServerConnection[]
 * data — it never called into a pool, never touched ToolPreFilter, and had
 * no reload() method at all. loadAndWire()/reload() close that gap at the
 * class level. As of the CHARIOT::§7.5::1 engine-wiring fix, `EpicAI.ts`
 * (src/engine/EpicAI.ts) actually constructs a RegistryLoader and calls
 * `loadAndWire()` from `start()` — see EpicAI.startup-wiring.test.ts for
 * the production-wiring-level test; this file stays focused on the
 * class-level wiring/reconciliation logic in isolation.
 *
 * `load()` itself reads the registry artifact through
 * `verifiedReadOrNull()`, which is Ed25519-signature-gated with no dev
 * opt-out (verifyCatalogSignature.ts docstring: "There is intentionally no
 * opt-out env var"). Fabricating a validly-signed fixture bundle is out of
 * scope for this eval (and out of scope for this unit's authorization —
 * no signing key access). This file therefore overrides the already-public
 * `load()` method with a fixed, in-memory RegistryLoadResult (a standard
 * seam-injection technique — `load()` is not private/final) so the
 * WIRING logic in loadAndWire()/reload() is exercised directly, decoupled
 * from the (separately-covered-elsewhere, unrelated-to-this-node) artifact
 * signature gate.
 *
 * Run (after `tsc`):
 *   node --test dist/engine/federation/RegistryLoader.wire-and-reload.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  RegistryLoader,
  type RegistryLoadResult,
  type RegistryLoaderFederationTarget,
  type RegistryLoaderToolIndex,
} from './RegistryLoader.js';
import type { ServerConnection, Tool } from '../types/index.js';

function connection(name: string): ServerConnection {
  return { name, transport: 'stdio', command: 'npx', args: [`@epicai/${name}`] };
}

function tool(server: string, name: string): Tool {
  return { name, description: 'd', parameters: { type: 'object', properties: {} }, server, tier: 'direct' };
}

/** Test double standing in for FederationManager — records connect/unload
 *  calls and serves listTools() from whatever is currently "connected". */
function fakeFederation(): RegistryLoaderFederationTarget & {
  connected: Set<string>;
  connectCalls: string[];
  unloadCalls: Array<{ name: string; reason: string }>;
} {
  const connected = new Set<string>();
  const connectCalls: string[] = [];
  const unloadCalls: Array<{ name: string; reason: string }> = [];
  return {
    connected,
    connectCalls,
    unloadCalls,
    async connect(name: string) {
      connected.add(name);
      connectCalls.push(name);
      return undefined;
    },
    async unloadAdapter(name: string, reason: string) {
      connected.delete(name);
      unloadCalls.push({ name, reason });
      return { success: true };
    },
    listTools(): Tool[] {
      return [...connected].map((name) => tool(name, 'noop'));
    },
    // CHARIOT::§7.5::1 — mirrors FederationManager.listConnectedServerNames();
    // lets loadAndWire() skip a name pre-seeded into `connected` the way a
    // real `connectAll()` (run before loadAndWire() in EpicAI.start()) would.
    listConnectedServerNames(): string[] {
      return [...connected];
    },
  };
}

function fakeToolPreFilter(): RegistryLoaderToolIndex & { indexCalls: Tool[][] } {
  const indexCalls: Tool[][] = [];
  return {
    indexCalls,
    index(tools: Tool[]) { indexCalls.push(tools); },
  };
}

function loaderWithFixedResult(
  result: RegistryLoadResult,
  opts: { federation?: RegistryLoaderFederationTarget; toolPreFilter?: RegistryLoaderToolIndex },
): RegistryLoader {
  const loader = new RegistryLoader(opts);
  // Seam injection — see file docstring. `load` is public, not final.
  (loader as unknown as { load: () => RegistryLoadResult }).load = () => result;
  return loader;
}

function resultFor(names: string[]): RegistryLoadResult {
  return {
    loaded: names.map((n) => ({ connection: connection(n), connectionType: 'mcp' as const, entry: {
      id: n, name: n, description: 'd', category: 'productivity', keywords: [], type: 'mcp' as const,
    } })),
    skipped: [],
    totalInRegistry: names.length,
  };
}

test('CHARIOT::§7.5::1 — loadAndWire() connects every loaded adapter and re-indexes ToolPreFilter', async () => {
  const federation = fakeFederation();
  const toolPreFilter = fakeToolPreFilter();
  const loader = loaderWithFixedResult(resultFor(['alpha', 'beta']), { federation, toolPreFilter });

  const result = await loader.loadAndWire();

  assert.deepEqual(result.loaded.map((l) => l.connection.name), ['alpha', 'beta']);
  assert.deepEqual(federation.connectCalls.sort(), ['alpha', 'beta']);
  assert.equal(toolPreFilter.indexCalls.length, 1, 'ToolPreFilter re-indexed exactly once per loadAndWire()');
  assert.deepEqual(
    toolPreFilter.indexCalls[0].map((t) => t.server).sort(),
    ['alpha', 'beta'],
  );
});

test('loadAndWire() with neither federation nor toolPreFilter configured behaves exactly like load() — no side effects (pre-1.4.0 compatibility)', async () => {
  const loader = loaderWithFixedResult(resultFor(['alpha']), {});
  const result = await loader.loadAndWire();
  assert.deepEqual(result.loaded.map((l) => l.connection.name), ['alpha']);
  // No federation/toolPreFilter wired — nothing to assert on beyond "did not throw".
});

test('CHARIOT::§7.5::1 — reload() connects newly-present adapters and unloads no-longer-present ones', async () => {
  const federation = fakeFederation();
  const toolPreFilter = fakeToolPreFilter();
  const loader = loaderWithFixedResult(resultFor(['alpha', 'beta']), { federation, toolPreFilter });
  await loader.loadAndWire();
  assert.deepEqual([...federation.connected].sort(), ['alpha', 'beta']);

  // Simulate a registry change: 'beta' removed (unloaded/revoked), 'gamma' added.
  (loader as unknown as { load: () => RegistryLoadResult }).load = () => resultFor(['alpha', 'gamma']);
  const result = await loader.reload();

  assert.deepEqual(result.loaded.map((l) => l.connection.name), ['alpha', 'gamma']);
  assert.deepEqual([...federation.connected].sort(), ['alpha', 'gamma']);
  assert.deepEqual(federation.unloadCalls.map((u) => u.name), ['beta']);
  assert.deepEqual(federation.connectCalls, ['alpha', 'beta', 'gamma'], 'alpha connected once at loadAndWire(), gamma connected once at reload()');
  assert.equal(toolPreFilter.indexCalls.length, 2, 'once at loadAndWire(), once at reload()');
  assert.deepEqual(toolPreFilter.indexCalls[1].map((t) => t.server).sort(), ['alpha', 'gamma']);
});

test('CHARIOT::§7.5::1 — reload() without a configured federation throws (nothing to reconcile against)', async () => {
  const loader = loaderWithFixedResult(resultFor(['alpha']), {});
  await assert.rejects(() => loader.reload(), /requires a `federation` target/);
});

test('CHARIOT::§7.5::1 — loadAndWire() does not double-connect an adapter name already connected (e.g. by connectAll() before this ran)', async () => {
  const federation = fakeFederation();
  // Simulate EpicAI.start(): connectAll() already connected this name from
  // FederationConfig.servers before loadAndWire() ever runs.
  federation.connected.add('already-up');
  const loader = loaderWithFixedResult(resultFor(['already-up', 'brand-new']), { federation });

  const result = await loader.loadAndWire();

  assert.deepEqual(result.loaded.map((l) => l.connection.name), ['already-up', 'brand-new']);
  assert.deepEqual(
    federation.connectCalls,
    ['brand-new'],
    'an already-connected name must not be passed to connect() again',
  );
  assert.deepEqual([...federation.connected].sort(), ['already-up', 'brand-new']);
});

test('CHARIOT::§7.5::1 — loadAndWire() still connects every loaded adapter when the target has no listConnectedServerNames() (pre-1.4.1 target compatibility)', async () => {
  const federation = fakeFederation();
  // Delete the optional method entirely to prove the `?? []` fallback path
  // (a target satisfying the pre-existing, narrower interface) still works.
  delete (federation as { listConnectedServerNames?: unknown }).listConnectedServerNames;
  const loader = loaderWithFixedResult(resultFor(['alpha']), { federation });

  await loader.loadAndWire();

  assert.deepEqual(federation.connectCalls, ['alpha']);
});
