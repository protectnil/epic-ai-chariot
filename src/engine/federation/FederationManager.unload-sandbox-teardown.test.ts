/**
 * Regression eval: unloadAdapter() tears down a sandboxed adapter's sandbox
 * (CHARIOT §7.6::2 — "WHEN an adapter is revoked at runtime the system
 * SHALL drop active connections; SandboxManager tears down running
 * sandboxes").
 *
 * The defect this exists to catch: unloadAdapter() unconditionally called
 * `this.pool.disconnect(name)` — a no-op for sandboxed adapters, which live
 * outside `this.pool` entirely (see connectSandboxed()) — and never
 * consulted `this.sandboxedAdapters` nor called `this.sandbox.destroy(name)`.
 * A sandboxed adapter unloaded via `unloadAdapter()` therefore stayed alive
 * inside SandboxManager's internal `sandboxes` map forever, even though
 * FederationManager reported success. `disconnect()` (the sibling method)
 * already did this correctly; unloadAdapter() just never used the same path.
 *
 * This test connects a sandboxed adapter (SandboxManager mode:'none', so no
 * real child process/worker is spawned — just SandboxManager's own
 * create/destroy bookkeeping, which is exactly what's under test), calls
 * unloadAdapter(), and asserts the SandboxManager no longer holds the
 * sandbox. It would FAIL against the pre-fix code (the sandbox is never
 * destroyed).
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/FederationManager.unload-sandbox-teardown.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { FederationManager } from './FederationManager.js';
import { SandboxManager } from './sandbox/SandboxManager.js';
import type { AdapterCatalogEntry } from './AdapterCatalog.js';

/**
 * SandboxManager confines the adapter path to SANDBOX_PACKAGE_ROOT
 * (SandboxManager.ts:21) via confinePath (:72). Staging the fixture in the OS
 * temp dir is therefore rejected as `realpath-failed` before create() is ever
 * reached — the guard is correct and must not be weakened for a test, so the
 * fixture is staged INSIDE the package root instead. Same root derivation as
 * SandboxManager: this file compiles to dist/engine/federation/, so three
 * levels up is the package root.
 *
 * The fixture is handed over as a FILESYSTEM PATH, not a file:// URL:
 * confinePath does `resolve(root, candidate)` then realpathSync, so a URL
 * string resolves to a nonexistent `<root>/file:/...` and is rejected as
 * realpath-failed. SandboxManager passes `confined.resolved` (a path) on to
 * WorkerSandbox/ProcessSandbox, so a path is what the contract expects.
 */
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

const stagedDirs: string[] = [];

function trivialAdapterPath(): string {
  const dir = mkdtempSync(join(PACKAGE_ROOT, '.chariot-unload-sandbox-test-'));
  stagedDirs.push(dir);
  const file = join(dir, 'trivial-adapter.mjs');
  writeFileSync(
    file,
    `export default class TrivialAdapter {
       constructor() { this.tools = []; }
       async callTool() { return { content: [], isError: false }; }
     }`,
  );
  return file;
}

function sandboxesMap(manager: SandboxManager): Map<string, unknown> {
  return (manager as unknown as { sandboxes: Map<string, unknown> }).sandboxes;
}

test('unloadAdapter() destroys the sandbox for a sandboxed adapter', async () => {
  const sandboxManager = new SandboxManager();
  const federation = new FederationManager({ servers: [] }, { sandbox: sandboxManager });

  const name = 'community-sandboxed-adapter';
  const catalogEntry: AdapterCatalogEntry = {
    name,
    displayName: name,
    version: '1.0.0',
    category: 'productivity',
    keywords: [],
    toolNames: [],
    description: 'trivial test adapter',
    author: 'community',
  };

  await federation.connectSandboxed(catalogEntry, trivialAdapterPath(), {}, { mode: 'none' });
  assert.ok(sandboxesMap(sandboxManager).has(name), 'precondition: sandbox must be created');
  assert.equal(federation.isAdapterSandboxed(name), true);

  const result = await federation.unloadAdapter(name, 'test-unload');
  assert.equal(result.success, true, `unload must succeed: ${result.error}`);

  assert.equal(
    sandboxesMap(sandboxManager).has(name),
    false,
    '§7.6::2: unloadAdapter() must call SandboxManager.destroy() — the sandbox must not ' +
      'still be present after a successful unload',
  );
  assert.equal(federation.isAdapterSandboxed(name), false);
});

test('cleanup: staged fixture directories are removed from the package root', () => {
  // The fixture has to live inside the package root to clear confinePath, so it
  // must be cleaned up explicitly — an OS temp dir would have been reaped for us.
  for (const dir of stagedDirs) rmSync(dir, { recursive: true, force: true });
  stagedDirs.length = 0;
});
