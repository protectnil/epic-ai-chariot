/**
 * @epicai/chariot — Sandbox Manager
 * Creates and manages sandboxed adapter instances.
 * protectnil → worker-thread, vendor/community → process.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { fileURLToPath } from 'node:url';
import { resolve as pathResolve, dirname } from 'node:path';
import { createLogger } from '../../logger.js';
import type { Tool, ToolResult } from '../../types/index.js';
import type { AdapterCatalogEntry } from '../AdapterCatalog.js';
import { WorkerSandbox } from './WorkerSandbox.js';
import { ProcessSandbox } from './ProcessSandbox.js';
import type { AdapterSandboxConfig, SandboxMode } from './types.js';
import { DEFAULT_SANDBOX_CONFIG } from './types.js';
import { confinePath } from '../../keys/pathConfinement.js';

// dist/engine/federation/sandbox/SandboxManager.js → package root
const SANDBOX_PACKAGE_ROOT = pathResolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

const log = createLogger('federation.sandbox');

export interface SandboxedAdapter {
  listTools(): Promise<Tool[]>;
  callTool(name: string, args: Record<string, unknown>): Promise<ToolResult>;
  stop(): Promise<void>;
}

export class SandboxManager {
  private readonly sandboxes = new Map<string, SandboxedAdapter>();

  /**
   * Create a sandboxed adapter instance.
   * If one already exists for this adapter, return the existing one.
   */
  async create(
    catalogEntry: AdapterCatalogEntry,
    adapterPath: string,
    credentials: Record<string, string>,
    configOverride?: Partial<AdapterSandboxConfig>,
  ): Promise<SandboxedAdapter> {
    const key = catalogEntry.name;

    // Idempotent: return existing sandbox
    const existing = this.sandboxes.get(key);
    if (existing) return existing;

    const mode = this.modeForAuthor(catalogEntry.author);
    const config: AdapterSandboxConfig = {
      ...DEFAULT_SANDBOX_CONFIG,
      mode,
      ...configOverride,
    };

    // FAIL-CLOSED: never spawn an adapter that DECLARES a confinement this
    // build cannot actually enforce. `egressEnforcement`, `allowedHosts`, and
    // `fileSystemAccess` are honest-signal fields — a config that asks for
    // network/filesystem confinement must get a hard refusal, not a process
    // that runs with full socket/fs access while the config reads as a
    // security guarantee. (Zero-day: these fields were declared but consumed
    // nowhere, so untrusted vendor/community adapters holding live
    // credentials ran completely unconfined.)
    this.assertConfinementEnforceable(key, config);

    log.info('creating sandbox', { adapter: key, mode, author: catalogEntry.author });

 // defense-in-depth: confine adapterPath to package root before
    // any sandbox subsystem dynamically imports it. The worker / process
    // child processes also re-confine; this is the first of two gates.
    const confined = confinePath(adapterPath, SANDBOX_PACKAGE_ROOT);
    if (!confined.ok) {
      throw new Error(`sandbox adapter path rejected: ${confined.reason} (${adapterPath})`);
    }
    const safeAdapterPath = confined.resolved;

    let sandbox: SandboxedAdapter;

    if (config.mode === 'worker-thread') {
      const ws = new WorkerSandbox(safeAdapterPath, config, credentials);
      await ws.start();
      sandbox = ws;
    } else if (config.mode === 'process') {
      const ps = new ProcessSandbox(safeAdapterPath, config, credentials);
      await ps.start();
      sandbox = ps;
    } else {
      // mode === 'none' — direct import, no isolation (dev only)
      type AdapterInstance = {
        tools: Tool[];
        callTool(name: string, args: Record<string, unknown>): Promise<ToolResult>;
        connect?(): Promise<void>;
        disconnect?(): Promise<void>;
      };
      type AdapterCtor = new (config: Record<string, string>) => AdapterInstance;
      // eslint-disable-next-line local/no-dynamic-module-specifier -- DYNAMIC_LOADER_SITES: adapter package path resolved from the signed catalog and confined by confinePath() to SANDBOX_PACKAGE_ROOT before this import
      const mod = await import(safeAdapterPath) as Record<string, unknown>;
      const AdapterClass = (mod.default ?? Object.values(mod)[0]) as AdapterCtor;
      const adapter = new AdapterClass(credentials);
      if (adapter.connect) await adapter.connect();
      sandbox = {
        listTools: () => Promise.resolve(adapter.tools),
        callTool: (name, args) => adapter.callTool(name, args),
        stop: async () => { if (adapter.disconnect) await adapter.disconnect(); },
      };
    }

    this.sandboxes.set(key, sandbox);
    return sandbox;
  }

  /**
   * Stop and remove a sandbox.
   */
  async destroy(adapterName: string): Promise<void> {
    const sandbox = this.sandboxes.get(adapterName);
    if (!sandbox) return;

    await sandbox.stop();
    this.sandboxes.delete(adapterName);
    log.info('sandbox destroyed', { adapter: adapterName });
  }

  /**
   * Stop all sandboxes.
   */
  async destroyAll(): Promise<void> {
    for (const [name, sandbox] of this.sandboxes) {
      try {
        await sandbox.stop();
      } catch (err) {
        log.warn('sandbox stop error', { adapter: name, error: String(err) });
      }
    }
    this.sandboxes.clear();
  }

  get activeCount(): number {
    return this.sandboxes.size;
  }

  /**
   * Reject any sandbox config that requests a confinement guarantee this
   * build does not actually implement. This is the enforcement half of the
   * honest-signal contract: rather than silently ignoring
   * `egressEnforcement` / `allowedHosts` / `fileSystemAccess` (which would
   * let untrusted adapter code run with full network + filesystem access
   * while the config claims otherwise), we fail closed.
   *
   * - worker-thread mode shares the host process entirely, so it CANNOT
   *   confine network or filesystem at all — any non-default confinement
   *   request is rejected.
   * - process mode does not (yet) apply an OS-level egress jail
   *   (netns+nftables / sandbox-exec) or a Node permission-model fs jail in
   *   this build, so a request for either is rejected rather than honored
   *   as a no-op.
   *
   * The default config (`egressEnforcement: 'none'`, `allowedHosts: []`,
   * `fileSystemAccess: 'none'`) declares NO confinement and is the operator's
   * explicit choice to run the adapter unconfined — that is permitted (with
   * a warning for untrusted authors) and is not a false guarantee.
   */
  private assertConfinementEnforceable(adapterName: string, config: AdapterSandboxConfig): void {
    const wantsEgressJail = config.egressEnforcement !== 'none' || config.allowedHosts.length > 0;
    const wantsFsJail = config.fileSystemAccess !== 'none';

    if (config.mode === 'worker-thread') {
      if (wantsEgressJail || wantsFsJail) {
        throw new Error(
          `sandbox "${adapterName}": worker-thread mode cannot enforce network or filesystem confinement ` +
          `(it shares the host process), but the config requests it ` +
          `(egressEnforcement=${config.egressEnforcement}, allowedHosts=${config.allowedHosts.length}, ` +
          `fileSystemAccess=${config.fileSystemAccess}). Refusing to run untrusted code while advertising ` +
          `confinement that is not applied. Use process mode with a supported enforcement mechanism, or set ` +
          `these fields to their unconfined defaults to acknowledge no confinement.`,
        );
      }
      return;
    }

    if (config.mode === 'process') {
      if (wantsEgressJail) {
        throw new Error(
          `sandbox "${adapterName}": egress confinement (egressEnforcement=${config.egressEnforcement}, ` +
          `allowedHosts=${config.allowedHosts.length}) is declared but this build does not implement an ` +
          `OS-level egress jail. Refusing to spawn with full network access while the config claims the ` +
          `adapter is network-confined. Implement the netns+nftables / sandbox-exec jail before enabling this, ` +
          `or set egressEnforcement='none' and allowedHosts=[] to acknowledge unconfined egress.`,
        );
      }
      if (wantsFsJail) {
        throw new Error(
          `sandbox "${adapterName}": filesystem confinement (fileSystemAccess=${config.fileSystemAccess}) is ` +
          `declared but this build does not implement a filesystem jail. Refusing to spawn with full ` +
          `filesystem access while the config claims it is confined. Implement the Node permission-model gate ` +
          `before enabling this, or set fileSystemAccess='none' to acknowledge unconfined filesystem access.`,
        );
      }
      return;
    }

    // mode === 'none' (dev-only direct import) — no isolation at all; any
    // confinement request is meaningless and must be rejected.
    if (wantsEgressJail || wantsFsJail) {
      throw new Error(
        `sandbox "${adapterName}": mode='none' performs a direct in-process import with no isolation, ` +
        `but the config requests network/filesystem confinement. Refusing to advertise confinement that ` +
        `cannot exist in this mode.`,
      );
    }
  }

  private modeForAuthor(author: AdapterCatalogEntry['author']): SandboxMode {
    switch (author) {
      case 'protectnil': return 'worker-thread';
      case 'vendor': return 'process';
      case 'community': return 'process';
      default: return 'process';
    }
  }
}
