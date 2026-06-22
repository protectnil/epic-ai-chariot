/**
 * @epicai/chariot — SandboxedMCPAdapter
 *
 * MCPAdapter shim that delegates every operation to a SandboxedAdapter
 * running in a worker-thread or child-process boundary. This lets
 * FederationManager hold a uniform `Map<string, MCPAdapter>` while
 * adapter execution is actually isolated from chariot's process.
 *
 * Trust boundary:
 *   - chariot main process (this shim runs here) ↔ worker/process boundary ↔ adapter code
 *
 * The shim itself does no business logic. Tools, results, and errors flow
 * through `SandboxedAdapter.callTool / listTools / stop` — those methods
 * cross the isolation boundary via the worker/process IPC protocol that
 * `WorkerSandbox` / `ProcessSandbox` implement.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { Tool, ToolResult, ConnectionStatus } from '../../types/index.js';
import type { MCPAdapter } from '../adapters/base.js';
import type { SandboxedAdapter } from './SandboxManager.js';
import type { SandboxMode } from './types.js';
import { createLogger } from '../../logger.js';

const log = createLogger('federation.sandbox.adapter');

/**
 * Read-through cache of tools to avoid an IPC round-trip on every
 * `listTools()`. Cleared on `disconnect()`. Tools are static per
 * adapter version, so a single fetch is sufficient.
 */
export class SandboxedMCPAdapter implements MCPAdapter {
  private _status: ConnectionStatus = 'disconnected';
  private cachedTools: Tool[] | null = null;

  constructor(
    public readonly name: string,
    private readonly sandboxed: SandboxedAdapter,
    public readonly mode: SandboxMode,
  ) {}

  get status(): ConnectionStatus {
    return this._status;
  }

  async connect(): Promise<void> {
    // `SandboxedAdapter` is produced by `SandboxManager.create()`, which
    // synchronously starts the worker / process. State transition only.
    this._status = 'connected';
    log.info('sandboxed adapter connected', { adapter: this.name, mode: this.mode });
  }

  async disconnect(): Promise<void> {
    this.cachedTools = null;
    try {
      await this.sandboxed.stop();
    } finally {
      this._status = 'disconnected';
      log.info('sandboxed adapter disconnected', { adapter: this.name });
    }
  }

  async listTools(): Promise<Tool[]> {
    if (this.cachedTools !== null) return this.cachedTools;
    const tools = await this.sandboxed.listTools();
    this.cachedTools = tools;
    return tools;
  }

  async callTool(toolName: string, args: Record<string, unknown>): Promise<ToolResult> {
    if (this._status !== 'connected') {
      throw new Error(`SandboxedMCPAdapter "${this.name}": callTool while ${this._status}`);
    }
    return this.sandboxed.callTool(toolName, args);
  }

  /**
   * Probe the sandbox boundary by issuing a cheap `listTools` and
   * timing the round-trip. Surfaces a worker/process that is alive
   * but stuck — the IPC round-trip is the signal.
   */
  async ping(): Promise<number> {
    const start = Date.now();
    await this.sandboxed.listTools();
    return Date.now() - start;
  }
}
