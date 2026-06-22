/**
 * @epicai/chariot — Connection Pool
 * Manages N concurrent MCP server connections with retry and health monitoring.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type {
  ServerConnection,
  RetryPolicy,
  ConnectionHealth,
} from '../types/index.js';
import type { MCPAdapter } from './adapters/base.js';
import { MCPClientAdapter } from './adapters/MCPClientAdapter.js';
import type { AccessPolicyEngine } from '../trust/AccessPolicyEngine.js';
import type { EgressContext, EgressDecision } from '../trust/types.js';
import { createLogger } from '../logger.js';

const egressLog = createLogger('federation.connection-pool.egress');

const DEFAULT_RETRY: RetryPolicy = {
  maxRetries: 3,
  backoffMs: 1000,
  maxBackoffMs: 30000,
};

const DEFAULT_HEALTH_CHECK_INTERVAL_MS = 30000;

/**
 * Per-adapter connection state. Most adapters live in `connected` for
 * their entire lifetime. `unloading` is a transient state set by
 * `markUnloading()` when the federation layer decides to kick an
 * adapter out of the pool without restarting the process. In the
 * `unloading` state, new dispatches are refused but in-flight calls
 * are allowed to drain.
 */
export type AdapterConnectionState = 'connected' | 'unloading' | 'disconnected';

export class ConnectionPool {
  private readonly adapters = new Map<string, MCPAdapter>();
  private readonly adapterStates = new Map<string, AdapterConnectionState>();
  /**
   * In-flight tool-call counter per adapter. Incremented at the start
   * of every `beginCall()` and decremented at the end of `endCall()`.
   * Used by `waitForQuiescence()` to poll for drain.
   */
  private readonly inFlightCounts = new Map<string, number>();
  private readonly retryPolicy: RetryPolicy;
  private readonly healthCheckIntervalMs: number;
  private healthCheckTimer: ReturnType<typeof setInterval> | null = null;
  private readonly healthCallbacks: ((health: ConnectionHealth) => void)[] = [];
  /**
 * Optional egress policy engine. When set, the federation
   * layer calls `evaluateEgress()` before every outbound adapter
   * dispatch and refuses to begin the call when the policy denies.
   * When unset, egress is unrestricted — callers are responsible for
   * supplying the engine through `setAccessPolicyEngine()` or at
   * construction time when enterprise IAM is in effect.
   */
  private accessPolicyEngine: AccessPolicyEngine | null = null;
  /**
   * Audit callbacks fired on every egress decision. Two classes:
   *   - critical: must succeed; a throw aborts the dispatch with a
   *     synthetic egress-deny. The hash-chained audit trail subscribes
   *     here so a misbehaving auditor is a hard failure, not a silent
   *     gap. Use sparingly.
   *   - bestEffort: errors logged and swallowed. Use for metrics,
   *     non-load-bearing telemetry, debugging hooks.
   */
  private readonly criticalEgressAuditors: ((decision: EgressDecision, ctx: EgressContext) => void)[] = [];
  private readonly egressAuditCallbacks: ((decision: EgressDecision, ctx: EgressContext) => void)[] = [];
  /**
   * When true, evaluateEgress with no engine wired returns a synthetic
   * deny decision. Enterprise deployments set this so a bootstrap that
   * forgets `setAccessPolicyEngine` cannot silently collapse to
   * open-source allow-all semantics (Simplify P2 finding).
   */
  private requirePolicyEngine = false;

  constructor(
    retryPolicy?: RetryPolicy,
    healthCheckIntervalMs?: number,
    accessPolicyEngine?: AccessPolicyEngine,
  ) {
    this.retryPolicy = retryPolicy ?? DEFAULT_RETRY;
    this.healthCheckIntervalMs = healthCheckIntervalMs ?? DEFAULT_HEALTH_CHECK_INTERVAL_MS;
    this.accessPolicyEngine = accessPolicyEngine ?? null;
  }

  /**
   * Lock the pool into enterprise mode. After this returns, any
   * evaluateEgress() call with no policy engine wired returns
   * `allow=false`. Idempotent. Call from enterprise IAM bootstrap.
   */
  requirePolicyEngineWired(): void {
    this.requirePolicyEngine = true;
  }

  /**
   * Inject (or replace) the egress policy engine after construction.
   * Used by FederationManager when the trust layer is initialized
   * lazily.
   */
  setAccessPolicyEngine(engine: AccessPolicyEngine | null): void {
    this.accessPolicyEngine = engine;
  }

  /**
   * Evaluate whether an outbound dispatch to `ctx` is allowed.
   *
   * Returns an EgressDecision. When no policy engine has been wired
   * (the default for the open-source single-tenant gateway), the call
   * is allowed with `reason: 'no policy engine configured'` — egress
   * gating is an enterprise IAM feature that requires a deliberate
   * `setAccessPolicyEngine` call to activate.
   *
   * Federation-layer callers MUST invoke this before any
   * `adapter.callTool(...)` that crosses the network boundary. Stdio
   * MCP adapters and in-process REST adapters that do not emit
   * outbound network calls should pass a synthetic `host: 'local'` or
   * SKIP the check entirely — the latter is preferred for clarity.
   *
   * On deny, every registered audit callback is invoked synchronously
   * with the decision and the context. Callbacks must not throw —
   * those are swallowed to keep the network path resilient.
   */
  evaluateEgress(ctx: EgressContext): EgressDecision {
    if (!this.accessPolicyEngine) {
      if (this.requirePolicyEngine) {
        egressLog.error('egress.no_engine_in_enterprise_mode', {
          tenantId: ctx.tenantId, adapter: ctx.adapterName, host: ctx.host,
        });
        const enterpriseSynthetic: EgressDecision = {
          allow: false,
          reason: 'policy engine required but not configured',
          host: ctx.host,
          port: ctx.port,
          protocol: ctx.protocol,
        };
        // Route enterprise-mode synthetic deny through critical auditors
        // so hash-chained audit captures the no-engine deny event
        // (Simplify R2 minor finding).
        for (const cb of this.criticalEgressAuditors) {
          try { cb(enterpriseSynthetic, ctx); } catch (err) {
            egressLog.error('egress.critical_audit_failed_on_synthetic', { error: String(err) });
          }
        }
        return enterpriseSynthetic;
      }
      return {
        allow: true,
        reason: 'no policy engine configured',
        host: ctx.host,
        port: ctx.port,
        protocol: ctx.protocol,
      };
    }
    const decision = this.accessPolicyEngine.evaluateEgress(ctx);
    // Critical auditors first — a throw here converts to a synthetic
    // egress-deny rather than letting the dispatch proceed with a
    // missing audit record. Hash-chain audit must be in this class.
    for (const cb of this.criticalEgressAuditors) {
      try {
        cb(decision, ctx);
      } catch (err) {
        egressLog.error('egress.critical_audit_failed', {
          error: String(err),
          tenantId: ctx.tenantId,
          adapter: ctx.adapterName,
          host: ctx.host,
        });
        return {
          allow: false,
          reason: `critical egress auditor failed: ${String(err)}`,
          host: ctx.host,
          port: ctx.port,
          protocol: ctx.protocol,
        };
      }
    }
    for (const cb of this.egressAuditCallbacks) {
      try {
        cb(decision, ctx);
      } catch (err) {
        egressLog.error('egress.audit_callback_error', { error: String(err) });
      }
    }
    if (!decision.allow) {
      egressLog.warn('egress.blocked', {
        tenantId: ctx.tenantId,
        adapter: ctx.adapterName,
        tool: ctx.toolName,
        host: ctx.host,
        port: ctx.port,
        protocol: ctx.protocol,
        ruleId: decision.ruleId,
        reason: decision.reason,
      });
    }
    return decision;
  }

  /**
   * Register an audit listener invoked on every egress decision (allow
   * AND deny). Returns an unsubscribe function. The hash-chained audit
   * trail subscribes here so every blocked outbound is recorded.
   */
  onEgressDecision(callback: (decision: EgressDecision, ctx: EgressContext) => void): () => void {
    this.egressAuditCallbacks.push(callback);
    return () => {
      const idx = this.egressAuditCallbacks.indexOf(callback);
      if (idx !== -1) this.egressAuditCallbacks.splice(idx, 1);
    };
  }

  /**
   * Register a CRITICAL audit listener. A throw from any critical
   * auditor converts the dispatch into a synthetic egress-deny —
   * dispatches proceed only when every critical auditor has
   * succeeded. Use for hash-chain audit, legal/forensic recording,
   * any audit-of-record listener whose failure must not silently
   * leak a network call.
   */
  onCriticalEgressDecision(callback: (decision: EgressDecision, ctx: EgressContext) => void): () => void {
    this.criticalEgressAuditors.push(callback);
    return () => {
      const idx = this.criticalEgressAuditors.indexOf(callback);
      if (idx !== -1) this.criticalEgressAuditors.splice(idx, 1);
    };
  }

  /**
   * Connect to an MCP server with retry logic.
   * Accepts an optional custom adapter or factory function.
   * If not provided, defaults to MCPClientAdapter.
   */
  async connect(
    config: ServerConnection,
    adapterOrFactory?: MCPAdapter | ((config: ServerConnection) => MCPAdapter),
  ): Promise<MCPAdapter> {
    if (this.adapters.has(config.name)) {
      throw new Error(`Server "${config.name}" is already connected`);
    }

    // Factory function for creating fresh adapter instances on each retry.
    // Avoids retry-state leakage from partially initialized adapters.
    const createAdapter = (): MCPAdapter => {
      if (adapterOrFactory) {
        return typeof adapterOrFactory === 'function' ? adapterOrFactory(config) : adapterOrFactory;
      }
      return new MCPClientAdapter(config);
    };

    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.retryPolicy.maxRetries; attempt++) {
      // Fresh adapter per attempt — no leaked transport/client state from prior failures
      const adapter = createAdapter();
      try {
        await adapter.connect();
        this.adapters.set(config.name, adapter);
        this.adapterStates.set(config.name, 'connected');
        this.inFlightCounts.set(config.name, 0);
        this.emitHealth(config.name, adapter);
        return adapter;
      } catch (error) {
        // Clean up failed adapter to release any partial resources
        try { await adapter.disconnect(); } catch { /* best effort cleanup */ }
        lastError = error instanceof Error ? error : new Error(String(error));

        if (attempt < this.retryPolicy.maxRetries) {
          const backoff = Math.min(
            this.retryPolicy.backoffMs * Math.pow(2, attempt),
            this.retryPolicy.maxBackoffMs ?? 30000,
          );
          await this.sleep(backoff);
        }
      }
    }

    throw new Error(
      `Failed to connect to server "${config.name}" after ${this.retryPolicy.maxRetries + 1} attempts: ${lastError?.message}`,
    );
  }

  /**
   * Disconnect from a specific server.
   * Clears state tracking in addition to closing the transport.
   */
  async disconnect(name: string): Promise<void> {
    const adapter = this.adapters.get(name);
    if (!adapter) return;

    await adapter.disconnect();
    this.adapters.delete(name);
    this.adapterStates.set(name, 'disconnected');
    this.inFlightCounts.delete(name);
  }

  // ---------------------------------------------------------------------------
  // Runtime unload state machine (since 1.4.0)
  // ---------------------------------------------------------------------------

  /**
   * Return the connection state of a specific adapter.
   *
   *   - `connected` — normal operation, tool calls dispatch normally
   *   - `unloading` — federation layer has decided to kick this
   *     adapter; new dispatches are refused, in-flight calls drain
   *   - `disconnected` — adapter has been fully removed from the pool
   *   - `undefined` — adapter was never in the pool
   */
  stateOf(name: string): AdapterConnectionState | undefined {
    return this.adapterStates.get(name);
  }

  /**
   * Mark an adapter as `unloading`. This is a synchronous flag flip
   * — it does NOT close the transport or remove the adapter from the
   * pool. After calling this, the caller is expected to:
   *
   *   1. Stop routing new dispatches to this adapter (the
   *      federation-layer caller in `FederationManager.callTool`
   *      checks `stateOf(name) === 'unloading'` and returns an error
   *      ToolResult before incrementing the in-flight counter).
   *   2. Call `waitForQuiescence(name, maxMs)` to wait for in-flight
   *      calls to drain.
   *   3. Call `disconnect(name)` to close the transport and fully
   *      remove the adapter.
   *
   * Idempotent. Calling `markUnloading` on an already-unloading or
   * disconnected adapter is a no-op.
   */
  markUnloading(name: string): void {
    const current = this.adapterStates.get(name);
    if (current === undefined || current === 'disconnected') return;
    if (current === 'unloading') return;
    this.adapterStates.set(name, 'unloading');
  }

  /**
   * Poll the in-flight counter for an adapter until it reaches zero
   * or the deadline fires. Returns `true` when quiescence was reached
   * cleanly, `false` when the deadline was exceeded (caller may then
   * force a disconnect with in-flight calls still pending — those
   * calls will see their own transport close with an abort).
   *
   * Polls at 50ms intervals. The bound is coarse by design — in-flight
   * tool calls have their own timeouts (typically 10-60 seconds at
   * the adapter level), so a 30-second quiescence deadline is usually
   * generous. Callers that want a tighter window can pass a smaller
   * `maxMs`.
   */
  async waitForQuiescence(name: string, maxMs: number): Promise<boolean> {
    const deadline = Date.now() + maxMs;
    while (Date.now() < deadline) {
      const count = this.inFlightCounts.get(name) ?? 0;
      if (count === 0) return true;
      await this.sleep(50);
    }
    return (this.inFlightCounts.get(name) ?? 0) === 0;
  }

  /**
   * Bracket helper — increment the in-flight counter for an adapter
   * before dispatching a tool call. Pairs with `endCall(name)`. The
   * federation layer wraps every `adapter.callTool(...)` in this
   * bracket so the pool always has an accurate drain count.
   *
   * Returns `false` if the adapter is in the `unloading` or
   * `disconnected` state — the caller should NOT dispatch in that
   * case, and should instead return an error ToolResult. Returns
   * `true` when the dispatch is allowed to proceed; the caller must
   * call `endCall(name)` in a `finally` block.
   */
  beginCall(name: string): boolean {
    const state = this.adapterStates.get(name);
    if (state !== 'connected') return false;
    const current = this.inFlightCounts.get(name) ?? 0;
    this.inFlightCounts.set(name, current + 1);
    return true;
  }

  /**
   * Bracket helper — decrement the in-flight counter. Always called
   * in a `finally` block after a successful `beginCall`, regardless
   * of whether the dispatch succeeded or threw. Safe against
   * underflow (clamps at 0).
   */
  endCall(name: string): void {
    const current = this.inFlightCounts.get(name) ?? 0;
    if (current <= 1) {
      this.inFlightCounts.set(name, 0);
      return;
    }
    this.inFlightCounts.set(name, current - 1);
  }

  /**
   * Current in-flight call count for an adapter. Exposed for tests
   * and observability. Callers outside the pool should not mutate
   * this — use `beginCall` / `endCall` instead.
   */
  inFlightCount(name: string): number {
    return this.inFlightCounts.get(name) ?? 0;
  }

  /**
   * Disconnect from all servers and stop health monitoring.
   */
  async disconnectAll(): Promise<void> {
    this.stopHealthCheck();

    const disconnects = Array.from(this.adapters.values()).map(a => a.disconnect());
    await Promise.allSettled(disconnects);
    this.adapters.clear();
    this.adapterStates.clear();
    this.inFlightCounts.clear();
  }

  /**
   * Get an adapter by server name.
   */
  get(name: string): MCPAdapter | undefined {
    return this.adapters.get(name);
  }

  /**
   * Synchronous, in-memory health lookup for a single server.
   *
   * Returns the cached `MCPAdapter.status` without issuing a fresh
   * ping. Used by the runtime tool-shortlist health filter, which
   * runs on every query and cannot afford a network probe per tool.
   * The pool's periodic health check (`startHealthCheck`) keeps
   * `adapter.status` reasonably current; consumers that need a fresh
   * probe can still call `health()`.
   *
   * Returns `undefined` when no adapter is registered under that name —
   * callers should treat this as "unknown" (do not exclude from
   * selection on absent registration).
   */
  getHealthByServer(server: string): ConnectionHealth | undefined {
    const adapter = this.adapters.get(server);
    if (!adapter) return undefined;
    return {
      server,
      status: adapter.status,
      toolCount: 0,
    };
  }

  /**
   * Get health status of all connections.
   */
  async health(): Promise<ConnectionHealth[]> {
    const results: ConnectionHealth[] = [];

    for (const [name, adapter] of this.adapters) {
      let lastPingMs: number | undefined;
      let lastError: string | undefined;
      let toolCount = 0;

      try {
        lastPingMs = await adapter.ping();
        const tools = await adapter.listTools();
        toolCount = tools.length;
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
      }

      results.push({
        server: name,
        status: adapter.status,
        lastPingMs,
        lastError,
        toolCount,
      });
    }

    return results;
  }

  /**
   * Start periodic health checks.
   */
  startHealthCheck(): void {
    if (this.healthCheckTimer) return;

    this.healthCheckTimer = setInterval(() => {
      void (async () => {
        for (const [name, adapter] of this.adapters) {
          try {
            await adapter.ping();
          } catch {
            this.emitHealth(name, adapter);
          }
        }
      })();
    }, this.healthCheckIntervalMs);

    // Don't block process exit
    if (this.healthCheckTimer.unref) {
      this.healthCheckTimer.unref();
    }
  }

  /**
   * Stop periodic health checks.
   */
  stopHealthCheck(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
  }

  /**
   * Register a callback for health status changes.
   * Returns an unsubscribe function.
   */
  onHealthChange(callback: (health: ConnectionHealth) => void): () => void {
    this.healthCallbacks.push(callback);
    return () => this.offHealthChange(callback);
  }

  /**
   * Deregister a health change callback by reference.
   */
  offHealthChange(callback: (health: ConnectionHealth) => void): void {
    const idx = this.healthCallbacks.indexOf(callback);
    if (idx !== -1) this.healthCallbacks.splice(idx, 1);
  }

  /**
   * Number of connected servers.
   */
  get size(): number {
    return this.adapters.size;
  }

  /**
   * List all connected server names.
   */
  serverNames(): string[] {
    return Array.from(this.adapters.keys());
  }

  private emitHealth(name: string, adapter: MCPAdapter): void {
    const health: ConnectionHealth = {
      server: name,
      status: adapter.status,
      toolCount: 0,
    };

    for (const cb of this.healthCallbacks) {
      try {
        cb(health);
      } catch {
        // Don't let callback errors break health monitoring
      }
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
