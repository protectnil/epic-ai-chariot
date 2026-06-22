/**
 * @epicai/chariot — Federation Manager
 * Manages connections to multiple MCP servers, provides unified tool discovery,
 * invocation, and cross-source correlation.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type {
  FederationConfig,
  ServerConnection,
  ConnectionHealth,
  Tool,
  ToolResult,
  CorrelationQuery,
  CorrelationResult,
  ObservabilityEmitterContract,
} from '../types/index.js';
import { ConnectionPool } from './ConnectionPool.js';
import { ToolRegistry } from './ToolRegistry.js';
import { Correlator } from './Correlator.js';
import type { MCPAdapter } from './adapters/base.js';
import type { AdapterCatalog, AdapterCatalogEntry } from './AdapterCatalog.js';
import type { SandboxManager } from './sandbox/SandboxManager.js';
import { SandboxedMCPAdapter } from './sandbox/SandboxedMCPAdapter.js';
import type { AdapterSandboxConfig } from './sandbox/types.js';
import { createLogger } from '../logger.js';
import { retryTelemetryStorage, type RetryTelemetryStore } from '../mcp-servers/base.js';
import { randomUUID } from 'node:crypto';
import { validateAgainstToolSchema, type ToolInputSchema } from './validateToolSchema.js';
import { createHash } from 'node:crypto';
import { canonicalStringify } from '../../util/canonical-json.js';

/**
 * minimal in-memory approval registry. Production deployments
 * wire a Mongo `approval_queue` collection via the same interface
 * (approve / has). Keyed by `${tenantId}:${adapterId}:${toolName}:${argsHash}`
 * so an approved call must match the exact tool + args fingerprint.
 */
export class ApprovalRegistry {
  protected approvals = new Set<string>();
  has(key: string): boolean { return this.approvals.has(key); }
  approve(key: string): void { this.approvals.add(key); }
  revoke(key: string): void { this.approvals.delete(key); }
 /** used by spawnSubAgent to snapshot keys for the child registry. */
  keys(): string[] { return [...this.approvals]; }
}

/**
 * sub-agent approval registry. Narrow-only: inherits a frozen
 * snapshot of the parent's approvals at spawn time; can revoke (narrow)
 * but cannot approve keys outside that snapshot (widening blocked).
 */
export class SubAgentApprovalRegistry extends ApprovalRegistry {
  private readonly frozenSnapshot: ReadonlySet<string>;
  constructor(snapshot: Iterable<string>) {
    super();
    const arr = [...snapshot];
    this.frozenSnapshot = new Set(arr);
    for (const k of arr) this.approvals.add(k);
  }
  approve(key: string): void {
    if (!this.frozenSnapshot.has(key)) {
      throw new Error(`SubAgentApprovalRegistry: cannot widen approval surface — key "${key}" not in parent snapshot`);
    }
    super.approve(key);
  }
}

/**
 * spawn a sub-agent context with an immutable approval-rule
 * manifest derived from the parent's registry. Hash is canonical-sorted
 * SHA-256 over the key list so identical key sets yield identical hashes.
 */
export function spawnSubAgent(params: {
  parentAgentId: string;
  parentRegistry: ApprovalRegistry;
  emitter?: ObservabilityEmitterContract;
}): { context: import('../types/index.js').SubAgentContext; registry: SubAgentApprovalRegistry } {
  const sortedKeys = params.parentRegistry.keys().slice().sort();
  const manifestHash = createHash('sha256')
    .update(canonicalStringify(sortedKeys))
    .digest('hex');
  const spawnedAt = new Date();
  const context: import('../types/index.js').SubAgentContext = {
    parentAgentId: params.parentAgentId,
    inheritedApprovalRules: new Set(sortedKeys),
    manifestHash,
    spawnedAt,
  };
  const registry = new SubAgentApprovalRegistry(sortedKeys);
  if (params.emitter) {
    params.emitter.emitSubAgentSpawn({
      parentAgentId: params.parentAgentId,
      manifestHash,
      ruleCount: sortedKeys.length,
      spawnedAt,
    });
  }
  return { context, registry };
}

const log = createLogger('federation.manager');

/**
 * Optional extensions to FederationManager construction. The catalog
 * enables runtime revocation enforcement: when set, the manager refuses
 * to connect to or call tools on adapters whose catalog entries are
 * marked `revoked: true`. If `catalog` is omitted, revocation checks
 * are skipped and revocation is not enforced.
 */
export interface FederationManagerOptions {
  /**
   * AdapterCatalog (already loaded) used to look up revocation state
   * at connect time and per-tool-call. Pass the same catalog instance
   * that AdapterCatalog.load() populated; revocations introduced via
   * refreshRevocations() after construction are honored on subsequent
   * calls because the isRevoked check reads live catalog state.
   */
  catalog?: AdapterCatalog;
  /**
   * SandboxManager used by `connectSandboxed()` to spawn each adapter
   * in an isolated worker-thread or child-process boundary. Omit for
   * deployments that do not isolate adapter execution. `connectSandboxed`
   * throws if invoked without a sandbox manager wired here.
   */
  sandbox?: SandboxManager;
  /**
 * optional ApprovalRegistry consulted on every callTool when the
   * catalog entry has requiresApproval=true. Pre-approved keys are
   * `${tenantId}:${adapterId}:${toolName}:${argsHash}` (SHA-256 of canonical
   * JSON). Omit to inherit the default in-memory registry — every call to
   * a requiresApproval tool will block until operator.approve() runs.
   */
  approvalRegistry?: ApprovalRegistry;
  /**
 * observability emitter wired into every adapter dispatch.
   * When set, callTool calls adapter.setObservabilityEmitter(...) before
   * invoking adapter.callTool, and wraps the call in
   * retryTelemetryStorage.run(...) so per-retry events fire and the
   * resulting ToolResult carries the rolled-up retryCount/retryReasons.
   */
  observabilityEmitter?: ObservabilityEmitterContract;
}

export class FederationManager {
  private readonly pool: ConnectionPool;
  private readonly registry: ToolRegistry;
  private readonly correlator: Correlator;
  private readonly config: FederationConfig;
  private readonly adapterMap = new Map<string, MCPAdapter>();
  private readonly serverConfigs = new Map<string, ServerConnection>();
  private readonly sandboxedAdapters = new Set<string>();
  /**
   * In-flight call counters for sandboxed adapters. The
   * ConnectionPool's beginCall/endCall infrastructure manages
   * pool-attached adapters; sandboxed adapters live outside the pool
   * (their lifecycle is owned by SandboxManager) so we track their
   * in-flight count here. Used by `waitForSandboxedQuiescence` for
   * revocation-drain symmetry with the pool-backed path
 * (Simplify R2 finding on ).
   */
  private readonly sandboxedInFlight = new Map<string, number>();
  private readonly catalog: AdapterCatalog | undefined;
  private readonly sandbox: SandboxManager | undefined;
 // observability emitter forwarded to adapters at dispatch time.
  private readonly observabilityEmitter: ObservabilityEmitterContract | undefined;
 // optional approval registry; defaults to a fresh in-memory one.
  private readonly approvalRegistry: ApprovalRegistry;

  constructor(config: FederationConfig, options: FederationManagerOptions = {}) {
    this.config = config;
    this.catalog = options.catalog;
    this.sandbox = options.sandbox;
    this.observabilityEmitter = options.observabilityEmitter;
    this.approvalRegistry = options.approvalRegistry ?? new ApprovalRegistry();
    this.pool = new ConnectionPool(
      config.retryPolicy,
      config.healthCheckIntervalMs,
    );
    this.registry = new ToolRegistry();
    this.correlator = new Correlator();
  }

 /** expose the approval registry so operators can pre-approve calls. */
  getApprovalRegistry(): ApprovalRegistry {
    return this.approvalRegistry;
  }

  // ---------------------------------------------------------------------------
 // Sandboxed adapter dispatch —   // ---------------------------------------------------------------------------

  /**
   * Connect to an adapter whose code is run inside an isolated worker
   * thread or child process. Requires `options.sandbox` to have been
   * passed to the constructor.
   *
   * The flow:
   *   1. SandboxManager.create() spawns the worker/process from
   *      `adapterPath` with `credentials` injected at the boundary.
   *      The chariot main process never sees the raw credential values
   *      after this point — they live only on the other side of the
   *      IPC boundary.
   *   2. SandboxedMCPAdapter wraps the resulting SandboxedAdapter so
   *      it looks like a regular MCPAdapter to the rest of federation.
   *   3. Connect, discover tools, register in the unified tool registry.
   *
   * Returns `this` for chaining. Throws when sandbox manager is not
   * wired or when the adapter's catalog entry is marked revoked.
   */
  async connectSandboxed(
    catalogEntry: AdapterCatalogEntry,
    adapterPath: string,
    credentials: Record<string, string>,
    sandboxConfig?: Partial<AdapterSandboxConfig>,
  ): Promise<this> {
    if (!this.sandbox) {
      throw new Error(
        `connectSandboxed("${catalogEntry.name}"): no SandboxManager wired at construction`,
      );
    }

    // Re-enter guard (Simplify P2 finding): repeated connectSandboxed
    // with the same name would orphan the prior shim and double-
    // register tools. Refuse the duplicate; caller must disconnect
    // first if they intend to replace.
    if (this.sandboxedAdapters.has(catalogEntry.name) || this.adapterMap.has(catalogEntry.name)) {
      throw new Error(
        `connectSandboxed("${catalogEntry.name}"): adapter already registered; disconnect first`,
      );
    }

    if (this.catalog?.isRevoked(catalogEntry.name)) {
      const details = this.catalog.getRevocationDetails(catalogEntry.name);
      log.warn('federation_manager.skipped_revoked_sandbox_connect', {
        adapterId: catalogEntry.name,
        reason: details?.reason,
        revokedAt: details?.revokedAt,
      });
      return this;
    }

    const sandboxed = await this.sandbox.create(
      catalogEntry,
      adapterPath,
      credentials,
      sandboxConfig,
    );

    const mode = sandboxConfig?.mode ?? 'process';
    const shim = new SandboxedMCPAdapter(catalogEntry.name, sandboxed, mode);
    await shim.connect();

    this.adapterMap.set(catalogEntry.name, shim);
    this.sandboxedAdapters.add(catalogEntry.name);
    this.sandboxedInFlight.set(catalogEntry.name, 0);

    // Discover and register tools (crosses the IPC boundary once).
    const tools = await shim.listTools();
    this.registry.registerServer(catalogEntry.name, tools);

    log.info('federation_manager.connected_sandboxed', {
      adapter: catalogEntry.name,
      mode,
      toolCount: tools.length,
    });

    return this;
  }

  /**
   * Return true when the named adapter was attached via
   * `connectSandboxed()` and is therefore running behind a worker /
   * process boundary. Returns false for stdio / REST adapters attached
   * via `connect()` and for unknown names.
   */
  isAdapterSandboxed(name: string): boolean {
    return this.sandboxedAdapters.has(name);
  }

  /**
   * Current in-flight call count for a sandboxed adapter. Returns 0
   * for non-sandboxed names (use `pool.inFlightCount` for those).
   * Exposed for tests + revocation drain.
   */
  sandboxedInFlightCount(name: string): number {
    return this.sandboxedInFlight.get(name) ?? 0;
  }

  /**
   * Poll the sandboxed in-flight counter until it reaches zero or
   * `maxMs` fires. Returns true on clean drain. Mirrors
   * `ConnectionPool.waitForQuiescence` for the sandboxed path so a
   * revocation-driven unload can wait for in-flight calls to finish
   * before destroying the worker.
   */
  async waitForSandboxedQuiescence(name: string, maxMs: number): Promise<boolean> {
    const deadline = Date.now() + maxMs;
    while (Date.now() < deadline) {
      if ((this.sandboxedInFlight.get(name) ?? 0) === 0) return true;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    return (this.sandboxedInFlight.get(name) ?? 0) === 0;
  }


  /** Expose the pool for callers that need to wire the egress engine
 *. Returns the same instance the manager dispatches against. */
  getPool(): ConnectionPool {
    return this.pool;
  }

  /**
   * Build a structured ToolResult representing a revoked-adapter refusal.
   * Shared helper so the exact shape stays consistent for every rejection
   * path.
   */
  private buildRevokedToolResult(
    tool: Tool,
    details: { revokedAt?: string; reason?: string } | undefined,
    startedAt: number,
  ): ToolResult {
    const reason = details?.reason ?? 'no reason recorded';
    const message = `Tool "${tool.name}" blocked: adapter "${tool.server}" is revoked in the catalog (${reason}).`;
    log.warn('federation_manager.blocked_revoked_call', {
      adapterId: tool.server,
      toolName: tool.name,
      reason: details?.reason,
      revokedAt: details?.revokedAt,
    });
    return {
      content: [{ type: 'text', text: message }],
      isError: true,
      server: tool.server,
      tool: tool.name,
      durationMs: Date.now() - startedAt,
 // revocation is an explicit catalog-level refusal.
      outcome: 'explicit_failure',
    } as ToolResult;
  }

  /**
   * Connect to a single MCP server.
   * Discovers tools and registers them in the unified catalog.
   */
  async connect(
    name: string,
    config: ServerConnection,
    adapterOrFactory?: MCPAdapter | ((config: ServerConnection) => MCPAdapter),
  ): Promise<this> {
    // Revocation gate: if a catalog was provided and the adapter is
    // marked revoked, refuse to connect at all. This prevents the
    // adapter from ever entering the adapterMap or the tool registry,
    // which is the strongest runtime containment the federation layer
    // can offer against a compromised or contradicted catalog entry.
    if (this.catalog?.isRevoked(name)) {
      const details = this.catalog.getRevocationDetails(name);
      log.warn('federation_manager.skipped_revoked_connect', {
        adapterId: name,
        reason: details?.reason,
        revokedAt: details?.revokedAt,
      });
      return this;
    }

    const serverConfig = { ...config, name };
    const adapter = await this.pool.connect(serverConfig, adapterOrFactory);

    this.adapterMap.set(name, adapter);
    this.serverConfigs.set(name, serverConfig);

    // Discover and register tools
    const tools = await adapter.listTools();
    this.registry.registerServer(name, tools);

    return this;
  }

  /**
   * Connect to all servers defined in the federation config.
   */
  async connectAll(): Promise<void> {
    const connectPromises = this.config.servers.map(server =>
      this.connect(server.name, server),
    );
    await Promise.allSettled(connectPromises);
  }

  /**
   * Disconnect from a specific server.
   */
  async disconnect(name: string): Promise<this> {
    this.registry.unregisterServer(name);
    this.adapterMap.delete(name);
    this.serverConfigs.delete(name);

    if (this.sandboxedAdapters.has(name)) {
      // Sandboxed adapters live outside the pool — shim.disconnect()
      // stops the worker/process via SandboxedAdapter.stop(), but the
      // SandboxManager bookkeeping (activeCount) is decremented via
      // SandboxManager.destroy().
      const shim = this.adapterMap.get(name);
      if (shim) {
        try { await shim.disconnect(); } catch (err) {
          log.warn('federation_manager.sandbox_disconnect_error', { adapter: name, error: String(err) });
        }
      }
      this.sandboxedAdapters.delete(name);
      this.sandboxedInFlight.delete(name);
      if (this.sandbox) {
        await this.sandbox.destroy(name).catch((err: unknown) => {
          log.warn('federation_manager.sandbox_destroy_error', { adapter: name, error: String(err) });
        });
      }
    } else {
      await this.pool.disconnect(name);
    }
    return this;
  }

  /**
   * Disconnect from all servers.
   */
  async disconnectAll(): Promise<void> {
    this.registry.clear();
    // Drain sandboxed adapters first — pool.disconnectAll() does not
    // know about them (they live in this.sandbox, not in the pool).
    // Failing to iterate this set leaks worker threads / child
 // processes (Simplify P1 finding on ).
    if (this.sandbox && this.sandboxedAdapters.size > 0) {
      const sandboxedNames = Array.from(this.sandboxedAdapters);
      for (const name of sandboxedNames) {
        const shim = this.adapterMap.get(name);
        if (shim) {
          try { await shim.disconnect(); } catch (err) {
            log.warn('federation_manager.sandbox_disconnect_all_error', { adapter: name, error: String(err) });
          }
        }
      }
      // Best-effort destroy across the whole sandbox manager — picks
      // up any sandbox the shim did not stop cleanly.
      await this.sandbox.destroyAll().catch((err: unknown) => {
        log.warn('federation_manager.sandbox_destroy_all_error', { error: String(err) });
      });
      this.sandboxedAdapters.clear();
      this.sandboxedInFlight.clear();
    }
    this.adapterMap.clear();
    this.serverConfigs.clear();
    await this.pool.disconnectAll();
  }

  /**
   * List all discovered tools across all connected servers (all tiers).
   */
  listTools(): Tool[] {
    return this.registry.listAll();
  }

  /**
   * List only orchestrated tools (eligible for SLM selection via pre-filter).
   */
  listOrchestratedTools(): Tool[] {
    return this.registry.listOrchestrated();
  }

  /**
   * List only direct tools (callable by explicit name, not sent to SLM).
   */
  listDirectTools(): Tool[] {
    return this.registry.listDirect();
  }

  /**
   * List tools from a specific server.
   */
  listToolsByServer(server: string): Tool[] {
    return this.registry.listByServer(server);
  }

  /**
   * Call a tool by name. Automatically routes to the correct server.
   * Validates required fields from the tool's parameters schema before dispatch.
   *
 * `tenantId`: the tenant on whose behalf the call is made.
   * Used for egress policy evaluation when the federation pool has been
   * wired with an AccessPolicyEngine. Defaults to
   * `process.env.CHARIOT_TENANT_ID` or 'local' for single-tenant
   * deployments and harness invocations.
   */
  async callTool(name: string, args: Record<string, unknown>, tenantId?: string): Promise<ToolResult> {
    const startedAt = Date.now();
    const effectiveTenantId = tenantId ?? process.env.CHARIOT_TENANT_ID ?? 'local';
    const tool = this.registry.get(name);
    if (!tool) {
      throw new Error(`Tool "${name}" not found in any connected server`);
    }

    // Revocation gate (defense in depth — connect() already skips revoked
    // adapters, but the catalog can be updated between connect time and
    // call time via a catalog refresh, so every call re-checks live
    // catalog state before dispatch).
    //
    // SCOPE LIMITATION (TOCTOU): This check runs BEFORE the dispatch.
    // Between the moment `this.catalog.isRevoked(tool.server)` returns
    // false and the moment the awaited `adapter.callTool(...)` below
    // completes, the catalog can be mutated by an async refresh. A
    // tool call that was already in flight at the moment of revocation
    // will complete normally — the vendor has already received the
    // request; the federation layer cannot retroactively cancel it.
    //
    // This is the intentional 1.1.0 boundary. The revocation gate in
    // 1.2.0 prevents NEW dispatch to revoked adapters; it does not
    // cancel in-flight invocations. Cooperative per-call cancellation
    // is planned for 1.2.0 as part of the runtime adapter unload work
    // (addressed in 1.4.0 with runtime unload). Until then,
    // users concerned about the in-flight window should (a) keep
    // revocation refresh intervals short and (b) ensure tool calls
    // have tight client-side timeouts so an in-flight call on a
    // just-revoked adapter does not linger past the refresh cadence.
    if (this.catalog?.isRevoked(tool.server)) {
      return this.buildRevokedToolResult(
        tool,
        this.catalog.getRevocationDetails(tool.server),
        startedAt,
      );
    }

 // per-tool input-schema validation gate. Reject malformed args
    // BEFORE dispatch to prevent the AgentProp-Bench 62% cascade rate.
    // Replaces the prior throw-Error-based "basic JSON Schema required-field
    // type checking" block — Zod's schema-build covers required-field presence
    // and type matching uniformly, and the result is returned as a structured
    // ToolResult rather than an unhandled exception.
    {
      const originalToolName = name.includes(':') ? name.split(':').slice(1).join(':') : name;
      const vAdapter = { id: tool.server, tools: [{ name: originalToolName, inputSchema: tool.parameters as unknown as ToolInputSchema | undefined }] };
      const verdict = validateAgainstToolSchema(vAdapter, originalToolName, args);
      if (!verdict.valid) {
 // emit a single telemetry event so operators can track the
        // cascade-prevention rate per AgentProp-Bench.
        if (this.observabilityEmitter) {
          this.observabilityEmitter.emitParameterValidationRejected({
            adapterId: tool.server,
            toolName: originalToolName,
            issues: verdict.errors,
          });
        }
        return {
          content: JSON.stringify({ error: 'invalid_arguments', adapter: tool.server, tool: originalToolName, issues: verdict.errors }),
          isError: true,
          server: tool.server,
          tool: originalToolName,
          durationMs: Date.now() - startedAt,
          outcome: 'explicit_failure',
 // spec §2.3 demands errorClass === 'invalid_arguments' on
          // parameter-validation rejection. Earlier commit 09ad692 stamped
          // 'validation'; the ErrorClass enum carries both 'validation' and
          // 'invalid_arguments' but the spec-literal value is 'invalid_arguments'.
          errorClass: 'invalid_arguments',
          retryCount: 0,
          retryReasons: [],
        } as ToolResult;
      }
    }

    const adapter = this.adapterMap.get(tool.server);
    if (!adapter) {
      throw new Error(`Server "${tool.server}" for tool "${name}" is not connected`);
    }

 // per-tool approval gate (Adaline mechanism 4). When the
    // catalog flags requiresApproval=true, block dispatch until a matching
    // pre-approval exists in the registry. ApprovalKey hashes (tenant,
    // adapter, tool, canonical args) so a different args payload must be
    // approved separately.
    const approvalCatalogEntry = this.catalog?.byName(tool.server);
    const requiresApproval = (approvalCatalogEntry as { requiresApproval?: boolean } | undefined)?.requiresApproval === true;
    if (requiresApproval) {
      const originalToolNameForApproval = name.includes(':') ? name.split(':').slice(1).join(':') : name;
      // Canonical-stringify so logically-identical arg objects with
      // different key order share an approval key.
      const argsHash = createHash('sha256').update(canonicalStringify(args ?? {})).digest('hex');
      const approvalKey = `${effectiveTenantId}:${tool.server}:${originalToolNameForApproval}:${argsHash}`;
      if (!this.approvalRegistry.has(approvalKey)) {
        if (this.observabilityEmitter) {
          this.observabilityEmitter.emitApprovalRequired({
            adapterId: tool.server,
            toolName: originalToolNameForApproval,
            tenantId: effectiveTenantId,
            argsHash,
            approvalKey,
          });
        }
        return {
          content: JSON.stringify({ error: 'approval_required', adapter: tool.server, tool: originalToolNameForApproval, approvalKey }),
          isError: true,
          server: tool.server,
          tool: originalToolNameForApproval,
          durationMs: Date.now() - startedAt,
          outcome: 'escalated',
          retryCount: 0,
          retryReasons: [],
        } as ToolResult;
      }
    }

    // Runtime unload gate (since 1.4.0). beginCall() atomically checks
    // that the adapter is in the `connected` state and increments the
    // in-flight counter. If the adapter has been marked `unloading`
    // between tool resolution and dispatch, beginCall returns false
    // and we return an error ToolResult instead of dispatching.
    //
    // This gate closes the TOCTOU window that L1 documented as a
    // scope limitation. Combined with `unloadAdapter()` below, a
    // revocation can now both (a) prevent new dispatches AND (b)
    // wait for in-flight calls to drain before closing the transport.
    // Sandboxed adapters live outside the ConnectionPool — their
    // shim's connect/disconnect lifecycle is owned by the
    // SandboxManager, so we skip pool.beginCall (which would refuse
    // because the pool never registered the shim) and use our own
    // sandboxedInFlight counter for drain symmetry.
    const isSandboxed = this.sandboxedAdapters.has(tool.server);
    if (isSandboxed) {
      this.sandboxedInFlight.set(
        tool.server,
        (this.sandboxedInFlight.get(tool.server) ?? 0) + 1,
      );
    } else if (!this.pool.beginCall(tool.server)) {
      return this.buildUnloadingToolResult(tool, startedAt);
    }

    const decrementSandboxedInFlight = (): void => {
      if (!isSandboxed) return;
      const current = this.sandboxedInFlight.get(tool.server) ?? 0;
      this.sandboxedInFlight.set(tool.server, Math.max(0, current - 1));
    };

 // Egress gate. For network-emitting transports, resolve
    // the destination from the stored ServerConnection and consult the
    // pool's egress policy engine.
    //
    // Stdio adapters are STILL evaluated (host='stdio:<adapter>',
    // protocol=undefined) so per-adapter allow/deny rules can gate
    // even non-network adapters — the policy may want to refuse
    // executing a specific stdio adapter under a specific tenant.
    //
    // FAIL-CLOSED: an unparseable URL on a non-stdio transport yields
    // a deny decision rather than silently bypassing the gate
    // (Simplify P1 finding). Stdio adapters synthesize their host.
    const serverConfig = this.serverConfigs.get(tool.server);
    const egressTarget = this.resolveEgressTargetOrDeny(tool.server, serverConfig);
    if (egressTarget !== 'skip') {
      const decision = this.pool.evaluateEgress({
        tenantId: effectiveTenantId,
        adapterName: tool.server,
        toolName: tool.name,
        host: egressTarget.host,
        port: egressTarget.port,
        protocol: egressTarget.protocol,
      });
      if (!decision.allow) {
        if (isSandboxed) decrementSandboxedInFlight();
        else this.pool.endCall(tool.server);
        return this.buildEgressBlockedToolResult(tool, decision, startedAt);
      }
    }

 // open a fresh per-call retry-telemetry store so concurrent
    // calls to the same shared adapter instance each get their own counter.
    // Duck-type setObservabilityEmitter so adapters that don't extend
    // MCPAdapterBase compile and behave as before (count stays at 0).
 // thread the per-tool FailurePolicy from the adapter catalog
    // entry (if present) into the retry-telemetry store so
    // fetchWithRetryTelemetry can consult it on each retryable hit.
    const catalogEntry = this.catalog?.byName(tool.server);
    const failurePolicy = (catalogEntry as { failurePolicy?: import('../types/index.js').FailurePolicy } | undefined)?.failurePolicy;
 // thread per-adapter timeoutMs from the catalog entry.
    const timeoutMs = (catalogEntry as { timeoutMs?: number } | undefined)?.timeoutMs;
 // when the catalog says the adapter/tool is not idempotent-safe
    // generate a stable Idempotency-Key for this dispatch. Retries within
    // fetchWithRetryTelemetry read the same key from the per-call store, so
    // every attempt (initial + N retries) deduplicates downstream.
    const idempotent = (catalogEntry as { idempotent?: import('../types/index.js').Idempotent } | undefined)?.idempotent;
    const needsKey = idempotent !== 'safe'; // 'unsafe' or 'unknown' or undefined (defensive)
    const idempotencyKey = needsKey
      ? `${effectiveTenantId}:${tool.server}:${randomUUID()}`
      : undefined;
    // Federation-level wall-clock guard. RetryTelemetryStore.timeoutMs
    // bounds each upstream request, but adapters with poll-until-done
    // loops can run unboundedly across many sub-fetches. The signal
    // threads through RetryTelemetryStore.parentSignal so every
    // per-attempt fetch aborts when the cap fires.
    const toolTimeoutMs = (catalogEntry as { toolTimeoutMs?: number } | undefined)?.toolTimeoutMs ?? 60_000;
    const federationController = new AbortController();
    const federationTimer = setTimeout(() => federationController.abort(), toolTimeoutMs);
    const store: RetryTelemetryStore = {
      retryCount: 0,
      retryReasons: [],
      adapterId: tool.server,
      toolName: name.includes(':') ? name.split(':').slice(1).join(':') : name,
      ...(failurePolicy ? { failurePolicy } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      ...(idempotencyKey !== undefined ? { idempotencyKey } : {}),
      parentSignal: federationController.signal,
    };
    const setter = (adapter as unknown as { setObservabilityEmitter?: (e: ObservabilityEmitterContract | undefined) => void }).setObservabilityEmitter;
    if (typeof setter === 'function') setter.call(adapter, this.observabilityEmitter);

    try {
      // Use the original tool name (without server prefix) for the MCP call
      const originalName = name.includes(':') ? name.split(':').slice(1).join(':') : name;
      try {
        const result = await retryTelemetryStorage.run(store, () => adapter.callTool(originalName, args));
        // Stamp the rolled-up retry counts onto the returned ToolResult.
 // default outcome from isError when the adapter didn't supply one.
 // when policy short-circuited the dispatch, outcome
        // overrides whatever the adapter set (escalated > stop > anything).
        const policyOutcome = store.policyDecision?.action === 'escalate' ? 'escalated' as const
          : store.policyDecision?.action === 'stop' ? 'stopped_by_policy' as const
          : undefined;
        // when the federation deadline aborted, force
        // outcome='timeout' so downstream audit/orchestrator consumers
        // see timeout semantics rather than the generic 'unknown'.
        const timeoutOutcome = store.errorClass === 'timeout' ? 'timeout' as const : undefined;
        return {
          ...result,
          retryCount: store.retryCount,
          retryReasons: store.retryReasons,
          outcome: policyOutcome ?? timeoutOutcome ?? result.outcome ?? (result.isError ? 'unknown' : 'success'),
 // thread the per-call errorClass classification from the
          // store (set inside fetchWithRetryTelemetry on retry exhaustion).
          ...(store.errorClass !== undefined ? { errorClass: store.errorClass } : {}),
 // when policy says stop, surface isError=true so callers
          // treat it as a failed call. Escalated outcomes keep the adapter's
          // own isError verdict.
          ...(store.policyDecision?.action === 'stop' ? { isError: true } : {}),
        };
      } catch (err) {
 // §4 step 7: failure path still surfaces retry metadata so a
        // retried-then-thrown call is not silently lost from observability.
 // thrown adapter errors classify as 'unknown' (post-state opaque)
        // unless they look like a timeout.
        const errMsg = err instanceof Error ? err.message : String(err);
        const isTimeout = err instanceof Error && err.name === 'AbortError';
        return {
          content: JSON.stringify({ error: errMsg }),
          isError: true,
          server: tool.server,
          tool: originalName,
          durationMs: Date.now() - startedAt,
          retryCount: store.retryCount,
          retryReasons: store.retryReasons,
          outcome: isTimeout ? 'timeout' : 'unknown',
 // failure-path classification — thrown AbortError →
          // 'timeout', other thrown errors → 'unknown' unless the in-flight
          // fetchWithRetry already stamped the store before the throw.
          errorClass: store.errorClass ?? (isTimeout ? 'timeout' : 'unknown'),
        };
      }
    } finally {
      clearTimeout(federationTimer);
      if (isSandboxed) decrementSandboxedInFlight();
      else this.pool.endCall(tool.server);
    }
  }

  /**
   * Resolve the egress destination tuple for a tool dispatch. Returns:
   *   - 'skip' when no ServerConnection is registered (e.g. a test
   *     harness adapter or a mock) — egress not enforced.
   *   - { host: 'stdio:<adapter>', protocol: undefined } for stdio
   *     adapters so per-adapter rules still fire.
   *   - { host: 'sandboxed:<adapter>', protocol: undefined } for
   *     sandboxed adapters (network is enforced inside the worker).
   *   - { host, port, protocol } parsed from URL for network adapters.
   *   - { host: '<unparseable>', protocol: undefined } when the URL
   *     cannot be parsed but transport is network — default-deny then
   *     catches it (FAIL-CLOSED, Simplify P1 finding).
   */
  private resolveEgressTargetOrDeny(
    adapterName: string,
    config: ServerConnection | undefined,
  ): { host: string; port?: number; protocol?: 'http' | 'https' } | 'skip' {
    if (this.sandboxedAdapters.has(adapterName)) {
      return { host: `sandboxed:${adapterName}` };
    }
    if (!config) return 'skip';
    if (config.transport === 'stdio') {
      return { host: `stdio:${adapterName}` };
    }
    if (!config.url) {
      return { host: '<unparseable>' };
    }
    try {
      const u = new URL(config.url);
      const protocol: 'http' | 'https' | undefined =
        u.protocol === 'http:' ? 'http'
        : u.protocol === 'https:' ? 'https'
        : undefined;
      const port = u.port ? Number(u.port) : undefined;
      return { host: u.hostname, port, protocol };
    } catch {
      return { host: '<unparseable>' };
    }
  }

  /**
   * Build a structured ToolResult representing an egress-blocked refusal.
   * Mirrors the revoked/unloading result shape so client error handling
   * stays uniform.
   */
  private buildEgressBlockedToolResult(
    tool: Tool,
    decision: { reason: string; ruleId?: string; host: string; port?: number; protocol?: 'http' | 'https' },
    startedAt: number,
  ): ToolResult {
    const dest = decision.protocol
      ? `${decision.protocol}://${decision.host}${decision.port ? ':' + decision.port : ''}`
      : decision.host;
    const ruleSuffix = decision.ruleId ? ` (rule ${decision.ruleId})` : '';
    const message = `Tool "${tool.name}" blocked: egress to ${dest} denied by policy${ruleSuffix}. ${decision.reason}`;
    log.warn('federation_manager.blocked_egress_call', {
      adapterId: tool.server,
      toolName: tool.name,
      destination: dest,
      ruleId: decision.ruleId,
      reason: decision.reason,
    });
    return {
      content: [{ type: 'text', text: message }],
      isError: true,
      server: tool.server,
      tool: tool.name,
      durationMs: Date.now() - startedAt,
 // explicit gateway-level refusal (egress policy / unloading).
      outcome: 'explicit_failure',
    } as ToolResult;
  }

  /**
   * Runtime adapter unload — L3 (1.4.0).
   *
   * Removes a single adapter from the federation without restarting
   * the process. The sequence is:
   *
   *   1. Mark the adapter as `unloading` in the pool. New dispatches
   *      via `callTool()` will now return an error ToolResult instead
   *      of routing to the adapter.
   *   2. Wait for in-flight calls to drain, bounded by
   *      `maxQuiescenceMs` (default 30s). Calls that started before
   *      step 1 run to completion — the federation layer does not
   *      cancel them.
   *   3. Close the transport via `ConnectionPool.disconnect()`,
   *      remove from `ToolRegistry`, remove from `adapterMap`.
   *
   * Returns a result object describing the outcome so the caller
   * (kill-list watcher, manual API, or a tool-layer admin call) can
   * log it.
   *
   * Unknown adapter names are a no-op — returns
   * `{ success: false, reason: 'unknown' }` without throwing.
   */
  async unloadAdapter(
    name: string,
    reason: string,
    options: { maxQuiescenceMs?: number } = {},
  ): Promise<{
    success: boolean;
    reason: string;
    quiescent: boolean;
    inFlightAtClose: number;
    durationMs: number;
    /**
     * When success is false AND the adapter was known, this carries
     * the underlying error message so operator tooling can surface
     * the reason (usually a transport close failure on the MCP
     * adapter's side). Undefined on success or when the adapter
     * was unknown.
     */
    error?: string;
  }> {
    const startedAt = Date.now();
    const maxQuiescenceMs = options.maxQuiescenceMs ?? 30_000;

    if (!this.adapterMap.has(name)) {
      return {
        success: false,
        reason: 'unknown',
        quiescent: true,
        inFlightAtClose: 0,
        durationMs: Date.now() - startedAt,
      };
    }

    log.info('federation_manager.unload.begin', { adapterId: name, reason });

    // Step 1: flip state so new dispatches are refused
    this.pool.markUnloading(name);

    // Step 2: wait for in-flight calls to drain
    const quiescent = await this.pool.waitForQuiescence(name, maxQuiescenceMs);
    const inFlightAtClose = this.pool.inFlightCount(name);

    if (!quiescent) {
      log.warn('federation_manager.unload.quiescence_timeout', {
        adapterId: name,
        maxQuiescenceMs,
        inFlightAtClose,
        note:
          'proceeding with transport close; in-flight calls will observe abort when their own adapter transport shuts down',
      });
    }

    // Step 3: tear down the registry + pool entries for this adapter.
    //
    // Order matters. We disconnect the transport FIRST so that any
    // failure surfaces as a caller-visible error on this function's
    // return value — if disconnect throws, the pool is left with the
    // adapter still in its map in the `unloading` state, which is
    // the recoverable failure state. Only after a clean disconnect
    // do we unregister from the registry and adapterMap. If we
    // unregistered first and disconnect then threw, we'd have a
    // tool-registry-clean-but-pool-stale inconsistency that no
    // caller could observe.
    let disconnectError: string | undefined;
    try {
      await this.pool.disconnect(name);
    } catch (err) {
      disconnectError = err instanceof Error ? err.message : String(err);
      log.error('federation_manager.unload.disconnect_failed', {
        adapterId: name,
        error: disconnectError,
        note: 'adapter remains in pool in unloading state; retry unload after investigating',
      });
    }

    if (disconnectError) {
      // Failed unload — do NOT remove from the registry or adapterMap.
      // The adapter is in a limbo state where new dispatches are
      // refused (pool.markUnloading is set) but the transport is
      // still present. A subsequent unloadAdapter call can retry.
      const durationMs = Date.now() - startedAt;
      return {
        success: false,
        reason,
        quiescent,
        inFlightAtClose,
        durationMs,
        error: disconnectError,
      };
    }

    // Clean disconnect — remove registry + map entries
    this.registry.unregisterServer(name);
    this.adapterMap.delete(name);

    const durationMs = Date.now() - startedAt;
    log.info('federation_manager.unload.complete', {
      adapterId: name,
      reason,
      quiescent,
      inFlightAtClose,
      durationMs,
    });

    return {
      success: true,
      reason,
      quiescent,
      inFlightAtClose,
      durationMs,
    };
  }

  /**
   * Build an error ToolResult for a call that arrived during an
   * active unload. Same shape as the revocation refusal — callers
   * handling errors should not need to distinguish the two cases.
   */
  private buildUnloadingToolResult(tool: Tool, startedAt: number): ToolResult {
    const message = `Tool "${tool.name}" blocked: adapter "${tool.server}" is currently unloading from the federation. Retry after the unload completes, or resolve the underlying revocation.`;
    log.warn('federation_manager.blocked_unloading_call', {
      adapterId: tool.server,
      toolName: tool.name,
    });
    return {
      content: [{ type: 'text', text: message }],
      isError: true,
      server: tool.server,
      tool: tool.name,
      durationMs: Date.now() - startedAt,
 // explicit gateway-level refusal (egress policy / unloading).
      outcome: 'explicit_failure',
    } as ToolResult;
  }

  /**
   * Correlate entities and events across connected servers.
   */
  async correlate(query: CorrelationQuery): Promise<CorrelationResult> {
    return this.correlator.correlate(query, this.adapterMap);
  }

  /**
   * Get health status of all connections.
   */
  async health(): Promise<ConnectionHealth[]> {
    return this.pool.health();
  }

  /**
   * Synchronous, in-memory health lookup for one server. Pass-through
   * to ConnectionPool.getHealthByServer. Used by the runtime
   * tool-shortlist health filter that runs on every query and needs
   * a non-blocking lookup. Returns `undefined` when no adapter is
   * registered under that name.
   */
  getHealthByServer(server: string): ConnectionHealth | undefined {
    return this.pool.getHealthByServer(server);
  }

  /**
   * Register a callback for health status changes.
   */
  onHealthChange(callback: (health: ConnectionHealth) => void): void {
    this.pool.onHealthChange(callback);
  }

  /**
   * Start periodic health monitoring.
   */
  startHealthCheck(): void {
    this.pool.startHealthCheck();
  }

  /**
   * Stop periodic health monitoring.
   */
  stopHealthCheck(): void {
    this.pool.stopHealthCheck();
  }

  /**
   * Number of connected servers.
   */
  get serverCount(): number {
    return this.pool.size;
  }

  /**
   * List the names of all currently-connected adapters. Used by
   * KillListWatcher (L3, 1.4.0) to diff against an incoming kill
   * list. Stable snapshot — mutations to the pool after this call
   * do not affect the returned array.
   */
  serverNames(): string[] {
    return this.pool.serverNames();
  }

  /**
   * Total number of discovered tools.
   */
  get toolCount(): number {
    return this.registry.size;
  }
}

