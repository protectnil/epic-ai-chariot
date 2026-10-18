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
import { NO_RETRY_FAILURE_POLICY } from '../types/index.js';
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
import { RateLimiter, type RateLimitConfig } from '../resilience/RateLimiter.js';
import { ErrorClassifier } from '../resilience/ErrorClassifier.js';
import { randomUUID } from 'node:crypto';
import { validateAgainstToolSchema, type ToolInputSchema } from './validateToolSchema.js';
import { createHash } from 'node:crypto';
import { canonicalStringify } from '../../util/canonical-json.js';
import { AccessPolicyEngine } from '../trust/AccessPolicyEngine.js';
import type { AdapterVerificationLookup, EgressRule, PrincipalType, TenantContext } from '../trust/types.js';
// Anomaly-detector dispatch wiring (T4). Imported from the observability
// barrel (NOT '../../index.js'/src/index.ts) — src/index.ts re-exports
// `./engine/index.js`, which re-exports FederationManager itself, so
// importing the top-level package barrel here would be a circular
// import. '../../observability/index.js' has no dependency on `engine`
// at all, so it is cycle-free.
import { reportToolDispatch } from '../../observability/index.js';
// CHARIOT::§16.1 Federation (rulings item 91/105) — the customer-facing
// event bus. Imported directly from emitter.js (not the observability
// barrel above) to match this repo's established direct-import pattern
// for chariotEmitter (see src/catalog/VerifiedCatalog.ts,
// src/iam/services/mfa.ts, src/license/loader.ts) and because emitter.ts
// has no dependency back on `engine`, so this import is cycle-free the
// same way the barrel import above is.
import { chariotEmitter } from '../../observability/emitter.js';

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
 * Parse a `ServerConnection.url` into the `{ host, port, protocol }`
 * tuple used for egress evaluation. Shared by `resolveEgressTargetOrDeny`
 * (per-dispatch, at call time) and `buildInstalledAdapterEgressAllowlist`
 * (per-adapter, at construction time) so the seeded allow-rule's host
 * pattern is guaranteed to match what dispatch will actually ask for —
 * one parse implementation, not two that could drift apart. Returns
 * `undefined` for a missing or unparseable URL; callers decide the
 * fail-closed behavior (dispatch denies via '<unparseable>'; seeding
 * simply emits no rule for that adapter).
 */
function parseNetworkEgressTarget(
  url: string | undefined,
): { host: string; port?: number; protocol?: 'http' | 'https' } | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    const protocol: 'http' | 'https' | undefined =
      u.protocol === 'http:' ? 'http'
      : u.protocol === 'https:' ? 'https'
      : undefined;
    const port = u.port ? Number(u.port) : undefined;
    return { host: u.hostname, port, protocol };
  } catch {
    return undefined;
  }
}

/**
 * Auto-generate egress allow-rules for the adapters declared in
 * `FederationConfig.servers` at construction time. Used ONLY by the
 * FederationManager constructor when the caller omits `egressPolicy`
 * entirely — see the egress-synthesis comment there for the regression
 * this closes (default-deny-with-zero-rules blocked a deployment's own
 * installed adapters out of the box).
 *
 * `config.servers` is exactly the adapter list `connectAll()` dispatches
 * to, so it doubles as "the adapters the operator installed." Each
 * server gets AT MOST one narrow allow rule, scoped to BOTH its own
 * adapter name (`adapters: [name]`) and its own declared destination
 * (`hostPatterns: [host]`) — so this can never become a blanket
 * any-adapter-to-any-installed-host rule; adapter A's dispatches cannot
 * ride adapter B's allow-rule to reach B's host.
 *
 * - `stdio` adapters: allowed at the synthetic `stdio:<name>` host that
 *   `resolveEgressTargetOrDeny` emits for stdio transports (stdio
 *   dispatch IS evaluated by `evaluateEgress` — see that method's doc
 *   comment — so under a zero-rule default it would otherwise be denied
 *   too).
 * - `streamable-http` adapters: allowed at the hostname parsed from
 *   `server.url` via the same `parseNetworkEgressTarget` dispatch will
 *   use. A server with a missing/unparseable URL gets NO rule — nothing
 *   safe to allowlist for a target that can't be resolved; the existing
 *   FAIL-CLOSED '<unparseable>' dispatch-time path is what should (and
 *   will) deny it.
 */
/**
 * Extracts the tool-name half of a combined `"${adapterId}:${toolName}"`
 * string (the shape BM25 routing / chariot_call names emit — CH-22).
 *
 * FIX (2026-09-30, release-blocking): the prior expression at all 4 call
 * sites below — `name.includes(':') ? name.split(':').slice(1).join(':')
 * : name` — assumed the adapter id ITSELF contains no colon, dropping
 * only the first segment. True for every catalog adapter id, but FALSE
 * for a discovered adapter's `discovered:<serviceId>` operational-
 * namespace prefix (src/engine/federation/configuredAdapterIds.ts) — for
 * `"discovered:server-abc123:get_widgets"` the old expression returned
 * `"server-abc123:get_widgets"` instead of `"get_widgets"`, so dispatch
 * failed "Unknown tool" even after routing correctly picked the adapter
 * and tool. `knownAdapterId` (always available at each call site as
 * `tool.server`) gives the EXACT boundary regardless of how many colons
 * the id itself contains — this never has to guess.
 */
function toolNameFromCombinedName(name: string, knownAdapterId: string): string {
  if (name.startsWith(`${knownAdapterId}:`)) {
    return name.slice(knownAdapterId.length + 1);
  }
  return name.includes(':') ? name.split(':').slice(1).join(':') : name;
}

export function buildInstalledAdapterEgressAllowlist(servers: ServerConnection[]): EgressRule[] {
  const rules: EgressRule[] = [];
  for (const server of servers) {
    if (server.transport === 'stdio') {
      rules.push({
        id: `auto-allow:${server.name}`,
        effect: 'allow',
        priority: 0,
        adapters: [server.name],
        hostPatterns: [`stdio:${server.name}`],
      });
      continue;
    }
    if (server.transport === 'streamable-http') {
      const target = parseNetworkEgressTarget(server.url);
      if (!target) continue;
      rules.push({
        id: `auto-allow:${server.name}`,
        effect: 'allow',
        priority: 0,
        adapters: [server.name],
        hostPatterns: [target.host],
        ...(target.protocol ? { protocols: [target.protocol] } : {}),
      });
    }
  }
  return rules;
}

/**
 * §8.7::5 — conservative default per-server token-bucket rate applied when
 * a FederationManagerOptions caller supplies no `rateLimit`. There is no
 * existing per-server-limit config surface on `FederationConfig` today
 * (`FailurePolicy.onRateLimit` is a per-tool RETRY policy consumed
 * elsewhere, not a request-rate seam), so this is the fallback bucket size
 * rather than a value threaded from an existing seam: 10 requests/second
 * per server, refilled continuously — generous enough not to throttle
 * ordinary dispatch, but small enough that a penalize()'d server (a real
 * 429) visibly paces before its next request.
 */
const DEFAULT_RATE_LIMIT_CONFIG: RateLimitConfig = { maxRequests: 10, windowMs: 1000 };

/** Options accepted by `unloadAdapter()` — extracted as a named type so
 *  the public dedupe wrapper and the private implementation share one
 *  declaration instead of two independently-editable inline copies. */
export interface UnloadAdapterOptions {
  maxQuiescenceMs?: number;
  /**
   * CHARIOT::§7.6 — true when this unload IS a runtime revocation
   * (the KillListWatcher's every call is; a plain operator-initiated
   * unload is not). Only when true does unloadAdapter (a) join `name`
   * into the in-memory kill-list revocation set so lazy reconnect is
   * refused (§7.6::1, §7.6::3), (b) cancel pending ApprovalQueue items
   * pointing at `name` (§7.6::4), and (c) emit the
   * federation.adapter.revoked audit event (§7.6::5). Defaults to
   * false so pre-clause callers/tests are unaffected.
   */
  revoked?: boolean;
}

/** Result returned by `unloadAdapter()` — see `UnloadAdapterOptions` doc
 *  comment for why this is a named type. */
export interface UnloadAdapterResult {
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
}

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
  /**
   * Optional adapter-verification status lookup (gap #7 — Wiz 5 finding
   * that new/unverified adapters were never routed into manual review).
   * When wired, every `callTool` dispatch consults
   * `verifiedCatalog.getVerification(tool.server).status` BEFORE
   * dispatch: `'failed'` is an outright refusal (mirrors the revocation
   * refusal); `'pending'`/`'stale'` force the same approval-registry gate
   * used for a catalog `requiresApproval` flag, so a brand-new or
   * demoted adapter cannot execute tools until an operator explicitly
   * approves the call. Omit to skip this gate entirely (matches the
   * pre-existing, pre-1.x behavior — same opt-in posture as the egress
   * engine).  Typically a `VerifiedCatalog` instance
   * (src/catalog/VerifiedCatalog.ts), passed structurally so this module
   * does not need to import the `catalog` package (see
   * `AdapterVerificationLookup` doc comment for the cycle rationale).
   */
  verifiedCatalog?: AdapterVerificationLookup;
  /**
   * §8.7::5 — per-server RateLimiter config. When omitted, the manager
   * constructs its RateLimiter with DEFAULT_RATE_LIMIT_CONFIG (there is no
   * existing per-server-limit seam on FederationConfig to inherit from —
   * see that constant's doc comment). Every dispatch waits for allowance
   * on `tool.server` before calling the adapter; a 429 response drains
   * that server's bucket (RateLimiter.penalize) so subsequent calls to the
   * SAME server pace out, while other servers are unaffected.
   */
  rateLimit?: RateLimitConfig;
  /**
   * CHARIOT::§7.6::4 — approval-queue handle consulted by
   * unloadAdapter({ revoked: true }) to cancel every pending approval
   * pointing at the revoked adapter. Structural (not a concrete class
   * import) so this module does not need to depend on the autonomy
   * package; `TieredAutonomy.cancelByServer` and `ApprovalQueue.cancelByServer`
   * both satisfy this shape. Omit to skip approval cancellation (matches
   * pre-clause behavior).
   */
  approvalQueue?: { cancelByServer(server: string, reason: string): unknown | Promise<unknown> };
  /**
   * CHARIOT::§7.6::5 — "An audit record is emitted under event type
   * `federation.adapter.revoked`." Optional hook invoked by
   * `unloadAdapter({ revoked: true })` on every successful runtime
   * revocation (kill-list unload AND catalog-triggered unload alike —
   * both funnel through the same `unloadAdapter` call), in addition to
   * (not instead of) `observabilityEmitter.emitAdapterRevoked`. The
   * caller (EpicAI) wires this to `AuditTrail.record({ action:
   * 'federation.adapter.revoked', ... })` so the literal event-type
   * string lands in the tamper-evident audit chain, not only in
   * observability telemetry. Errors are caught and logged — a failed
   * audit write must never abort or reverse an already-completed
   * revocation.
   */
  onAdapterRevoked?: (payload: {
    adapterId: string;
    reason: string;
    revokedAt: string;
    cancelledApprovalCount: number;
  }) => void | Promise<void>;
  /**
   * CHARIOT::§7.6::1 — F6 fix. When `catalog` is set, the constructor
   * always seeds `revokedNames` from it once (unconditional — never
   * gated by this option). By DEFAULT (`true`, or omitted) the
   * constructor ALSO registers its own `catalog.onChanged()` listener
   * that re-syncs on every subsequent catalog rebuild. Set this to
   * `false` when a caller (EpicAI) wants to be the SOLE owner of the
   * catalog-change reaction — serializing `syncCatalogRevocations()`
   * with its own `RegistryLoader.reload()` on a promise queue, so the
   * two reconciliations (both of which can independently observe and
   * act on the same just-revoked, still-connected adapter name) never
   * run concurrently against the same `adapterMap`. When `false`, the
   * caller MUST call the public `syncCatalogRevocations()` method
   * itself (e.g. from its own `catalog.onChanged()` listener) — nothing
   * else will run it after construction.
   */
  autoSyncCatalogRevocations?: boolean;
}

/**
 * Optional actor/request context threaded through `callTool` for
 * observability wiring (T4) and the principal-kind partition (gap #3).
 * Every field is optional so existing 2-arg/3-arg call sites (Correlator,
 * tests, embedders) compile and behave unchanged — omission is treated
 * with the same conservative defaults documented per-field below.
 */
export interface CallToolActorContext {
  /** Caller-resolved actor/user id. Defaults to `'unknown'` when omitted —
   *  NOT the tenantId, so the anomaly detector's cross-tenant drift rule
   *  never conflates "no actor supplied" with a real per-tenant identity. */
  actorId?: string;
  /** Principal kind for RBAC/annotation-gate purposes. Defaults to
   *  `'human'` wherever consulted (see trust/types.ts PrincipalType doc). */
  principalType?: PrincipalType;
  /**
   * True ONLY when the caller has verified, from real RBAC/session data,
   * that the acting principal/token is scoped read-only. Defaults to
   * `false` (NOT read-only) when omitted — this is the conservative,
   * non-stub default: without real scope data the dispatcher must never
   * assert a read-only guarantee it cannot back up, since the
   * ScopeViolationRule fires on `destructive && grantedReadOnly` and a
   * false positive here would be a fabricated finding.
   */
  readOnlyScope?: boolean;
  /** Client source IP, when known to the caller. Passed through to
   *  `reportToolDispatch` untouched; omitted when unknown. */
  sourceIp?: string;
  /**
   * §8.9::11 — the full request-scoped TenantContext
   * {tenantId, principalId, roles, tier, attributes} resolved at the
   * AUTHENTICATED boundary (contextFromJWT / contextFromCert). Carried
   * unchanged through dispatch to the egress-policy decision, the
   * pre-dispatch audit record and the anomaly report.
   *
   * Absent on the unauthenticated OSS/local path — that path asserts no
   * roles and therefore cannot obtain any grant it does not have today.
   * Never populate this with createDevContext() for a real dispatch: that
   * helper asserts roles:['admin'] / tier:'enterprise'.
   */
  tenantContext?: TenantContext;
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
 // optional adapter-verification status lookup (gap #7).
  private readonly verifiedCatalog: AdapterVerificationLookup | undefined;
 // §8.7::5 — per-server token-bucket back-pressure; see DEFAULT_RATE_LIMIT_CONFIG.
  private readonly rateLimiter: RateLimiter;
  // CHARIOT::§7.6::4 — approval queue consulted on revocation; see
  // FederationManagerOptions.approvalQueue doc comment.
  private readonly approvalQueue: FederationManagerOptions['approvalQueue'];
  // CHARIOT::§7.6::5 — audit hook consulted on revocation; see
  // FederationManagerOptions.onAdapterRevoked doc comment.
  private readonly onAdapterRevoked: FederationManagerOptions['onAdapterRevoked'];
  /**
   * CHARIOT::§7.6::1 — "consults an in-memory revocation set on every
   * callTool ... populated from two sources: the catalog's per-entry
   * `revoked: true` flag, and a runtime kill-list consumer (§7.7)."
   * This IS that set — the union of both sources, not just the kill-list
   * half:
   *   - kill-list / runtime unload: populated exclusively by
   *     unloadAdapter(name, reason, { revoked: true }) — the call
   *     KillListWatcher makes for every entry it unloads (§7.7), and the
   *     same call `syncCatalogRevocations()` below makes when a
   *     currently-connected adapter is newly caught by a catalog reload.
   *   - catalog `revoked: true`: seeded at construction (when `catalog`
   *     is already loaded) and re-synced on every subsequent
   *     `catalog.onChanged()` notification via `syncCatalogRevocations()`,
   *     via `AdapterCatalog.revokedNames()` — the catalog's own alias-
   *     correct (name + id) revocation index, so this set never drifts
   *     out of sync with `isRevoked()`'s alias handling.
   * `this.catalog?.isRevoked()` remains as an ADDITIONAL live check at
   * every gate below — harmless redundancy that also covers a catalog
   * wired without `onChanged` having fired yet.
   */
  private readonly revokedNames = new Set<string>();

  /**
   * CHARIOT::§7.6 — F6 fix: in-flight teardown dedupe, keyed by adapter
   * name. See `unloadAdapter()`'s docstring for the full rationale.
   */
  private readonly unloadInFlight = new Map<string, Promise<UnloadAdapterResult>>();

  /**
   * CHARIOT::§7.6::1 — seed `revokedNames` from every catalog entry
   * currently flagged `revoked: true` (union with whatever the kill-list
   * path has already added), then run the full runtime-revocation path
   * (`unloadAdapter(..., { revoked: true })` — active-connection teardown,
   * ApprovalQueue cancellation, `federation.adapter.revoked` audit record,
   * §7.6::2-5) for any adapter that is BOTH currently connected AND newly
   * caught by this sync. Called once at construction (if `catalog` is
   * already loaded) and — when `autoSyncCatalogRevocations` is not
   * explicitly `false` — on every subsequent `catalog.onChanged()`
   * notification (catalog (re)load / signed-catalog refresh, §5.4).
   *
   * PUBLIC (F6 fix): a caller that sets `autoSyncCatalogRevocations:
   * false` (see that option's doc comment) becomes solely responsible
   * for calling this itself, typically serialized against its own
   * `RegistryLoader.reload()` on a promise queue so the two
   * reconciliations of the same catalog change never interleave. The
   * returned promise resolves once every teardown this call started has
   * settled — callers that need "this sync is fully done" (e.g. before
   * starting a `reload()` reconciliation) can `await` it directly rather
   * than relying on `unloadAdapter`'s in-flight-dedupe as an ordering
   * primitive.
   */
  async syncCatalogRevocations(): Promise<void> {
    if (!this.catalog) return;
    const newlyRevokedAndConnected: string[] = [];
    for (const name of this.catalog.revokedNames?.() ?? []) {
      if (!this.revokedNames.has(name)) {
        this.revokedNames.add(name);
        if (this.adapterMap.has(name)) {
          newlyRevokedAndConnected.push(name);
        }
      }
    }
    if (newlyRevokedAndConnected.length === 0) return;
    await Promise.all(
      newlyRevokedAndConnected.map((name) =>
        this.unloadAdapter(name, 'catalog reload: adapter marked revoked:true', {
          revoked: true,
        }).catch((err) => {
          log.error('federation_manager.catalog_revocation_unload_failed', {
            adapterId: name,
            error: err instanceof Error ? err.message : String(err),
          });
        }),
      ),
    );
  }

  constructor(config: FederationConfig, options: FederationManagerOptions = {}) {
    this.config = config;
    this.catalog = options.catalog;
    this.sandbox = options.sandbox;
    this.observabilityEmitter = options.observabilityEmitter;
    this.approvalRegistry = options.approvalRegistry ?? new ApprovalRegistry();
    this.verifiedCatalog = options.verifiedCatalog;
    this.approvalQueue = options.approvalQueue;
    // CHARIOT::§8.12::1 — forward the observability emitter into the
    // resilience-layer RateLimiter too, so it emits through it (per "the
    // orchestrator, federation, autonomy, and resilience layers all emit
    // through it"). `this.observabilityEmitter` above is typed as the
    // narrow `ObservabilityEmitterContract` (deliberately, to avoid an
    // import cycle — see that field's own doc comment); RateLimiterSeams'
    // `emitter` only needs the structurally-narrower `.info()` method,
    // which the concrete ObservabilityEmitter instance a caller actually
    // passes in always has, so this is a safe structural cast, not a type
    // widening of the stored field itself.
    this.rateLimiter = new RateLimiter(options.rateLimit ?? DEFAULT_RATE_LIMIT_CONFIG, {
      emitter: this.observabilityEmitter as unknown as { info(message: string, data?: Record<string, unknown>, layer?: string): void } | undefined,
    });
    // Wire the egress AccessPolicyEngine at construction. Gap #9 (Wiz 4):
    // egress enforcement is now DEFAULT-ON / fail-closed. Previously, a
    // FederationConfig with NO `egressPolicy` at all left `accessPolicyEngine`
    // undefined and the pool un-locked — ConnectionPool.evaluateEgress()
    // silently returned allow-all for every outbound dispatch (stdio AND
    // network) because the deny-by-default engine was never constructed in
    // the first place. That is the gap: the mechanism existed but nothing
    // turned it on by default.
    //
    // Fix: when `config.egressPolicy` is omitted entirely, synthesize a
    // deny-by-default policy (defaultEffect 'deny') AND lock the pool into
    // enterprise mode via requirePolicyEngineWired(), so a future refactor
    // that forgets to pass an engine can never silently collapse back to
    // allow-all.
    //
    // REGRESSION FIX (post-185c123): a *zero-rule* deny-by-default policy
    // is fail-closed for destinations Chariot has never heard of, which is
    // correct — but it is ALSO fail-closed for the adapters the operator
    // already installed via `config.servers`, because nothing had ever
    // allowlisted them. That left a default deployment unable to reach its
    // own signed, catalog-installed network adapters (or even dispatch to
    // its own stdio adapters — `resolveEgressTargetOrDeny` evaluates stdio
    // dispatch too, under a synthetic `stdio:<name>` host; see that
    // method's doc comment) until an operator hand-wrote egress rules.
    // That is a latent regression, not the intended security behavior.
    //
    // Fix: when `config.egressPolicy` is omitted, seed the synthesized
    // policy's rule set with one narrow ALLOW rule per adapter declared in
    // `config.servers` — the exact list `connectAll()` dispatches to, i.e.
    // "the adapters the operator installed." Each rule is scoped to BOTH
    // the adapter's own name (`adapters: [name]`) AND its own declared
    // destination (`hostPatterns: [host]`), via
    // `buildInstalledAdapterEgressAllowlist()` below. A compromised adapter
    // still cannot pivot to a different adapter's allowed host, and any
    // destination NOT declared in `config.servers` is still denied by
    // default — the security win (undeclared egress is blocked) is fully
    // preserved. Only the omitted-config case changes; nothing here alters
    // rule resolution for a caller who passes explicit `egressPolicy.rules`.
    //
    // Explicit-config callers are UNCHANGED: supplying `egressPolicy` (even
    // `{}`) takes over exactly as before — `enforce` remains opt-in,
    // `defaultEffect` remains whatever the caller sets, and `rules` is
    // exactly the array the caller passed (or `[]`), never auto-seeded.
    // Only the fully-omitted case changes, from silent allow-all (pre-fix)
    // to enforced deny-by-default with an installed-adapter allowlist
    // (this fix) — never a blanket deny-all-network default.
    const egressPolicy = config.egressPolicy ?? {
      defaultEffect: 'deny' as const,
      enforce: true,
      rules: buildInstalledAdapterEgressAllowlist(config.servers),
    };
    const accessPolicyEngine = new AccessPolicyEngine(
      [],
      'deny',
      egressPolicy.rules ?? [],
      egressPolicy.defaultEffect ?? 'deny',
    );
    this.pool = new ConnectionPool(
      config.retryPolicy,
      config.healthCheckIntervalMs,
      accessPolicyEngine,
    );
    if (egressPolicy.enforce) {
      // Fail-closed: after this, any evaluateEgress with no engine wired
      // returns a synthetic DENY instead of collapsing to allow-all.
      this.pool.requirePolicyEngineWired();
    }
    this.registry = new ToolRegistry();
    this.correlator = new Correlator();
    this.onAdapterRevoked = options.onAdapterRevoked;

    // CHARIOT::§7.6::1 — seed the union revocation set from the catalog's
    // already-loaded state (a no-op if `catalog` is unset or not yet
    // loaded — `revokedNames()` returns an empty set until `load()` has
    // run at least once). The seed always runs, unconditionally — it is
    // synchronous work (the `await` inside `syncCatalogRevocations()` is
    // only reached when there is something to actually tear down, and at
    // construction time `adapterMap` is always empty, so nothing async
    // ever executes here). F6 fix: self-registering an `onChanged()`
    // listener is now OPT-OUT (`autoSyncCatalogRevocations: false`) —
    // when a caller (EpicAI) wants to serialize this against its own
    // `RegistryLoader.reload()` reconciliation, it disables this
    // self-registration and calls the now-public `syncCatalogRevocations()`
    // itself, from its own single, ordered listener.
    if (this.catalog) {
      void this.syncCatalogRevocations();
      if (options.autoSyncCatalogRevocations !== false) {
        this.catalog.onChanged?.(() => {
          void this.syncCatalogRevocations();
        });
      }
    }
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

    // CHARIOT::§7.6::1/§7.6::3 — revocation set is catalog OR kill-list.
    if (this.catalog?.isRevoked(catalogEntry.name) || this.revokedNames.has(catalogEntry.name)) {
      const details = this.catalog?.getRevocationDetails(catalogEntry.name);
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
   * Build a structured ToolResult representing a 'failed'-verification
   * refusal (gap #7). Distinct from `buildRevokedToolResult` — revocation
   * is an operator/catalog action; this is the automated verification
   * pipeline (VerifiedCatalog) reporting that the adapter did not pass
   * its integrity/trust check. Same shape as the other gateway-level
   * refusals so client error handling stays uniform.
   */
  private buildUnverifiedToolResult(
    tool: Tool,
    status: 'failed',
    startedAt: number,
  ): ToolResult {
    const message = `Tool "${tool.name}" blocked: adapter "${tool.server}" has ${status} verification status and cannot be dispatched until it is re-verified or an operator overrides the demotion.`;
    log.warn('federation_manager.blocked_unverified_call', {
      adapterId: tool.server,
      toolName: tool.name,
      verificationStatus: status,
    });
    return {
      content: [{ type: 'text', text: message }],
      isError: true,
      server: tool.server,
      tool: tool.name,
      durationMs: Date.now() - startedAt,
 // automated verification refusal is an explicit gateway-level refusal.
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
    // CHARIOT::§7.6::1/§7.6::3 — revocation set is catalog OR kill-list;
    // refuses lazy connect for an adapter revoked via either source.
    if (this.catalog?.isRevoked(name) || this.revokedNames.has(name)) {
      const details = this.catalog?.getRevocationDetails(name);
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

    // CHARIOT::§16.1 Federation (CHARIOT-SPEC.md:1347, rulings item
    // 91/105) — emitted only after listTools()/registerServer() succeed,
    // so a connect that throws mid-setup (and never reaches here) does
    // not falsely report the adapter as connected.
    chariotEmitter.send('adapter.connected', {
      data: { adapterId: name, toolCount: tools.length },
    });

    return this;
  }

  /**
   * CHARIOT::§7.5::1 — names currently present in `adapterMap` (connected,
   * live adapters — sandboxed and pool-backed alike, both are added to
   * `adapterMap`; see `connect()`/`connectSandboxed()`). Used by
   * `RegistryLoader.loadAndWire()` so it does not double-connect a server
   * name `connectAll()` already connected from `config.federation.servers`.
   */
  listConnectedServerNames(): string[] {
    return Array.from(this.adapterMap.keys());
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
    // Capture the shim BEFORE removing it from adapterMap — otherwise the
    // sandboxed-teardown branch below reads it back as undefined and never
    // calls shim.disconnect(), leaking the worker/process.
    const shim = this.adapterMap.get(name);
    this.registry.unregisterServer(name);
    this.adapterMap.delete(name);
    this.serverConfigs.delete(name);

    if (this.sandboxedAdapters.has(name)) {
      // Sandboxed adapters live outside the pool — shim.disconnect()
      // stops the worker/process via SandboxedAdapter.stop(), but the
      // SandboxManager bookkeeping (activeCount) is decremented via
      // SandboxManager.destroy().
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
    // CHARIOT::§16.1 Federation (CHARIOT-SPEC.md:1347, rulings item
    // 91/105) — unconditional: this method has already unregistered/
    // removed the adapter above by this point regardless of branch.
    chariotEmitter.send('adapter.disconnected', { data: { adapterId: name } });
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
   *
   * `actor`: optional actor/principal context (gap #3 / T4 anomaly-
   * dispatch wiring). Every field is optional and defaults conservatively
   * — see `CallToolActorContext` doc comments. Omitting it entirely
   * preserves the exact pre-existing 2-arg/3-arg call behavior.
   */
  async callTool(
    name: string,
    args: Record<string, unknown>,
    tenantId?: string,
    actor?: CallToolActorContext,
  ): Promise<ToolResult> {
    const startedAt = Date.now();
    // §8.9::11 — the authenticated TenantContext, when supplied, is the
    // authoritative tenant. It is carried through egress policy, the anomaly
    // report and the audit record rather than being reduced to a bare id.
    const effectiveTenantContext = actor?.tenantContext;
    const effectiveTenantId =
      effectiveTenantContext?.tenantId
      ?? tenantId
      ?? process.env.CHARIOT_TENANT_ID
      ?? 'local';
    // A caller that supplies BOTH must not disagree: silently preferring one
    // would let a mismatched positional tenantId mask the authenticated tenant.
    if (effectiveTenantContext && tenantId && effectiveTenantContext.tenantId !== tenantId) {
      throw new Error('tenantId does not match actor.tenantContext.tenantId');
    }
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
    // CHARIOT::§7.6::1 — revocation set consulted on every callTool,
    // populated from BOTH the catalog revoked:true flag and the runtime
    // kill-list consumer (revokedNames, populated by unloadAdapter's
    // { revoked: true } path — see that field's doc comment).
    if (this.catalog?.isRevoked(tool.server) || this.revokedNames.has(tool.server)) {
      return this.buildRevokedToolResult(
        tool,
        this.catalog?.getRevocationDetails(tool.server),
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
      const originalToolName = toolNameFromCombinedName(name, tool.server);
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

 // per-tool approval gate (Adaline mechanism 4), now merged with
    // two additional fail-closed gates that force approval REGARDLESS of
    // the catalog's manual requiresApproval flag:
    //
    //   (a) Annotation gate (gap #2 — Wiz 2). A tool is treated as
    //       destructive/not-verifiably-read-only unless it explicitly
    //       declares `annotations.readOnlyHint === true`. A missing
    //       annotation, or an explicit `destructiveHint === true`, forces
    //       the approval gate even when no operator ever flagged the
    //       adapter's catalog entry. This is the exact definition the T4
    //       anomaly wiring below also uses for `destructive`, so the two
    //       stay consistent: "destructive = destructiveHint, OR not
    //       verifiably read-only".
    //   (b) Unverified-adapter gate (gap #7 — Wiz 5). When a
    //       verifiedCatalog lookup is wired, a 'failed' verification is an
    //       outright refusal (mirrors the revocation refusal below); a
    //       'pending' or 'stale' verification forces the same
    //       approval-registry gate, so a brand-new or demoted adapter
    //       cannot dispatch until an operator explicitly approves it.
    //       Skipped entirely when no verifiedCatalog is wired (opt-in,
    //       same posture as the egress engine).
    //
    // ApprovalKey hashes (tenant, adapter, tool, canonical args) so a
    // different args payload must be approved separately.
    const approvalCatalogEntry = this.catalog?.byName(tool.server);
    const catalogRequiresApproval = (approvalCatalogEntry as { requiresApproval?: boolean } | undefined)?.requiresApproval === true;

    const isVerifiablyReadOnly = tool.annotations?.readOnlyHint === true;
    const isDestructiveAnnotated = tool.annotations?.destructiveHint === true;
    // Shared with the reportToolDispatch() call below — keep these two
    // uses in sync; do not fork the definition.
    const destructive = isDestructiveAnnotated || !isVerifiablyReadOnly;

    let verificationStatus: 'verified' | 'failed' | 'pending' | 'stale' | undefined;
    if (this.verifiedCatalog) {
      verificationStatus = this.verifiedCatalog.getVerification(tool.server).status;
      if (verificationStatus === 'failed') {
        return this.buildUnverifiedToolResult(tool, verificationStatus, startedAt);
      }
    }
    const verificationForcesApproval = verificationStatus === 'pending' || verificationStatus === 'stale';

    const requiresApproval = catalogRequiresApproval || destructive || verificationForcesApproval;

    // T4 anomaly-detector wiring: report this dispatch's authz
    // classification exactly once per callTool() invocation, now that the
    // annotation/verification/catalog authz decision is fully known.
    // Fires regardless of allow vs. approval-required below — a BLOCKED
    // destructive call from a read-only-scoped actor is exactly the
    // forged-token/escalation signal ScopeViolationRule exists to catch,
    // so gating this on the outcome would hide the signal it is meant to
    // surface. grantedReadOnly defaults to false (NOT read-only) unless
    // the caller has passed real, verified scope data via `actor` — never
    // fabricated from tool metadata.
    reportToolDispatch({
      tenantId: effectiveTenantId,
      // §8.9::11 — prefer the authenticated principal over a caller-supplied
      // actorId; fall back to 'unknown' so an absent identity is never
      // conflated with a real one.
      actorId: actor?.actorId ?? effectiveTenantContext?.principalId ?? 'unknown',
      toolName: tool.name,
      adapterId: tool.server,
      destructive,
      grantedReadOnly: actor?.readOnlyScope === true,
      sourceIp: actor?.sourceIp,
      tenantContext: effectiveTenantContext,
    });

    if (requiresApproval) {
      const originalToolNameForApproval = toolNameFromCombinedName(name, tool.server);
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
          content: JSON.stringify({
            error: 'approval_required',
            adapter: tool.server,
            tool: originalToolNameForApproval,
            approvalKey,
            reason: catalogRequiresApproval
              ? 'catalog_flagged'
              : verificationForcesApproval
                ? `adapter_verification_${verificationStatus}`
                : 'not_verifiably_read_only',
          }),
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
        // §8.9::11 — carry the authenticated principal identity into the
        // policy decision. Spread-only so the unauthenticated path passes
        // exactly the fields it passes today.
        ...(effectiveTenantContext
          ? {
              principalId: effectiveTenantContext.principalId,
              roles: effectiveTenantContext.roles,
              attributes: effectiveTenantContext.attributes,
            }
          : {}),
      });
      if (!decision.allow) {
        if (isSandboxed) decrementSandboxedInFlight();
        else this.pool.endCall(tool.server);
        return this.buildEgressBlockedToolResult(tool, decision, startedAt);
      }
    }

    // §8.7::5 — CHARIOT-SPEC.md:781 per-server token-bucket back-pressure
    // gate. A server that has never returned 429 has a full bucket and this
    // resolves immediately; a server this.rateLimiter.penalize()'d below
    // (a real prior 429, see the catch/error-path handling further down)
    // paces here until its bucket refills, rather than hammering an
    // upstream that just told us to slow down. maxWaitMs uses the
    // RateLimiter default (30s); exceeding it is itself reported as a
    // rate-limited ToolResult rather than an unhandled rejection.
    try {
      await this.rateLimiter.waitForAllowance(tool.server);
    } catch (err) {
      if (isSandboxed) decrementSandboxedInFlight();
      else this.pool.endCall(tool.server);
      const message = err instanceof Error ? err.message : String(err);
      return this.buildRateLimitedToolResult(tool, message, startedAt);
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
 // AS::§2.5::5 — ADAPTER-STANDARD-MAY-2026.md:460 "Non-idempotent
    // (declared): The tool's `inputSchema` MUST carry
    // `x-chariot-idempotent: false`. The dispatcher MUST NOT retry;
    // failures surface as a single attempt." Read the flag from the
    // DISPATCHED TOOL's own inputSchema (tool.parameters) — distinct
    // from the per-ADAPTER `idempotent: 'safe'|'unsafe'|'unknown'`
    // catalog field read below (which only drives the Idempotency-Key
    // header). When the tool declares itself non-idempotent, force
    // every retry trigger to 'stop' so fetchWithRetryTelemetry's
    // applyPolicy() short-circuits on the very first failure — this
    // OVERRIDES any adapter-level failurePolicy that would otherwise
    // retry, because a non-idempotent TOOL's retry-safety is a
    // property the per-ADAPTER default cannot see or account for.
    const declaredNonIdempotent =
      (tool.parameters as Record<string, unknown> | undefined)?.['x-chariot-idempotent'] === false;
    const effectiveFailurePolicy = declaredNonIdempotent ? NO_RETRY_FAILURE_POLICY : failurePolicy;
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
      toolName: toolNameFromCombinedName(name, tool.server),
      ...(effectiveFailurePolicy ? { failurePolicy: effectiveFailurePolicy } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      ...(idempotencyKey !== undefined ? { idempotencyKey } : {}),
      parentSignal: federationController.signal,
    };
    const setter = (adapter as unknown as { setObservabilityEmitter?: (e: ObservabilityEmitterContract | undefined) => void }).setObservabilityEmitter;
    if (typeof setter === 'function') setter.call(adapter, this.observabilityEmitter);

    try {
      // Use the original tool name (without server prefix) for the MCP call
      const originalName = toolNameFromCombinedName(name, tool.server);
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
        // §8.7::5 — back-pressure the NEXT calls to this server when this
        // one came back rate-limited. Reuses ErrorClassifier's own 429
        // recognition (patterns: ['429','rate limit','too many requests'] →
        // prefix 'Rate limited') against the adapter's own error content
        // rather than a second, independently-maintained 429 regex here.
        if (result.isError) {
          const classified = ErrorClassifier.classify(
            new Error(typeof result.content === 'string' ? result.content : JSON.stringify(result.content)),
          );
          if (classified.message.startsWith('Rate limited:')) {
            this.rateLimiter.penalize(tool.server);
          }
        }
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
        // §8.7::5 — same back-pressure as the success-path 429 check above,
        // for the thrown-error path. Same reused ErrorClassifier recognition,
        // applied to the thrown error itself rather than result.content.
        const thrownClassified = ErrorClassifier.classify(err instanceof Error ? err : new Error(errMsg));
        if (thrownClassified.message.startsWith('Rate limited:')) {
          this.rateLimiter.penalize(tool.server);
        }
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
   *     sandboxed adapters. NOTE: this gates Chariot's OWN dispatch to the
   *     sandbox shim (local IPC); it does NOT confine sockets the sandboxed
   *     adapter opens itself. Real network confinement for sandboxed
   *     adapters is enforced fail-closed at launch by
   *     SandboxManager.assertConfinementEnforceable (a declared egress jail
   *     the runtime cannot apply refuses to start), NOT here.
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
    const target = parseNetworkEgressTarget(config.url);
    return target ?? { host: '<unparseable>' };
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
   * §8.7::5 — the pre-dispatch RateLimiter.waitForAllowance() gate exceeded
   * its maxWaitMs for `tool.server` (the server is still penalized from a
   * prior 429 and has not refilled in time). Reported the same way the
   * other pre-dispatch refusals above are: a typed ToolResult, not a thrown
   * error, so callers get structured back-pressure feedback instead of an
   * unhandled rejection.
   */
  private buildRateLimitedToolResult(tool: Tool, reason: string, startedAt: number): ToolResult {
    log.warn('federation_manager.rate_limited_call', {
      adapterId: tool.server,
      toolName: tool.name,
      reason,
    });
    return {
      content: JSON.stringify({ error: 'rate_limited', adapter: tool.server, tool: tool.name, reason }),
      isError: true,
      server: tool.server,
      tool: tool.name,
      durationMs: Date.now() - startedAt,
      outcome: 'explicit_failure',
      errorClass: 'rate_limit',
      retryCount: 0,
      retryReasons: [],
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
   *
   * CHARIOT::§7.6 — F6 fix: public entrypoint dedupes concurrent unloads
   * of the SAME adapter name against `unloadInFlight`. Two independent
   * triggers (e.g. `syncCatalogRevocations()`'s active-teardown path and
   * a `RegistryLoader.reload()` reconciliation, both potentially reacting
   * to the same catalog change) can each observe `adapterMap.has(name)`
   * as still true before either has finished tearing it down — without
   * this, both would run a full independent teardown, doubling
   * ApprovalQueue cancellation and the `federation.adapter.revoked` audit
   * emission. Every caller for the same in-flight `name` gets the
   * IDENTICAL promise (`===`), so exactly one teardown ever runs; a new
   * call after the in-flight one settles starts a fresh, independent
   * teardown as before (the map entry is cleared in `finally`).
   */
  // NOT `async`: an async wrapper would mint a fresh Promise per call and the
  // in-flight dedupe contract (identical promise for concurrent callers) would
  // not hold — the stored promise is returned as-is.
  unloadAdapter(
    name: string,
    reason: string,
    options: UnloadAdapterOptions = {},
  ): Promise<UnloadAdapterResult> {
    const existing = this.unloadInFlight.get(name);
    if (existing) return existing;

    const promise = this._unloadAdapterImpl(name, reason, options).finally(() => {
      this.unloadInFlight.delete(name);
    });
    this.unloadInFlight.set(name, promise);
    return promise;
  }

  /** Actual teardown implementation — see `unloadAdapter()`'s docstring
   *  above for the full contract; this is called at most once per
   *  in-flight `name` (deduped by the public wrapper). */
  private async _unloadAdapterImpl(
    name: string,
    reason: string,
    options: UnloadAdapterOptions,
  ): Promise<UnloadAdapterResult> {
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
    // §7.6::2: sandboxed adapters live outside `this.pool` entirely — a plain
    // `this.pool.disconnect(name)` is a no-op for them and leaves the running
    // sandbox process/worker alive. Mirror the same sandbox-aware teardown
    // `disconnect()` (above) already performs: stop the shim, then have
    // SandboxManager actually destroy the sandbox.
    if (this.sandboxedAdapters.has(name)) {
      const shim = this.adapterMap.get(name);
      if (shim) {
        try {
          await shim.disconnect();
        } catch (err) {
          log.warn('federation_manager.unload.sandbox_disconnect_error', {
            adapterId: name,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
      if (this.sandbox) {
        try {
          await this.sandbox.destroy(name);
        } catch (err) {
          disconnectError = err instanceof Error ? err.message : String(err);
          log.error('federation_manager.unload.sandbox_destroy_failed', {
            adapterId: name,
            error: disconnectError,
            note: 'adapter remains sandboxed in unloading state; retry unload after investigating',
          });
        }
      } else {
        // §7.6::2 invariant guard: a name enters sandboxedAdapters ONLY after
        // this.sandbox.create() succeeds (create is gated on `this.sandbox`),
        // and this.sandbox is never nulled — so this branch is unreachable.
        // If it ever fires, the SandboxManager that owns the running process
        // is gone; we CANNOT tear the sandbox down, so we must NOT silently
        // drop tracking (that would orphan the process). Record it as an
        // error so the entry stays and the operator is alerted.
        disconnectError =
          'sandboxed adapter has no SandboxManager to destroy it (invariant violation)';
        log.error('federation_manager.unload.sandbox_manager_absent', {
          adapterId: name,
          note: 'adapter remains tracked as sandboxed; cannot destroy without a SandboxManager',
        });
      }
      if (!disconnectError) {
        this.sandboxedAdapters.delete(name);
        this.sandboxedInFlight.delete(name);
      }
    } else {
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

    // CHARIOT::§16.1 Federation (CHARIOT-SPEC.md:1347, rulings item
    // 91/105) — fires for every successful unload, revoked or not (a
    // revoked unload ALSO emits adapter.revoked below, in addition to
    // this — the adapter genuinely disconnected either way).
    chariotEmitter.send('adapter.disconnected', { data: { adapterId: name, reason } });

    const durationMs = Date.now() - startedAt;
    log.info('federation_manager.unload.complete', {
      adapterId: name,
      reason,
      quiescent,
      inFlightAtClose,
      durationMs,
    });

    if (options.revoked) {
      // CHARIOT::§7.6::1/§7.6::3 — join the kill-list revocation set so a
      // subsequent connect()/connectSandboxed() for this name is refused
      // even though the adapter has already been removed from
      // adapterMap/registry above.
      this.revokedNames.add(name);

      // CHARIOT::§7.6::4 — cancel pending ApprovalQueue items pointing at
      // the revoked adapter.
      let cancelledApprovalCount = 0;
      if (this.approvalQueue) {
        try {
          const cancelled = await this.approvalQueue.cancelByServer(name, reason);
          cancelledApprovalCount = Array.isArray(cancelled) ? cancelled.length : 0;
        } catch (err) {
          log.error('federation_manager.unload.approval_cancel_failed', {
            adapterId: name,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }

      // CHARIOT::§7.6::5 — emit the federation.adapter.revoked audit
      // record. Exactly one emission per successful revoked unload (the
      // "unknown adapter" early-return above and the disconnectError
      // early-return further up both precede this point, so neither
      // fires an event).
      const revokedAt = new Date().toISOString();
      this.observabilityEmitter?.emitAdapterRevoked?.({
        adapterId: name,
        reason,
        revokedAt,
        cancelledApprovalCount,
      });
      // CHARIOT::§16.1 Federation (CHARIOT-SPEC.md:1347, rulings item
      // 91/105) — the customer-facing counterpart to the internal
      // observabilityEmitter call directly above and the audit-chain
      // record below; distinct from both (telemetry vs. audit-chain vs.
      // customer-facing event bus).
      chariotEmitter.send('adapter.revoked', {
        severity: 'warning',
        alertWorthy: true,
        data: { adapterId: name, reason, revokedAt, cancelledApprovalCount },
      });
      // CHARIOT::§7.6::5 — "An audit record is emitted under event type
      // `federation.adapter.revoked`." The observability emit above is
      // telemetry only and carries no event-type string; this is the
      // actual audit-chain record. Errors are caught and logged — a
      // failed audit write must not undo or block the revocation that
      // already completed above.
      try {
        await this.onAdapterRevoked?.({
          adapterId: name,
          reason,
          revokedAt,
          cancelledApprovalCount,
        });
      } catch (err) {
        log.error('federation_manager.unload.audit_record_failed', {
          adapterId: name,
          error: err instanceof Error ? err.message : String(err),
        });
      }
      log.info('federation_manager.adapter_revoked', {
        adapterId: name,
        reason,
        revokedAt,
        cancelledApprovalCount,
      });
    }

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
   *
   * SECURITY: the Correlator receives registry-namespaced tool listings
   * and a dispatch callback bound to `this.callTool`, so every fan-out
   * invocation passes the full gate stack (revocation re-check, schema
   * validation, per-tool approval, unload accounting, egress policy).
   * It never receives raw adapter references — raw dispatch would bypass
   * all five gates.
   */
  async correlate(
    query: CorrelationQuery,
    tenantId?: string,
    // §8.9::11 — correlation fans out to real dispatches; the authenticated
    // actor context must survive that hop, not be dropped at the callback.
    actor?: CallToolActorContext,
  ): Promise<CorrelationResult> {
    const servers = Array.from(this.adapterMap.keys()).map((name) => ({
      name,
      tools: this.registry.listByServer(name),
    }));
    return this.correlator.correlate(
      query,
      servers,
      (toolName, args) => this.callTool(toolName, args, tenantId, actor),
    );
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

