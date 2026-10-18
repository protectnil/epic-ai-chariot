/**
 * @epicai/chariot — EpicAI Entrypoint
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { z } from 'zod';
import type {
  EpicAIConfig,
  EpicAIAgent,
  EpicAIAuditAccessor,
  EpicAIFederationAccessor,
  EpicAIAutonomyAccessor,
  RunResult,
  StreamEvent,
  ActionDecision,
  AuditFilter,
  ConnectionHealth,
  Tool,
  PendingApproval,
  AutonomyPolicy,
  LLMFunction,
} from './types/index.js';
import { FederationManager } from './federation/FederationManager.js';
import { KillListWatcher } from './federation/KillListWatcher.js';
import { AdapterCatalog } from './federation/AdapterCatalog.js';
import { RegistryLoader } from './federation/RegistryLoader.js';
import { ToolPreFilter } from './federation/ToolPreFilter.js';
import { TieredAutonomy } from './autonomy/TieredAutonomy.js';
import { PersonaManager } from './persona/PersonaManager.js';
import { AuditTrail } from './audit/AuditTrail.js';
import { Orchestrator } from './orchestrator/Orchestrator.js';
import { createOrchestratorLLM } from './orchestrator/OrchestratorProvider.js';
import { createGeneratorLLM } from './orchestrator/GeneratorProvider.js';
// CHARIOT::§8.12::5 (W34-4b) — one TokenTracker per EpicAI instance, per ruling.
import { TokenTracker } from './observability/TokenTracker.js';
// CHARIOT::§8.12::1/::2 (W34-4b) — real observability wiring: cast
// config.observabilityEmitter to the concrete class (see the existing
// TieredAutonomy-forwarding comment a few lines below for why this cast
// pattern is already established here), and build the OTLP exporter from
// env (createOtlpHttpJsonSpanExporter returns null when unset — "off when
// unset", so this is a no-op unless an operator configures it).
import type { ObservabilityEmitter } from './observability/EventEmitter.js';
import { createOtlpHttpJsonSpanExporter, createOTelEventCallback } from './observability/OpenTelemetry.js';
// CHARIOT::§16.3::1 (gate finding 114(i), W34-4c) — process-wide
// registration seam; see the constructor call site's doc comment.
import { registerTokenUsageSource } from '../observability/tokenUsageRegistry.js';

// =============================================================================
// Config Validation Schemas
// =============================================================================

const AuthConfigSchema = z.object({
  type: z.enum(['bearer', 'basic', 'api-key']),
  token: z.string().optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  clientId: z.string().optional(),
  clientSecret: z.string().optional(),
  headerName: z.string().optional(),
});

const ServerConnectionSchema = z.object({
  name: z.string().min(1),
  transport: z.enum(['stdio', 'streamable-http']),
  url: z.string().url().optional(),
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  auth: AuthConfigSchema.optional(),
  timeoutMs: z.number().positive().optional(),
});

const RetryPolicySchema = z.object({
  maxRetries: z.number().int().min(0),
  backoffMs: z.number().positive(),
  maxBackoffMs: z.number().positive().optional(),
});

const OrchestratorConfigSchema = z.object({
  provider: z.enum(['auto', 'ollama', 'vllm', 'apple-foundation', 'custom']),
  model: z.string().min(1),
  adapter: z.string().optional(),
  baseUrl: z.string().url().optional(),
  timeoutMs: z.number().positive().optional(),
  maxIterations: z.number().int().positive().optional(),
  logLevel: z.enum(['debug', 'info', 'warn', 'error', 'off']).optional(),
  llm: z.custom<LLMFunction>(
    (val): val is LLMFunction => typeof val === 'function',
    'Expected a function',
  ).optional(),
});

const GeneratorConfigSchema = z.object({
  provider: z.enum(['openai', 'anthropic', 'ollama', 'digitalocean', 'custom']),
  model: z.string().min(1),
  apiKey: z.string().optional(),
  baseUrl: z.string().url().optional(),
  timeoutMs: z.number().positive().optional(),
  maxTokens: z.number().int().positive().optional(),
  llm: z.custom<LLMFunction>(
    (val): val is LLMFunction => typeof val === 'function',
    'Expected a function',
  ).optional(),
});

const FederationConfigSchema = z.object({
  servers: z.array(ServerConnectionSchema),
  retryPolicy: RetryPolicySchema.optional(),
  healthCheckIntervalMs: z.number().positive().optional(),
});

const AutonomyRulesSchema = z.object({
  auto: z.array(z.string()),
  escalate: z.array(z.string()),
  approve: z.array(z.string()),
});

const ApprovalQueueConfigSchema = z.object({
  persistence: z.enum(['memory', 'redis']),
  redis: z.object({
    host: z.string(),
    port: z.number().int().positive(),
    password: z.string().optional(),
  }).optional(),
  ttlMs: z.number().positive(),
  onExpire: z.enum(['deny', 'escalate-to-admin']).optional(),
});

const AutonomyConfigSchema = z.object({
  tiers: AutonomyRulesSchema,
  policies: z.array(z.object({
    name: z.string(),
    condition: z.custom<AutonomyPolicy['condition']>(
      (val): val is AutonomyPolicy['condition'] => typeof val === 'function',
      'Expected a function',
    ),
    override: z.enum(['auto', 'escalate', 'approve']),
    priority: z.number().optional(),
  })).optional(),
  approvalQueue: ApprovalQueueConfigSchema.optional(),
});

const PersonaConfigSchema = z.object({
  name: z.string().min(1),
  tone: z.string().min(1),
  domain: z.string().min(1),
  systemPrompt: z.string().min(1),
  vocabulary: z.record(z.string(), z.string()).optional(),
  constraints: z.array(z.string()).optional(),
  adapterPath: z.string().optional(),
});

const AuditAdapterSchema = z.object({}).passthrough().superRefine((val, ctx) => {
  const obj = val as Record<string, unknown>;
  for (const method of ['append', 'query', 'verify']) {
    if (typeof obj[method] !== 'function') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `AuditStoreAdapter must have a "${method}" method`,
      });
    }
  }
});

const AuditConfigSchema = z.object({
  store: z.enum(['append-only-log', 'memory', 'sqlite', 'custom']),
  path: z.string().optional(),
  adapter: AuditAdapterSchema.optional(),
  integrity: z.enum(['sha256-chain', 'none']),
  retention: z.object({
    maxAgeDays: z.number().positive().optional(),
    maxSizeBytes: z.number().positive().optional(),
  }).optional(),
  export: z.array(z.enum(['json', 'csv', 'syslog'])).optional(),
});

const RetrievalConfigSchema = z.object({
  memory: z.object({
    store: z.string().min(1),
    redis: z.object({ host: z.string(), port: z.number() }).optional(),
    mongo: z.object({ uri: z.string(), db: z.string() }).optional(),
    cacheTTLMs: z.number().positive().optional(),
  }).optional(),
}).optional();

const EpicAIConfigSchema = z.object({
  orchestrator: OrchestratorConfigSchema,
  generator: GeneratorConfigSchema.optional(),
  federation: FederationConfigSchema,
  autonomy: AutonomyConfigSchema,
  retrieval: RetrievalConfigSchema,
  persona: PersonaConfigSchema,
  audit: AuditConfigSchema,
  transport: z.enum(['sse', 'json']).optional(),
 // emitter is a class instance, not a JSON-serializable value;
  // z.unknown() preserves the instance through `.parse()` without imposing
  // shape constraints on the structural type.
  observabilityEmitter: z.unknown().optional(),
});

// =============================================================================
// Validation Helpers
// =============================================================================

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function validateActionId(actionId: string): void {
  if (!UUID_PATTERN.test(actionId)) {
    throw new Error(`Invalid actionId format: "${actionId}". Expected UUID.`);
  }
}

// =============================================================================
// EpicAI — Static Factory
// =============================================================================

export class EpicAI {
  /**
   * Create and configure an EpicAI agent.
   * Validates all configuration, instantiates all layers,
   * and returns a ready-to-start EpicAIAgent.
   */
  static create(config: EpicAIConfig): Promise<EpicAIAgent> {
    try {
      const validated = EpicAIConfigSchema.parse(config);
      return Promise.resolve(new EpicAIAgentImpl(validated as EpicAIConfig));
    } catch (err) {
      return Promise.reject(err as Error);
    }
  }
}

// =============================================================================
// EpicAIAgentImpl — Agent Lifecycle
// =============================================================================

class EpicAIAgentImpl implements EpicAIAgent {
  private readonly config: EpicAIConfig;
  private started = false;

  private readonly federationManager: FederationManager;
  private killListWatcher: KillListWatcher | null = null;
  // CHARIOT::§7.5::1 / §7.6::1 — the catalog the FederationManager's
  // revocation gate and RegistryLoader's load-time revocation filter
  // both read. `EpicAIConfig` gives the engine no registry/catalog
  // source of its own (see `EpicAIConfig` — no `catalog`/`registryUrl`
  // field anywhere on it or on `FederationConfig`), so this always
  // constructs against RegistryLoader's own default resolution: the
  // bundled adapter-bundle.json, signature-verified (`source: 'bundle'`
  // is CatalogSourceConfig's minimal valid config — see
  // AdapterCatalog's constructor/loadFromBundle default path).
  private readonly adapterCatalog: AdapterCatalog;
  private registryLoader: RegistryLoader | null = null;
  // CHARIOT::§7.5::1 — the ONE ToolPreFilter instance shared by
  // RegistryLoader (indexed after every loadAndWire()/reload()) and
  // Orchestrator (queried on every execute() — see
  // OrchestratorDeps.toolPreFilter doc comment for why this is a
  // separate field from Orchestrator's own `preFilter` select-options).
  private readonly toolPreFilter: ToolPreFilter;
  // CHARIOT::§7.6::1 / §7.5::1 — F6 fix: single serialization queue for
  // the catalog-change reaction. See the `adapterCatalog.onChanged()`
  // registration in `start()` for the full rationale.
  private catalogReconcile: Promise<void> = Promise.resolve();
  private readonly tieredAutonomy: TieredAutonomy;
  // CHARIOT::§8.12::5 (W34-4b) — one per EpicAI instance, per ruling.
  private readonly tokenTracker: TokenTracker = new TokenTracker();
  private readonly personaManager: PersonaManager;
  private readonly auditTrail: AuditTrail;
  private orchestrator: Orchestrator | null = null;

  readonly audit: EpicAIAuditAccessor;
  readonly federation: EpicAIFederationAccessor;
  readonly autonomy: EpicAIAutonomyAccessor;

  constructor(config: EpicAIConfig) {
    this.config = config;

    // CHARIOT::§7.5::1 / §7.6::1 — constructed before FederationManager so
    // the same instance can be passed into it below. Not yet `load()`ed
    // here (that is async — `AdapterCatalog.load()` runs in `start()`,
    // before `connectAll()`); `FederationManagerOptions.catalog`'s own doc
    // comment permits this ("revocations introduced ... after
    // construction are honored on subsequent calls because the isRevoked
    // check reads live catalog state").
    this.adapterCatalog = new AdapterCatalog({ source: 'bundle' });

    // CHARIOT::§7.5::1 — constructed once here so the SAME instance can
    // be handed to both RegistryLoader (in start()) and Orchestrator
    // (also in start(), after loadAndWire() has already indexed it).
    this.toolPreFilter = new ToolPreFilter();

    // Instantiate real layer implementations.
    // CHARIOT::§8.12::1 — forward the optional observability emitter so the
    // autonomy layer's evaluate() decisions emit through it too (previously
    // only federation received this option here; autonomy did not).
    // `config.observabilityEmitter` is typed `z.unknown()` at the Zod
    // boundary (see EpicAIConfigSchema's own comment: "emitter is a class
    // instance, not a JSON-serializable value") — the structural cast below
    // is the same pattern already used to forward it into FederationManager.
    this.tieredAutonomy = new TieredAutonomy(
      config.autonomy.tiers,
      config.autonomy.approvalQueue,
      { emitter: config.observabilityEmitter as { info(message: string, data?: Record<string, unknown>, layer?: string): void } | undefined },
    );
 // forward the optional observability emitter so adapter retries
    // surface as 'tool-call-retry' StreamEvents and persist on ActionRecord.
    // CHARIOT::§7.6::4 — approvalQueue wired via a closure (not a direct
    // reference) so construction order doesn't matter; tieredAutonomy is
    // already assigned above by the time any dispatch calls this at runtime.
    // CHARIOT::§7.6::5 — onAdapterRevoked likewise wired via a closure
    // referencing `this.auditTrail` / `this.personaManager`, both assigned
    // immediately below; the closure only runs later, at an actual
    // runtime revocation, by which point construction has completed.
    // CHARIOT::§7.6::1 — F6 fix: `autoSyncCatalogRevocations: false` —
    // EpicAI is the sole owner of the catalog-change reaction (see the
    // single `adapterCatalog.onChanged()` listener registered in
    // start()), which serializes `syncCatalogRevocations()` against
    // `RegistryLoader.reload()` on `this.catalogReconcile` so the two
    // reconciliations of the same catalog change can never interleave
    // and double-teardown the same adapter (F6). The constructor-time
    // seed of `revokedNames` still runs unconditionally inside
    // FederationManager's own constructor regardless of this flag.
    this.federationManager = new FederationManager(config.federation, {
      catalog: this.adapterCatalog,
      autoSyncCatalogRevocations: false,
      observabilityEmitter: config.observabilityEmitter,
      approvalQueue: {
        cancelByServer: (server: string, reason: string) =>
          this.tieredAutonomy.cancelByServer(server, reason),
      },
      onAdapterRevoked: async (payload) => {
        await this.auditTrail.record({
          timestamp: new Date(),
          action: 'federation.adapter.revoked',
          tool: '',
          server: payload.adapterId,
          tier: 'auto',
          status: 'completed',
          input: { reason: payload.reason },
          output: { cancelledApprovalCount: payload.cancelledApprovalCount },
          persona: this.personaManager.active().name,
          durationMs: 0,
        });
      },
    });
    this.personaManager = new PersonaManager();
    this.personaManager.register(config.persona);
    this.auditTrail = new AuditTrail(config.audit);

    // Register dynamic policies if provided
    if (config.autonomy.policies) {
      for (const policy of config.autonomy.policies) {
        this.tieredAutonomy.addPolicy(policy);
      }
    }

    // Wire real accessors
    this.audit = {
      query: async (filter: AuditFilter) => {
        return this.auditTrail.query(filter);
      },
      verify: async () => {
        return this.auditTrail.verify();
      },
      export: async (format: 'json' | 'csv' | 'syslog') => {
        return this.auditTrail.export(format);
      },
    };

    this.federation = {
      health: (): ConnectionHealth[] => {
        // ConnectionPool.health() is async, but the accessor interface is sync.
        // Return cached tool-count-based health from ToolRegistry.
        const tools = this.federationManager.listTools();
        const serverMap = new Map<string, number>();
        for (const t of tools) {
          serverMap.set(t.server, (serverMap.get(t.server) ?? 0) + 1);
        }
        const result: ConnectionHealth[] = [];
        for (const [server, toolCount] of serverMap) {
          result.push({ server, status: 'connected', toolCount });
        }
        return result;
      },
      listTools: (): Tool[] => {
        return this.federationManager.listTools();
      },
    };

    this.autonomy = {
      pending: async (): Promise<PendingApproval[]> => {
        return this.tieredAutonomy.pending();
      },
      listPolicies: (): AutonomyPolicy[] => {
        return this.tieredAutonomy.listPolicies();
      },
    };

    // CHARIOT::§16.3::1 / gate finding 114(i), W34-4c — register this
    // instance's TokenTracker-backed getTokenUsageByAdapter() with the
    // process-wide registry so ANY ChariotMetrics instance later
    // constructed in the SAME process (e.g. `chariot serve`'s
    // ChariotState.ts) picks it up automatically — no second wiring call
    // needed by whoever constructs ChariotMetrics. Most-recent-
    // registration-wins (documented in tokenUsageRegistry.ts): a second
    // EpicAI instance in the same process replaces this one as the
    // registered source.
    registerTokenUsageSource(this);
  }

  async start(): Promise<void> {
    if (this.started) {
      throw new Error('Agent already started');
    }

    // VALIDATE FIRST — no side effects until config is proven valid
    const orchestratorLLM = createOrchestratorLLM(this.config.orchestrator);

    let generatorLLM: LLMFunction;
    if (this.config.generator) {
      generatorLLM = createGeneratorLLM(this.config.generator);
    } else if (this.config.orchestrator.provider === 'ollama' || this.config.orchestrator.provider === 'auto') {
      generatorLLM = orchestratorLLM;
    } else {
      throw new Error(
        'Generator config is required when orchestrator is not Ollama. ' +
        'Provide a generator config or use provider: "ollama" for the orchestrator to handle both roles.'
      );
    }

    // SIDE EFFECTS — only after validation passes

    // CHARIOT::§7.5::1 / §7.6::1 — load the catalog BEFORE connectAll()
    // so the revocation gate (`FederationManager.connect()`,
    // `this.catalog?.isRevoked()` / `revokedNames`) sees real catalog
    // state — including any `revoked: true` entries — for the very first
    // connect attempt, not an empty just-constructed catalog. A load
    // failure here is caught the same way `AdapterCatalog.load()`
    // documents for every caller (CH-02: falls back / goes to the
    // `invalid` empty-catalog state internally); it does not throw.
    await this.adapterCatalog.load();

    await this.federationManager.connectAll();
    await this.auditTrail.init();

    // CHARIOT::§7.7::1 — "KillListWatcher SHALL run as part of the
    // federation startup sequence" — unconditionally, not only when a
    // feed URL happens to be configured. When CHARIOT_KILL_LIST_URL is
    // unset (the current default — the upstream catalog publisher no longer publishes the
    // kill-list feed, §7.7), `start()` itself is the documented no-op:
    // it logs a single `kill_list_watcher.disabled_no_url` INFO line and
    // returns without installing a timer or making any network call
    // (§7.7::2 — "finds the feed empty, emits a single INFO log per
    // startup, and has no runtime effect").
    const killListUrl = process.env.CHARIOT_KILL_LIST_URL?.trim();
    // CHARIOT::§7.7::2 — "has no runtime effect" when there is no feed to
    // consume. Parse/validate CHARIOT_KILL_LIST_INTERVAL_MS and
    // CHARIOT_KILL_LIST_MAX_QUIESCENCE_MS ONLY when a feed URL is actually
    // configured — a malformed tuning value for a feed that is not even
    // wired up must not throw and block startup. When `killListUrl` is
    // unset, `intervalMs`/`maxQuiescenceMs` stay `undefined` and
    // `KillListWatcher` takes its own no-op-no-url path below regardless
    // of what (if anything) those env vars happen to contain.
    let intervalMs: number | undefined;
    let maxQuiescenceMs: number | undefined;
    if (killListUrl) {
      const intervalEnv = process.env.CHARIOT_KILL_LIST_INTERVAL_MS;
      intervalMs = intervalEnv !== undefined && intervalEnv.trim() !== ''
        ? Number.parseInt(intervalEnv, 10)
        : undefined;
      if (intervalMs !== undefined && (!Number.isFinite(intervalMs) || intervalMs <= 0)) {
        throw new Error('Invalid CHARIOT_KILL_LIST_INTERVAL_MS: expected a positive integer.');
      }

      const maxQuiescenceEnv = process.env.CHARIOT_KILL_LIST_MAX_QUIESCENCE_MS;
      maxQuiescenceMs = maxQuiescenceEnv !== undefined && maxQuiescenceEnv.trim() !== ''
        ? Number.parseInt(maxQuiescenceEnv, 10)
        : undefined;
      if (maxQuiescenceMs !== undefined && (!Number.isFinite(maxQuiescenceMs) || maxQuiescenceMs <= 0)) {
        throw new Error('Invalid CHARIOT_KILL_LIST_MAX_QUIESCENCE_MS: expected a positive integer.');
      }
    }

    this.killListWatcher = new KillListWatcher({
      federation: this.federationManager,
      url: killListUrl,
      intervalMs,
      verifySignature: process.env.CHARIOT_KILL_LIST_VERIFY_SIGNATURE === 'false' ? false : true,
      publicKeyPem: process.env.CHARIOT_KILL_LIST_PUBLIC_KEY_PEM,
      maxQuiescenceMs,
    });
    this.killListWatcher.start();

    // CHARIOT::§7.5::1 — "instantiates each catalog-listed adapter, wires
    // it into the pool, registers its tools with ToolPreFilter, and
    // exposes a reload() for runtime adapter unload." `toolPreFilter`
    // wires `this.toolPreFilter` — the SAME instance passed to
    // Orchestrator below — so `loadAndWire()` (and every subsequent
    // `reload()`) actually calls `.index(federation.listTools())` on the
    // instance Orchestrator queries every `execute()` call, not a
    // separate, ignored one.
    this.registryLoader = new RegistryLoader({
      catalog: this.adapterCatalog,
      federation: this.federationManager,
      toolPreFilter: this.toolPreFilter,
    });
    await this.registryLoader.loadAndWire();

    // CHARIOT::§7.6::1 / §7.5::1 — F6 fix: ONE listener, serialized on
    // `this.catalogReconcile`, is the SOLE reaction to a catalog rebuild.
    // `FederationManager` was constructed with
    // `autoSyncCatalogRevocations: false` specifically so it does NOT
    // ALSO register its own listener — two independent listeners
    // (FederationManager's active-teardown sync and RegistryLoader's
    // add/remove reconciliation) could otherwise both observe the same
    // newly-revoked, still-connected adapter name and both tear it down
    // (duplicated ApprovalQueue cancellation + audit emission). Chaining
    // on the queue guarantees `syncCatalogRevocations()` (active teardown
    // of anything newly revoked) fully completes BEFORE `reload()` runs
    // (full add/remove reconciliation against the registry) — by the
    // time `reload()` calls `unloadAdapter()` for a name already torn
    // down above, that call hits the pre-existing "unknown adapter"
    // no-op path (adapterMap no longer has it), not a second revocation.
    this.adapterCatalog.onChanged(() => {
      this.catalogReconcile = this.catalogReconcile
        .then(() => this.federationManager.syncCatalogRevocations())
        .then(() => this.registryLoader?.reload())
        .then(() => undefined)
        .catch((err) => {
          this.auditTrail.record({
            timestamp: new Date(),
            action: 'federation.registry_loader.reload_failed',
            tool: '',
            server: '',
            tier: 'auto',
            status: 'failed',
            input: {},
            output: { error: err instanceof Error ? err.message : String(err) },
            persona: this.personaManager.active().name,
            durationMs: 0,
          }).catch(() => undefined);
        });
    });

    // CHARIOT::§8.12::1/::2 (W34-4b) — same structural cast pattern used
    // above for TieredAutonomy; this is the concrete ObservabilityEmitter
    // whenever config.observabilityEmitter is wired at all (a caller who
    // only wants OTel spans, not autonomy/resilience events, still passes
    // the same single emitter instance — there is one emitter, not one
    // per consumer).
    const stepEmitter = this.config.observabilityEmitter as ObservabilityEmitter | undefined;
    if (stepEmitter) {
      // CHARIOT::§8.12::2 — "off when unset": createOtlpHttpJsonSpanExporter
      // returns null when CHARIOT_OTEL_EXPORTER_OTLP_ENDPOINT is not
      // configured, so this is a no-op unless an operator sets it.
      const otlpExporter = createOtlpHttpJsonSpanExporter();
      if (otlpExporter) {
        stepEmitter.onEvent(createOTelEventCallback(otlpExporter));
      }
    }

    this.orchestrator = new Orchestrator({
      orchestratorLLM,
      generatorLLM,
      toolPreFilter: this.toolPreFilter,
      federation: this.federationManager,
      autonomy: this.tieredAutonomy,
      persona: this.personaManager,
      audit: this.auditTrail,
      maxIterations: this.config.orchestrator.maxIterations,
      tenantId: process.env.CHARIOT_TENANT_ID ?? 'local',
      // CHARIOT::§8.12::1 — wires 'step-trace' StreamEvents (StepTracer)
      // AND, via the onEvent subscription above, the OTLP exporter.
      // Previously never passed here at all — stepEmitter was always
      // undefined in production regardless of config.observabilityEmitter.
      stepEmitter,
      // CHARIOT::§8.12::5 — the one-per-instance token/cost ledger.
      tokenTracker: this.tokenTracker,
    });

    this.started = true;
  }

  async stop(): Promise<void> {
    if (!this.started) {
      throw new Error('Agent not started');
    }

    // Disconnect from all MCP servers
    this.killListWatcher?.stop();
    this.killListWatcher = null;
    await this.federationManager.disconnectAll();

    // Clean up autonomy timers
    this.tieredAutonomy.destroy();

    this.orchestrator = null;
    this.started = false;
  }

  /**
   * CHARIOT::§7.5::1 — "exposes a reload() for runtime adapter unload."
   * Public entrypoint onto `RegistryLoader.reload()`, reachable through
   * the `EpicAIAgent` surface (no lifecycle method for this existed on
   * the interface prior to this clause's implementation). Throws if the
   * agent has not been started yet (`this.registryLoader` is only set at
   * the end of `start()`'s wiring, after `loadAndWire()` first runs).
   */
  async reloadAdapters(): Promise<void> {
    if (!this.registryLoader) {
      throw new Error('Agent not started — call start() before reloadAdapters()');
    }
    // CHARIOT::§7.6::1 — F6 fix: route through the SAME serialization
    // queue the catalog.onChanged() listener uses, so a manual
    // reloadAdapters() call can never interleave with an in-progress
    // catalog-triggered reconciliation and double-teardown an adapter.
    const registryLoader = this.registryLoader;
    const chained = this.catalogReconcile.then(() => registryLoader.reload()).then(() => undefined);
    this.catalogReconcile = chained.catch(() => undefined);
    await chained;
  }

  /**
   * `sessionId` (CHARIOT::§8.2::3) — new optional parameter. There is no
   * session subsystem anywhere else in the engine (see Orchestrator.ts's
   * own comment at the buildSystemPrompt() call site: "runId has no
   * producer anywhere else in the engine — there is no session subsystem"),
   * so this plumbs a caller-supplied session identity through to
   * Orchestrator purely for MFA-assertion-binding attribution. No IAM-layer
   * caller in this repo passes one yet (see the W41 build report) — this is
   * additive so existing 2-arg/3-arg callers are unaffected.
   */
  /**
   * CHARIOT::§16.3::1 (CHARIOT-SPEC.md:1373, rulings item 91(3)) — "Token
   * usage by adapter (from §8.12 TokenTracker)." Structurally satisfies
   * `TokenUsageByAdapterSource` (src/observability/metrics.ts) by name
   * alone (`getTokenUsageByAdapter(): Record<string, {tokens, costUsd}>`).
   *
   * TWO ways this reaches a ChariotMetrics instance's getSummary()
   * (gate finding 114(i), W34-4c):
   *   1. Automatic — the constructor registers `this` with the
   *      process-wide registry (tokenUsageRegistry.ts), so ANY
   *      ChariotMetrics instance in the SAME process (e.g. `chariot
   *      serve`'s ChariotState.ts, which never imports EpicAI directly)
   *      picks it up with no second wiring call.
   *   2. Explicit override — a caller who owns both instances directly
   *      may still call `chariotMetrics.setTokenUsageSource(epicAI)`,
   *      which takes priority over the registry for that one
   *      ChariotMetrics instance.
   * A process that never constructs an EpicAI instance never registers a
   * source; ChariotMetrics.getSummary() then reports
   * `tokenUsageByAdapter: { available: false, reason: '...' }` — an
   * honest absence marker, not a silently-empty `{}`.
   */
  getTokenUsageByAdapter(): Record<string, { tokens: number; costUsd: number }> {
    return this.tokenTracker.summary().byAdapter;
  }

  async run(query: string, userId?: string, sourceIp?: string, sessionId?: string): Promise<RunResult> {
    if (!this.started || !this.orchestrator) {
      throw new Error('Agent not started. Call start() first.');
    }
    return this.orchestrator.run(query, userId, sourceIp, sessionId);
  }

  async *stream(query: string, userId?: string, sourceIp?: string, sessionId?: string): AsyncGenerator<StreamEvent> {
    if (!this.started || !this.orchestrator) {
      throw new Error('Agent not started. Call start() first.');
    }
    yield* this.orchestrator.stream(query, userId, sourceIp, sessionId);
  }

  async approve(actionId: string, opts: { approver: string }): Promise<ActionDecision> {
    validateActionId(actionId);
    const result = this.tieredAutonomy.approve(actionId, opts.approver);
    if (result instanceof Promise) {
      return result;
    }
    return result;
  }

  async deny(actionId: string, opts: { approver: string; reason: string }): Promise<ActionDecision> {
    validateActionId(actionId);
    const result = this.tieredAutonomy.deny(actionId, opts.approver, opts.reason);
    if (result instanceof Promise) {
      return result;
    }
    return result;
  }
}
