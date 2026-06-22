/**
 * @epicai/chariot — Type Definitions
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { ProbeEntry } from '../observability/LinearProbeReadout.js';

// =============================================================================
// LLM Provider Types
// =============================================================================

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  tool_call_id?: string;
  name?: string;
}

export interface LLMToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface LLMToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface LLMResponse {
  content: string | null;
  toolCalls: LLMToolCall[];
  finishReason: 'stop' | 'tool_calls' | 'length' | 'error' | 'content-filter' | 'refusal';
  /**
   * Optional hidden-state buffer from a local SLM (e.g. vLLM with
   * --return-hidden-states, llama.cpp embeddings API).  Absent on the
   * cloud-LLM path where the model is the customer's and internal
   * representations are unavailable.  When present, the Orchestrator
   * passes this to LinearProbeReadout.read() to emit 'selection-probe'
   * StreamEvents before federation.callTool. 
   */
  hiddenState?: Float32Array | number[];
}

export type LLMFunction = (params: {
  messages: LLMMessage[];
  tools?: LLMToolDefinition[];
}) => Promise<LLMResponse>;

// =============================================================================
// Orchestrator / Generator Configuration
// =============================================================================

export interface OrchestratorConfig {
  provider: 'auto' | 'ollama' | 'vllm' | 'apple-foundation' | 'custom';
  model: string;
  adapter?: string;
  baseUrl?: string;
  timeoutMs?: number;
  maxIterations?: number;
  logLevel?: 'debug' | 'info' | 'warn' | 'error' | 'off';
  llm?: LLMFunction;
}

export interface GeneratorConfig {
  provider: 'openai' | 'anthropic' | 'ollama' | 'digitalocean' | 'custom';
  model: string;
  apiKey?: string;
  baseUrl?: string;
  timeoutMs?: number;
  maxTokens?: number;
  llm?: LLMFunction;
}

// =============================================================================
// Federation Types
// =============================================================================

export interface AuthConfig {
  type: 'bearer' | 'basic' | 'api-key';
  token?: string;
  username?: string;
  password?: string;
  clientId?: string;
  clientSecret?: string;
  headerName?: string;
}

export interface ServerConnection {
  name: string;
  transport: 'stdio' | 'streamable-http';
  url?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  auth?: AuthConfig;
  timeoutMs?: number;
  /**
   * Supply-chain integrity fields for npm stdio adapters (air-gap guarantee).
   * When set, MCPClientAdapter.connect() verifies the tarball is present in
   * the local npm cache with the expected SHA-512 digest BEFORE spawning.
   * Absent on non-npm adapters (uvx, git, HTTP).
   */
  integrityPkg?: string;     // npm package name (e.g. `@scope/pkg`)
  integrityVersion?: string; // pinned version (e.g. `0.6.2`)
  integrityShasum?: string;  // SHA-512 hex digest from the adapter catalog
}

export interface RetryPolicy {
  maxRetries: number;
  backoffMs: number;
  maxBackoffMs?: number;
}

export type ConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error';

export interface ConnectionHealth {
  server: string;
  status: ConnectionStatus;
  lastPingMs?: number;
  lastError?: string;
  toolCount: number;
}

export interface FederationConfig {
  servers: ServerConnection[];
  retryPolicy?: RetryPolicy;
  healthCheckIntervalMs?: number;
}

export type ToolTier = 'orchestrated' | 'direct';

export interface Tool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  server: string;
  tier: ToolTier;
}

/**
 * four-outcome partition (Adaline rule 2). Distinguishes
 * "we don't know" from "we know it failed" so operators can act on
 * post-write timeouts without conflating them with rejected calls.
 */
export type CallOutcome = 'success' | 'explicit_failure' | 'timeout' | 'unknown' | 'escalated' | 'stopped_by_policy';

/**
 * idempotency classification for the tool/adapter. Publisher
 * heuristic stamps from tool-name prefix. 'safe' = no key needed,
 * 'unsafe' = key required, 'unknown' = warn-and-proceed (attach key
 * anyway since the downstream may honor it).
 */
export type Idempotent = 'safe' | 'unsafe' | 'unknown';

/**
 * per-tool failure policy (Adaline rule 3). Authored by the
 * adapter publisher, consumed by fetchWithRetryTelemetry, and stamped
 * onto ToolResult/ActionRecord via the CallOutcome enum when a policy
 * decision short-circuits the dispatch.
 */
export type PolicyAction = 'retry' | 'escalate' | 'stop';
export interface FailurePolicy {
  onTimeout: PolicyAction;
  onRateLimit: PolicyAction;
  on5xx: PolicyAction;
  maxRetries: number;
}
export const DEFAULT_FAILURE_POLICY: FailurePolicy = {
  onTimeout: 'retry',
  onRateLimit: 'retry',
  on5xx: 'retry',
  maxRetries: 3,
};

/**
 * error classification (Adaline mode 2: 60% of LLM-agent errors
 * are rate-limit class). Distinct from CallOutcome: outcome says "did the
 * call complete," errorClass says "what kind of failure." Absent on success.
 */
// spec dispatch-correctness-2026-05.md enumerates 'invalid_arguments'
// for per-tool input-schema rejection, 'policy_violation' for sub-agent
// widening attempts, and 'unauthorized' for expired approvals
//. 'validation' is retained for adapter-side validateInput throws
// (REST path) where the source of the rejection is the adapter module
// rather than the federation-layer schema gate.
export type ErrorClass =
  | 'rate_limit'
  | 'timeout'
  | 'auth'
  | 'validation'
  | 'invalid_arguments'
  | 'policy_violation'
  | 'unauthorized'
  | 'vendor_5xx'
  | 'unknown';

export interface ToolResult {
  content: unknown;
  isError: boolean;
  server: string;
  tool: string;
  durationMs: number;
 // retry telemetry, optional so legacy producers don't need migration.
  retryCount?: number;
  retryReasons?: string[];
 // four-outcome partition.
  outcome?: CallOutcome;
 // error classification.
  errorClass?: ErrorClass;
}

export interface CorrelationQuery {
  timeRange: { start: Date; end: Date };
  entities: string[];
  servers?: string[];
}

export interface CorrelatedEntity {
  id: string;
  sources: { server: string; data: Record<string, unknown> }[];
}

export interface CorrelatedEvent {
  timestamp: Date;
  server: string;
  tool: string;
  entity: string;
  data: Record<string, unknown>;
}

export interface CorrelationResult {
  entities: Map<string, CorrelatedEntity>;
  timeline: CorrelatedEvent[];
  serversCovered: string[];
}

// =============================================================================
// Autonomy Types
// =============================================================================

export interface AutonomyRules {
  auto: string[];
  escalate: string[];
  approve: string[];
}

export interface ActionContext {
  tool: string;
  server: string;
  args: Record<string, unknown>;
  persona: string;
  userId?: string;
  timestamp: Date;
  priorActions: ActionRecord[];
}

export interface AutonomyPolicy {
  name: string;
  condition: (action: ActionContext) => boolean;
  override: 'auto' | 'escalate' | 'approve';
  priority?: number;
}

export type ApprovalState = 'pending' | 'approved' | 'denied' | 'expired';

export interface PendingApproval {
  id: string;
  action: ActionContext;
  tier: 'escalate' | 'approve';
  state: ApprovalState;
  createdAt: Date;
  expiresAt: Date;
  decidedAt?: Date;
  decidedBy?: string;
  denyReason?: string;
}

export interface ActionDecision {
  id: string;
  action: string;
  tier: 'auto' | 'escalate' | 'approve';
  allowed: boolean;
  reason?: string;
  approvedBy?: string;
  timestamp: Date;
  policyApplied?: string;
}

export interface ApprovalQueueConfig {
  persistence: 'memory' | 'redis';
  redis?: { host: string; port: number; password?: string };
  ttlMs: number;
  onExpire?: 'deny' | 'escalate-to-admin';
}

export interface AutonomyConfig {
  tiers: AutonomyRules;
  policies?: AutonomyPolicy[];
  approvalQueue?: ApprovalQueueConfig;
}

// =============================================================================
// Memory Types
// =============================================================================

export type MemoryImportance = 'normal' | 'medium' | 'high';

export interface MemoryEntry {
  type: string;
  content: unknown;
  metadata?: Record<string, unknown>;
  importance: MemoryImportance;
}

export interface StoredMemory extends MemoryEntry {
  id: string;
  userId: string;
  createdAt: Date;
  accessCount: number;
  lastAccessed: Date | null;
  isDeleted: boolean;
  deletedAt?: Date;
}

export interface RecallOptions {
  type?: string;
  importance?: MemoryImportance;
  limit?: number;
  since?: Date;
  sortBy?: 'importance' | 'recency' | 'frequency';
}

export interface ContextSummary {
  totalMemories: number;
  memoryTypes: Map<string, number>;
  lastInteraction: Date | null;
  importantMemories: number;
  oldestMemory: Date | null;
  newestMemory: Date | null;
}

/**
 * Actor identity supplied to save() for importance-tier capability enforcement.
 * When absent (undefined), the store falls back to legacy behaviour and accepts
 * any importance value — preserving backwards-compatibility with callers that
 * pre-date .
 */
export interface MemoryActor {
  isAdmin?: boolean;
  capabilities?: MemoryCapability[];
}

/**
 * Per-scope capacity snapshot returned by getCapacityStatus().
 * Allows ops tooling to detect scopes approaching the eviction threshold.
 */
export interface CapacityStatus {
  entries: number;
  cap: number;
  nearCap: boolean;
}

export interface MemoryStoreAdapter {
  /**
   * Persist a new memory entry for the given userId.
   *
 * When `actor` is supplied and the actor lacks the `memory:high`
   * capability (and is not an admin), importance:'high' is silently downgraded
   * to 'medium'. When `actor` is undefined, all importance values are accepted
   * (legacy caller compatibility).
   *
 * If the per-scope capacity cap is reached, the lowest-importance /
   * oldest entry is evicted before the new entry is inserted. If the per-scope
   * high-importance cap is reached and the effective importance is 'high', save
   * rejects with a structured error.
   */
  save(userId: string, entry: MemoryEntry, actor?: MemoryActor): Promise<StoredMemory>;

  /**
   * Retrieve stored memories — **read-only**.
   *
 * recall() MUST NOT mutate accessCount, lastAccessed, or importance.
   * Callers that want access tracking MUST call recordAccess() separately.
   * Importance promotion MUST be performed via promoteImportance() — never
   * implicitly inside recall().
   */
  recall(userId: string, options: RecallOptions): Promise<StoredMemory[]>;

  context(userId: string): Promise<ContextSummary>;
  delete(userId: string, memoryId: string): Promise<void>;

  /**
   * Increment accessCount and set lastAccessed for the given memoryId.
   * No-op if the entry does not exist or is soft-deleted.
   *
 * This is the ONLY path that may mutate access metadata.
   */
  recordAccess(memoryId: string): Promise<void>;

  /**
   * Explicitly promote (or demote) the importance tier of a stored memory.
   *
 * Promoting to 'high' is subject to the per-scope cap
   * (MAX_HIGH_IMPORTANCE_PER_SCOPE). If the scope is at cap, this method
   * rejects with a structured error: { code: 'HIGH_IMPORTANCE_CAP_EXCEEDED' }.
   * Callers should catch and handle.
   *
   * No-op if the entry does not exist or is soft-deleted.
   */
  promoteImportance(memoryId: string, newImportance: MemoryImportance): Promise<void>;

  /**
   * Return current capacity metrics for a given userId scope.
   * nearCap is true when entries >= 90% of cap.
   */
  getCapacityStatus(userId: string): Promise<CapacityStatus>;
}

export interface MemoryConfig {
  store: MemoryStoreAdapter;
  cacheTTLMs: number;
  /**
   * Optional AES-256-GCM encryption key (32-byte hex string, 64 hex chars).
   * When present, memory entry content is encrypted before storage and
   * decrypted transparently on retrieval. When absent, behavior is unchanged.
   */
  encryptionKey?: string;
}

export interface RetrievalConfig {
  memory?: {
    store: string;
    redis?: { host: string; port: number; password?: string };
    mongo?: { uri: string; db: string };
    cacheTTLMs?: number;
  };
}

// =============================================================================
// Persona Types
// =============================================================================

export interface PersonaConfig {
  name: string;
  tone: string;
  domain: string;
  systemPrompt: string;
  vocabulary?: Record<string, string>;
  constraints?: string[];
  adapterPath?: string;
}

export interface ConversationContext {
  userId: string;
  sessionId: string;
  messageHistory: LLMMessage[];
  retrievedMemories: StoredMemory[];
  activeTools: string[];
}

// =============================================================================
// Step-Level Attribution Types
// =============================================================================

/**
 * The kind of step within a multi-step agent run.
 * Used by StepTracer and stored on ActionRecord.stepKind for post-hoc attribution.
 */
export type StepKind =
  | 'orchestrator-plan'
  | 'tool-call'
  | 'dlp-sanitize'
  | 'retrieval'
  | 'synthesis'
  | 'refusal';

/**
 * MAST failure mode taxonomy — Cemri et al., arXiv:2503.13657 (March 2025).
 * 14 modes across 3 root-cause categories derived from 1,642 annotated
 * multi-agent execution traces across 7 MAS frameworks (MetaGPT, ChatDev,
 * HyperAgent, AppWorld, AG2, Magentic-One, OpenManus).
 *
 * Used on ActionRecord.failureMode for non-success outcomes (status='failed').
 * undefined on successful or pending records.
 */
export type FailureMode =
  // FC1 — System Design Issues (5 modes)
  | 'FM-1.1_DISOBEY_TASK_SPEC'
  | 'FM-1.2_DISOBEY_ROLE_SPEC'
  | 'FM-1.3_STEP_REPETITION'
  | 'FM-1.4_LOSS_OF_CONV_HISTORY'
  | 'FM-1.5_UNAWARE_TERMINATION_CONDITIONS'
  // FC2 — Inter-Agent Misalignment (6 modes)
  | 'FM-2.1_CONVERSATION_RESET'
  | 'FM-2.2_FAIL_TO_CLARIFY'
  | 'FM-2.3_TASK_DERAILMENT'
  | 'FM-2.4_INFO_WITHHOLDING'
  | 'FM-2.5_IGNORED_AGENT_INPUT'
  | 'FM-2.6_REASONING_ACTION_MISMATCH'
  // FC3 — Task Verification (3 modes)
  | 'FM-3.1_PREMATURE_TERMINATION'
  | 'FM-3.2_INCOMPLETE_VERIFICATION'
  | 'FM-3.3_INCORRECT_VERIFICATION'
  // Operational — could not classify into any of the 14 MAST modes
  | 'UNKNOWN';

// =============================================================================
// Audit Types
// =============================================================================

export interface ActionRecord {
  id: string;
  sequenceNumber: number;
  previousHash: string;
  timestamp: Date;
  action: string;
  tool: string;
  server: string;
  tier: 'auto' | 'escalate' | 'approve';
  /**
   * Execution status.
   * - 'pending'   — recorded before tool execution begins; guarantees an audit
   *                 entry exists even if the process crashes mid-execution.
   * - 'completed' — tool returned successfully.
   * - 'failed'    — tool threw or returned isError=true.
   */
  status: 'pending' | 'completed' | 'failed';
  input: Record<string, unknown>;
  output: Record<string, unknown>;
  persona: string;
  approvedBy?: string;
  deniedBy?: string;
  denyReason?: string;
  durationMs: number;
  hash: string;

  // step-level attribution — participates in SHA-256 hash chain
  // (HashChain.computeHash excludes only status/output/durationMs; these
  //  immutable fields hash by default).
  traceId?: string;          // UUID v4 shared across all records in one run
  parentStepId?: string;     // UUID of the parent step (null if root step)
  stepKind?: StepKind;       // which step category produced this record
  confidence?: number | null; // 0.0–1.0 or null when not computable

  // Retry telemetry (reserved here for additive schema)
  retryCount?: number;       // number of retry attempts before final outcome
  retryReasons?: string[];   // per-attempt failure reason strings

 // four-outcome partition. Distinct from `status` (which is
  // pending/completed/failed): `outcome` tells you whether a completed
  // record landed cleanly, was rejected, timed out, or has an unknown
  // post-state. Absent on legacy rows; readers treat absence as 'unknown'.
  outcome?: CallOutcome;

 // error class. Independent of outcome and failureMode:
  // outcome=did-it-complete; errorClass=what-kind-of-failure;
  // failureMode=MAST taxonomy. Absent on success.
  errorClass?: ErrorClass;

  // MAST 14-mode failure taxonomy classification
  failureMode?: FailureMode; // undefined on pending/completed records
}

export interface AuditFilter {
  since?: Date;
  until?: Date;
  tier?: 'auto' | 'escalate' | 'approve';
  server?: string;
  tool?: string;
  persona?: string;
  approvedBy?: string;
  limit?: number;
  offset?: number;
}

export interface AuditStoreAdapter {
  append(record: ActionRecord): Promise<void>;
  query(filter: AuditFilter): Promise<ActionRecord[]>;
  verify(): Promise<{ valid: boolean; chainLength: number; brokenAt?: number }>;
  /**
   * Update the status and output of a previously recorded pending entry.
   * Implementations should mutate in-place (in-memory) or append a
   * status-update record (append-only stores). Optional — when not implemented
   * the update is silently skipped.
   */
  updateStatus?(
    id: string,
    status: 'completed' | 'failed',
    output: Record<string, unknown>,
    durationMs: number,
    /**
     * Optional immutable metadata to persist alongside the status flip.
     * `failureMode` is the classification per the MAST taxonomy on
     * non-success outcomes. Implementations MUST persist the supplied
     * fields so that downstream readers reconstructing the merged record
     * (e.g. `chariot trace explain`) see the failureMode alongside the
     * status. Implementations MUST NOT write `failureMode: null` —
     * absence is the off-state.
     */
    opts?: { failureMode?: FailureMode; retryCount?: number; retryReasons?: string[]; outcome?: CallOutcome; errorClass?: ErrorClass },
  ): Promise<void>;
}

export interface AuditConfig {
  store: 'append-only-log' | 'memory' | 'sqlite' | 'custom';
  path?: string;
  adapter?: AuditStoreAdapter;
  integrity: 'sha256-chain' | 'none';
  retention?: {
    maxAgeDays?: number;
    maxSizeBytes?: number;
  };
  export?: ('json' | 'csv' | 'syslog')[];
}

// =============================================================================
// Transport Types
// =============================================================================

export type TransportMode = 'sse' | 'json';

export type StreamEventType =
  | 'plan'
  | 'action'
  | 'approval-needed'
  | 'result'
  | 'memory'
  | 'narrative'
  | 'source-attribution'
  | 'no-narrative'
  | 'error'
  | 'done'
  | 'selection-probe'
  | 'step-trace'
  | 'tool-call-retry'
  | 'drift-detected';

// Discriminated union — each event type has an exact payload shape
export interface PlanEvent { type: 'plan'; data: { iteration: number; toolCalls: string[]; durationMs: number }; timestamp: Date }
export interface ActionEvent { type: 'action'; data: { tool: string; server: string; durationMs: number }; timestamp: Date }
export interface ApprovalNeededEvent { type: 'approval-needed'; data: { actionId: string; tool: string; server: string; tier: string; durationMs: number }; timestamp: Date }
export interface ResultEvent { type: 'result'; data: { tool: string; content: unknown; isError: boolean }; timestamp: Date }
export interface NarrativeEvent { type: 'narrative'; data: { text: string; durationMs: number; sources?: { server: string; tool: string; toolCallId: string | null }[]; truncated?: boolean }; timestamp: Date }
export interface SourceAttributionEvent { type: 'source-attribution'; data: { sources: { server: string; tool: string; toolCallId: string | null }[] }; timestamp: Date }
/**
 * OWASP LLM09 Risk Communication — emitted when toolResults > 0 but
 * synthesis.content is empty so the consumer can distinguish refusal /
 * content-filter / token-budget-truncation from "no answer." `reason`
 * is derived from the LLM provider's finishReason at the synthesis
 * step. `sources` preserves which tools ran even though no narrative
 * accompanied them.
 */
export interface NoNarrativeEvent { type: 'no-narrative'; data: { reason: 'refusal' | 'content-filter' | 'token-budget' | 'empty-synthesis' | 'unknown'; sources: { server: string; tool: string; toolCallId: string | null }[] }; timestamp: Date }
export interface MemoryEvent { type: 'memory'; data: { etched: boolean; findingsCount: number; durationMs: number }; timestamp: Date }
export interface ErrorEvent { type: 'error'; data: { message: string; tool?: string; server?: string }; timestamp: Date }
export interface DoneEvent { type: 'done'; data: { loopIterations: number; actionsExecuted: number; actionsPending: number; timing: RunTiming }; timestamp: Date }

/**
 * Linear-probe observability hook.
 *
 * Emitted ONCE per orchestrator iteration (= one LLM forward pass = one
 * hidden state) BEFORE any federation.callTool dispatch when a
 * LinearProbeReadout implementation is wired into OrchestratorDeps and
 * the LLM response carries a hidden-state buffer.
 *
 * Cardinality rationale: the probe reads the LLM's internal representation
 * at the final input-token position, which is computed exactly once per
 * planResponse. Emitting per-toolCall would duplicate identical probe data
 * across N events when the LLM returns N parallel calls. One probe per
 * forward pass is the physically meaningful unit.
 *
 * Read-only: does not alter selection behavior.
 */
export interface SelectionProbeEvent {
  type: 'selection-probe';
  data: {
    /**
     * Top-3 tool predictions by linear-probe confidence (sorted descending).
     * May be fewer than 3 if the probe returned fewer entries.
     */
    topThree: ProbeEntry[];
    /**
     * The tool name the orchestrator LLM actually selected this iteration.
     * Set to the single tool name when planResponse.toolCalls.length === 1
     * (unambiguous single-pick comparison). Set to null when multiple tool
     * calls are present in the same planResponse (ambiguous; consumers
     * comparing probe-vs-pick should treat this as "not comparable").
     */
    llmActualPick: string | null;
    /**
     * 0-based iteration index within the orchestrator execute loop.
     */
    iteration: number;
  };
  timestamp: Date;
}

/**
 * Step-level attribution event.
 *
 * Emitted by StepTracer at the start and end of each step boundary
 * (orchestrator-plan, tool-call, dlp-sanitize, retrieval, synthesis, refusal).
 * Persisted through AuditTrail.record so step events inherit hash-chain integrity.
 */
export interface StepTraceEvent {
  type: 'step-trace';
  data: {
    stepId: string;                       // UUID v4 unique to this step
    parentStepId: string | null;          // parent step UUID; null for run-root steps
    traceId: string;                      // UUID v4 shared across all steps in one run
    kind: StepKind;                       // step category (see StepKind)
    phase: 'start' | 'end';              // start emitted before fn(); end emitted after
    input: Record<string, unknown>;       // sanitized — no credential values
    output: Record<string, unknown>;      // populated on phase='end' only
    confidence: number | null;            // 0.0–1.0 or null when not computable
    durationMs: number;                   // 0 on phase='start'; elapsed on phase='end'
  };
  timestamp: Date;
}

/**
 * Retry-count telemetry event.
 *
 * Emitted by MCPAdapterBase.fetchWithRetryTelemetry once per retry attempt,
 * before the back-off delay. Operators pipe these to Grafana/Loki to detect
 * the "third-attempt-always-works" degradation signal.
 *
 * Alert threshold: mean retryCount per adapter > 1.5 across a 15-minute window.
 */
export interface ToolCallRetryEvent {
  type: 'tool-call-retry';
  data: {
    adapterId: string;
    toolName: string;
    /** 1-indexed: 1 = first retry after the initial failed attempt. */
    attempt: number;
    /** Human-readable failure reason, e.g. "429 rate-limited", "503 Service Unavailable". */
    reason: string;
  };
  timestamp: Date;
}

/**
 * policy decision event. Fires once when a per-tool
 * FailurePolicy short-circuits the dispatch (escalate or stop). Carries
 * the trigger (timeout / rate_limit / 5xx) and the policy that was
 * applied so operator dashboards can attribute the run termination.
 */
/**
 * activation steering applied (arxiv 2605.07990). Emitted
 * once when the Orchestrator's ActivationSteerer modifies a hidden
 * state via a per-category steering vector.
 */
export interface SteeringAppliedEvent {
  type: 'steering-applied';
  data: {
    modelName: string;
    layer: number;
    category: string;
    weight: number;
  };
  timestamp: Date;
}

/**
 * PROBE&PREFILL probe decision (arxiv 2605.09252).
 * Emitted once per Orchestrator decide() call when a local SLM supplies
 * hidden states. 'unsupported' fires when hidden states aren't available
 * (cloud LLM or Ollama path).
 */
export interface ProbeDecisionEvent {
  type: 'probe-decision';
  data: {
    decision: 'tool-needed' | 'no-tool' | 'unsupported';
    probability?: number;
    threshold: number;
  };
  timestamp: Date;
}

/**
 * context-budget-exceeded event (Chroma 2025 / Adaline mode 1).
 * Fires when a chariot_query / chariot_call would push the running
 * per-tenant context cost over CHARIOT_CONTEXT_BUDGET_TOKENS.
 */
export interface ContextBudgetExceededEvent {
  type: 'context-budget-exceeded';
  data: {
    tenantId: string;
    currentTokens: number;
    budgetTokens: number;
    wouldAddTokens: number;
  };
  timestamp: Date;
}

/**
 * emitted once per ToolPreFilter.select() call with the
 * cumulative token cost of the returned shortlist. Operators query
 * `chariot_tool_shortlist_token_cost` distribution to validate per-
 * tenant budget enforcement.
 */
export interface ShortlistTokenCostEvent {
  type: 'shortlist-token-cost';
  data: {
    totalTokens: number;
    toolCount: number;
    maxTokens?: number;
    maxTools: number;
  };
  timestamp: Date;
}

/**
 * immutable approval-rule snapshot inherited by a sub-agent
 * at delegation time. Spawn helper produces this; sub-agent cannot
 * widen its own approval surface mid-run (narrow-only contract).
 */
export interface SubAgentContext {
  readonly parentAgentId: string;
  readonly inheritedApprovalRules: ReadonlySet<string>;
  readonly manifestHash: string;
  readonly spawnedAt: Date;
}

/**
 * sub-agent spawn event. Recorded once per delegation with
 * the manifest hash so an auditor can reconstruct exactly which
 * approvals the child was authorized to use.
 */
export interface SubAgentSpawnEvent {
  type: 'sub-agent-spawn';
  data: {
    parentAgentId: string;
    manifestHash: string;
    ruleCount: number;
    spawnedAt: Date;
  };
  timestamp: Date;
}

/**
 * approval-required event. Fires once when a tool flagged
 * requiresApproval=true is invoked without a matching pre-approval in the
 * approval registry. Operators wire this to a webhook, queue, or external approval system.
 */
export interface ApprovalRequiredEvent {
  type: 'approval-required';
  data: {
    adapterId: string;
    toolName: string;
    tenantId: string;
    argsHash: string;
    approvalKey: string;
  };
  timestamp: Date;
}

/**
 * parameter validation rejection event. Fires when the
 * federation/handler layer's per-tool input-schema gate rejects args
 * before adapter dispatch. Operators aggregate to track the cascade-
 * prevention rate (AgentProp-Bench 62% baseline).
 */
export interface ParameterValidationRejectedEvent {
  type: 'parameter-validation-rejected';
  data: {
    adapterId: string;
    toolName: string;
    issues: Array<{ path: string; message: string; code: string }>;
  };
  timestamp: Date;
}

export interface PolicyDecisionEvent {
  type: 'policy-decision';
  data: {
    adapterId: string;
    toolName: string;
    trigger: 'timeout' | 'rate_limit' | '5xx';
    action: 'escalate' | 'stop';
    policy: FailurePolicy;
  };
  timestamp: Date;
}

/**
 * error-class telemetry event. Fires once when fetchWithRetry
 * exhausts retries and classifies the final failure into an ErrorClass.
 */
export interface ToolErrorClassifiedEvent {
  type: 'tool-error-classified';
  data: {
    adapterId: string;
    toolName: string;
    errorClass: ErrorClass;
  };
  timestamp: Date;
}

/** Micro-step timing breakdown for a single run */
export interface RunTiming {
  totalMs: number;
  retrievalMs: number;
  orchestratorMs: number;
  federationMs: number;
  autonomyMs: number;
  generatorMs: number;
  memoryMs: number;
}

/**
 * Production drift-detection event.
 *
 * Emitted by DriftDetector when a watched signal's z-score exceeds the
 * configured threshold (default 2.0) over the prior 7-day rolling window.
 *
 * The always-on DriftAlertWorker consumes these events (via the shared
 * alert JSONL file) and escalates to the existing IncidentSeverity pipeline.
 */
export interface DriftDetectedEvent {
  type: 'drift-detected';
  data: {
    /** Signal key: 'top1Accuracy' | 'errorRate:<adapterId>' | 'meanRetry:<adapterId>' | 'verdictDist' */
    signal: string;
    /** Current window value (most recent hourly sample). */
    currentValue: number;
    /** Mean of the prior 7-day rolling window (excluding current). */
    rollingMean: number;
    /** Std dev of the prior 7-day rolling window (Bessel-corrected). */
    rollingStdDev: number;
    /** z-score: (currentValue - rollingMean) / rollingStdDev */
    zScore: number;
    /** ISO timestamp of detection. */
    timestamp: string;
  };
  timestamp: Date;
}

export type StreamEvent =
  | PlanEvent
  | ActionEvent
  | ApprovalNeededEvent
  | ResultEvent
  | NarrativeEvent
  | SourceAttributionEvent
  | NoNarrativeEvent
  | MemoryEvent
  | ErrorEvent
  | DoneEvent
  | SelectionProbeEvent
  | StepTraceEvent
  | DriftDetectedEvent
  | ToolCallRetryEvent
  | ToolErrorClassifiedEvent
  | PolicyDecisionEvent
  | ParameterValidationRejectedEvent
  | ApprovalRequiredEvent
  | SubAgentSpawnEvent
  | ShortlistTokenCostEvent
  | ContextBudgetExceededEvent
  | ProbeDecisionEvent
  | SteeringAppliedEvent;

export interface RunResult {
  response: string;
  events: StreamEvent[];
  actionsExecuted: number;
  actionsPending: number;
  persona: string;
  durationMs: number;
}

// =============================================================================
// Top-Level Configuration
// =============================================================================

export interface EpicAIConfig {
  orchestrator: OrchestratorConfig;
  generator?: GeneratorConfig;
  federation: FederationConfig;
  autonomy: AutonomyConfig;
  retrieval?: RetrievalConfig;
  persona: PersonaConfig;
  audit: AuditConfig;
  transport?: TransportMode;
 // optional emitter wired down through FederationManager so adapter
  // retries surface as 'tool-call-retry' StreamEvents and persist on
  // ActionRecord.
  observabilityEmitter?: ObservabilityEmitterContract;
}

/**
 * minimal contract used by EpicAIConfig to avoid a hard import
 * cycle between types and observability. The concrete ObservabilityEmitter
 * implements this; consumers depend only on emitToolCallRetry.
 */
export interface ObservabilityEmitterContract {
  emitToolCallRetry(payload: { adapterId: string; toolName: string; attempt: number; reason: string }): void;
 // emitted once on retry exhaustion (or single-shot 4xx) with the
  // classified ErrorClass. Implementations that don't surface this signal
  // can no-op the method.
  emitToolErrorClassified(payload: { adapterId: string; toolName: string; errorClass: ErrorClass }): void;
 // emitted once when a FailurePolicy short-circuits dispatch
  // (escalate or stop). Implementations that don't surface this signal
  // can no-op the method.
  emitPolicyDecision(payload: { adapterId: string; toolName: string; trigger: 'timeout' | 'rate_limit' | '5xx'; action: 'escalate' | 'stop'; policy: FailurePolicy }): void;
 // emitted once when a per-tool input-schema validation rejects
  // args before adapter dispatch. Operators aggregate to track the
  // cascade-prevention rate.
  emitParameterValidationRejected(payload: { adapterId: string; toolName: string; issues: Array<{ path: string; message: string; code: string }> }): void;
 // emitted once when a tool requires approval and the registry
  // has no pre-approval for the call. Operators wire to a webhook or queue.
  emitApprovalRequired(payload: { adapterId: string; toolName: string; tenantId: string; argsHash: string; approvalKey: string }): void;
 // emitted once when a sub-agent is spawned with an inherited
  // approval-rule manifest. Operators reconstruct authorization scope from
  // the recorded manifestHash.
  emitSubAgentSpawn(payload: { parentAgentId: string; manifestHash: string; ruleCount: number; spawnedAt: Date }): void;
 // emitted once per ToolPreFilter.select() call with the
  // cumulative token cost of the returned shortlist (chariot_tool_shortlist_token_cost).
  emitShortlistTokenCost(payload: { totalTokens: number; toolCount: number; maxTokens?: number; maxTools: number }): void;
 // emitted once per chariot response that would push the running
  // per-tenant context cost past CHARIOT_CONTEXT_BUDGET_TOKENS.
  emitContextBudgetExceeded(payload: { tenantId: string; currentTokens: number; budgetTokens: number; wouldAddTokens: number }): void;
 // emitted once per ToolNecessityProbe.decide() call.
  emitProbeDecision(payload: { decision: 'tool-needed' | 'no-tool' | 'unsupported'; probability?: number; threshold: number }): void;
 // emitted once when ActivationSteerer modifies a hidden state.
  emitSteeringApplied(payload: { modelName: string; layer: number; category: string; weight: number }): void;
}

// =============================================================================
// Agent Interface
// =============================================================================

export interface EpicAIAuditAccessor {
  query(filter: AuditFilter): Promise<ActionRecord[]>;
  verify(): Promise<{ valid: boolean; chainLength: number; brokenAt?: number }>;
  export(format: 'json' | 'csv' | 'syslog'): Promise<string>;
}

export interface EpicAIFederationAccessor {
  health(): ConnectionHealth[];
  listTools(): Tool[];
}

export interface EpicAIAutonomyAccessor {
  pending(): Promise<PendingApproval[]>;
  listPolicies(): AutonomyPolicy[];
}

export interface EpicAIAgent {
  start(): Promise<void>;
  stop(): Promise<void>;
  run(query: string): Promise<RunResult>;
  stream(query: string): AsyncGenerator<StreamEvent>;
  approve(actionId: string, opts: { approver: string }): Promise<ActionDecision>;
  deny(actionId: string, opts: { approver: string; reason: string }): Promise<ActionDecision>;
  readonly audit: EpicAIAuditAccessor;
  readonly federation: EpicAIFederationAccessor;
  readonly autonomy: EpicAIAutonomyAccessor;
}

/**
 * Chariot error codes — single source of truth for structured-error `code` values
 * emitted across the engine surface (toolHandlers, AdapterCatalog, license, memory,
 * autonomy, audit, IAM). Use this union on every error object so renames are a
 * single-site change and typos are caught at compile time.
 */
export type ChariotErrorCode =
  | 'RATE_LIMIT_EXCEEDED'
  | 'TOOL_DEPTH_EXCEEDED'
  | 'TOOL_FANOUT_EXCEEDED'
  | 'RESPONSE_TOO_LARGE'
  | 'ARG_DEPTH_EXCEEDED'
  | 'ARG_PAYLOAD_TOO_LARGE'
  | 'RBAC_OPERATION_DENIED'
  | 'TOOL_NOT_REGISTERED'
  | 'TOOL_NOT_SURFACED_IN_SESSION'
  | 'CATALOG_INTEGRITY_ERROR'
  | 'HIGH_IMPORTANCE_CAP_EXCEEDED'
  | 'APPROVAL_QUEUE_CAP_EXCEEDED'
  | 'LICENSE_REVOKED'
  | 'LICENSE_EXPIRED'
  | 'LICENSE_NOT_YET_VALID'
  | 'LICENSE_TENANT_MISMATCH'
  | 'TSA_NOT_CONFIGURED'
  | 'ANCHOR_VERIFY_FAILED'
  | 'LENGTH_ATTESTATION_FAILED'
  | 'CHAIN_TRUNCATION_DETECTED'
  | 'CLAIM_VALIDATION_ARG_MISSING';

export const CHARIOT_ERROR_CODES = {
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  TOOL_DEPTH_EXCEEDED: 'TOOL_DEPTH_EXCEEDED',
  TOOL_FANOUT_EXCEEDED: 'TOOL_FANOUT_EXCEEDED',
  RESPONSE_TOO_LARGE: 'RESPONSE_TOO_LARGE',
  ARG_DEPTH_EXCEEDED: 'ARG_DEPTH_EXCEEDED',
  ARG_PAYLOAD_TOO_LARGE: 'ARG_PAYLOAD_TOO_LARGE',
  RBAC_OPERATION_DENIED: 'RBAC_OPERATION_DENIED',
  TOOL_NOT_REGISTERED: 'TOOL_NOT_REGISTERED',
  TOOL_NOT_SURFACED_IN_SESSION: 'TOOL_NOT_SURFACED_IN_SESSION',
  CATALOG_INTEGRITY_ERROR: 'CATALOG_INTEGRITY_ERROR',
  HIGH_IMPORTANCE_CAP_EXCEEDED: 'HIGH_IMPORTANCE_CAP_EXCEEDED',
  APPROVAL_QUEUE_CAP_EXCEEDED: 'APPROVAL_QUEUE_CAP_EXCEEDED',
  LICENSE_REVOKED: 'LICENSE_REVOKED',
  LICENSE_EXPIRED: 'LICENSE_EXPIRED',
  LICENSE_NOT_YET_VALID: 'LICENSE_NOT_YET_VALID',
  LICENSE_TENANT_MISMATCH: 'LICENSE_TENANT_MISMATCH',
  TSA_NOT_CONFIGURED: 'TSA_NOT_CONFIGURED',
  ANCHOR_VERIFY_FAILED: 'ANCHOR_VERIFY_FAILED',
  LENGTH_ATTESTATION_FAILED: 'LENGTH_ATTESTATION_FAILED',
  CHAIN_TRUNCATION_DETECTED: 'CHAIN_TRUNCATION_DETECTED',
  CLAIM_VALIDATION_ARG_MISSING: 'CLAIM_VALIDATION_ARG_MISSING',
} as const satisfies Record<ChariotErrorCode, ChariotErrorCode>;

/** Memory-store capability strings carried on MemoryActor.capabilities. */
export type MemoryCapability = 'memory:high';

/**
 * Ordinal rank for importance tiers (higher = more important).
 * 'low' is accepted as legacy input; maps below 'normal'.
 * Shared by InMemoryStore, RedisMongoAdapter, and any future ranker.
 */
export function importanceRank(importance: string): number {
  switch (importance) {
    case 'high':   return 3;
    case 'medium': return 2;
    case 'normal': return 1;
    default:       return 0; // 'low' or unknown
  }
}
