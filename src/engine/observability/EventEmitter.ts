/**
 * @epicai/chariot — Event Emitter
 * Structured event callback system for observability.
 * Consumers pipe events to their own logging/monitoring stack.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { StreamEvent } from '../types/index.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogEntry {
  level: LogLevel;
  message: string;
  data?: Record<string, unknown>;
  timestamp: Date;
  layer?: string;
}

export type EventCallback = (event: StreamEvent) => void;
export type LogCallback = (entry: LogEntry) => void;

export class ObservabilityEmitter {
  private readonly eventCallbacks: EventCallback[] = [];
  private readonly logCallbacks: LogCallback[] = [];
  private logLevel: LogLevel = 'info';

  private static readonly LEVEL_ORDER: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  /**
   * Register a callback for StreamEvents (orchestrator loop events).
   * Returns an unsubscribe function.
   */
  onEvent(callback: EventCallback): this {
    this.eventCallbacks.push(callback);
    return this;
  }

  /**
   * Deregister an event callback by reference.
   */
  offEvent(callback: EventCallback): this {
    const idx = this.eventCallbacks.indexOf(callback);
    if (idx !== -1) this.eventCallbacks.splice(idx, 1);
    return this;
  }

  /**
   * Register a callback for structured log entries.
   * Returns an unsubscribe function.
   */
  onLog(callback: LogCallback): this {
    this.logCallbacks.push(callback);
    return this;
  }

  /**
   * Deregister a log callback by reference.
   */
  offLog(callback: LogCallback): this {
    const idx = this.logCallbacks.indexOf(callback);
    if (idx !== -1) this.logCallbacks.splice(idx, 1);
    return this;
  }

  /**
   * Set minimum log level. Messages below this level are suppressed.
   */
  setLogLevel(level: LogLevel): this {
    this.logLevel = level;
    return this;
  }

  /**
   * Emit a StreamEvent to all registered callbacks.
   */
  emitEvent(event: StreamEvent): void {
    for (const cb of this.eventCallbacks) {
      try { cb(event); } catch { /* never break the pipeline */ }
    }
  }

  /**
 * Emit a retry telemetry event. Called once per retry attempt,
   * before the back-off delay. Operators aggregate these to detect the
   * "third-attempt-always-works" degradation signal.
   */
  emitToolCallRetry(payload: {
    adapterId: string;
    toolName: string;
    attempt: number;
    reason: string;
  }): void {
    this.emitEvent({
      type: 'tool-call-retry',
      data: payload,
      timestamp: new Date(),
    });
  }

  /**
 * emit a single 'tool-error-classified' event when
   * fetchWithRetry exhausts (or sees a single-shot 4xx) and the failure
   * has been categorized. Operators aggregate by `errorClass` to surface
   * rate-limit pressure (Adaline mode 2: 60% of LLM-agent errors are
   * rate-limit class).
   */
  emitToolErrorClassified(payload: {
    adapterId: string;
    toolName: string;
    errorClass: import('../types/index.js').ErrorClass;
  }): void {
    this.emitEvent({
      type: 'tool-error-classified',
      data: payload,
      timestamp: new Date(),
    });
  }

  /**
 * emit a single 'policy-decision' event when a per-tool
   * FailurePolicy short-circuits dispatch (escalate or stop). Operators
   * aggregate by trigger/action to size escalation queues and identify
   * tools whose policies are firing more than expected.
   */
  emitPolicyDecision(payload: {
    adapterId: string;
    toolName: string;
    trigger: 'timeout' | 'rate_limit' | '5xx';
    action: 'escalate' | 'stop';
    policy: import('../types/index.js').FailurePolicy;
  }): void {
    this.emitEvent({
      type: 'policy-decision',
      data: payload,
      timestamp: new Date(),
    });
  }

  /**
 * emit a single 'parameter-validation-rejected' event when the
   * federation-layer per-tool input-schema gate rejects args before dispatch.
   */
  emitParameterValidationRejected(payload: {
    adapterId: string;
    toolName: string;
    issues: Array<{ path: string; message: string; code: string }>;
  }): void {
    this.emitEvent({
      type: 'parameter-validation-rejected',
      data: payload,
      timestamp: new Date(),
    });
  }

  /**
 * emit a single 'approval-required' event when a tool requires
   * approval and the registry has no pre-approval. Operators wire to
   * a webhook, queue, or external approval system.
   */
  emitApprovalRequired(payload: {
    adapterId: string;
    toolName: string;
    tenantId: string;
    argsHash: string;
    approvalKey: string;
  }): void {
    this.emitEvent({
      type: 'approval-required',
      data: payload,
      timestamp: new Date(),
    });
  }

  /**
 * emit a single 'sub-agent-spawn' event with the inherited
   * approval-rule manifestHash so auditors can reconstruct scope.
   */
  emitSubAgentSpawn(payload: {
    parentAgentId: string;
    manifestHash: string;
    ruleCount: number;
    spawnedAt: Date;
  }): void {
    this.emitEvent({
      type: 'sub-agent-spawn',
      data: payload,
      timestamp: new Date(),
    });
  }

  /**
 * emit 'shortlist-token-cost' once per ToolPreFilter.select()
   * with cumulative token cost of returned shortlist.
   */
  emitShortlistTokenCost(payload: {
    totalTokens: number;
    toolCount: number;
    maxTokens?: number;
    maxTools: number;
  }): void {
    this.emitEvent({
      type: 'shortlist-token-cost',
      data: payload,
      timestamp: new Date(),
    });
  }

  /**
 * emit 'context-budget-exceeded' when a chariot response would
   * push the running per-tenant context past CHARIOT_CONTEXT_BUDGET_TOKENS.
   */
  emitContextBudgetExceeded(payload: {
    tenantId: string;
    currentTokens: number;
    budgetTokens: number;
    wouldAddTokens: number;
  }): void {
    this.emitEvent({
      type: 'context-budget-exceeded',
      data: payload,
      timestamp: new Date(),
    });
  }

 /** emit a single 'probe-decision' event per decide() call. */
  emitProbeDecision(payload: {
    decision: 'tool-needed' | 'no-tool' | 'unsupported';
    probability?: number;
    threshold: number;
  }): void {
    this.emitEvent({
      type: 'probe-decision',
      data: payload,
      timestamp: new Date(),
    });
  }

 /** emit a single 'steering-applied' event per ActivationSteerer.apply() that modifies. */
  emitSteeringApplied(payload: {
    modelName: string;
    layer: number;
    category: string;
    weight: number;
  }): void {
    this.emitEvent({
      type: 'steering-applied',
      data: payload,
      timestamp: new Date(),
    });
  }

  /**
   * Emit a structured log entry.
   */
  log(level: LogLevel, message: string, data?: Record<string, unknown>, layer?: string): void {
    if (ObservabilityEmitter.LEVEL_ORDER[level] < ObservabilityEmitter.LEVEL_ORDER[this.logLevel]) {
      return;
    }

    const entry: LogEntry = { level, message, data, timestamp: new Date(), layer };

    for (const cb of this.logCallbacks) {
      try { cb(entry); } catch { /* never break the pipeline */ }
    }
  }

  debug(message: string, data?: Record<string, unknown>, layer?: string): void {
    this.log('debug', message, data, layer);
  }

  info(message: string, data?: Record<string, unknown>, layer?: string): void {
    this.log('info', message, data, layer);
  }

  warn(message: string, data?: Record<string, unknown>, layer?: string): void {
    this.log('warn', message, data, layer);
  }

  error(message: string, data?: Record<string, unknown>, layer?: string): void {
    this.log('error', message, data, layer);
  }

  /**
   * Create a stderr-based log callback for development/debugging.
   *
   * Uses process.stderr (not stdout) to avoid polluting application output.
   * Each log entry is written as a single JSON line for structured parsing.
   *
   * @param redactKeys - Keys whose values will be recursively replaced
   *   with "[REDACTED]" at any depth, including inside arrays and nested objects.
   */
  static consoleLogger(redactKeys?: string[]): LogCallback {
    // a fail-open default — when no list is supplied every key
    // is logged in plaintext including any header field named
    // "Authorization". Default to a hard list of credential-shaped key
    // names. Callers passing an explicit list extend the defaults
    // rather than replace them.
    const DEFAULT_REDACT_KEYS = [
      'authorization', 'Authorization',
      'apiKey', 'apiSecret', 'api_key', 'api_secret',
      'password', 'passwd',
      'secret', 'clientSecret', 'client_secret',
      'token', 'bearer', 'access_token', 'refresh_token',
      'credential', 'credentials',
      'cookie', 'set-cookie', 'setCookie',
      'private_key', 'privateKey',
    ];
    const merged = new Set<string>(DEFAULT_REDACT_KEYS);
    for (const k of redactKeys ?? []) merged.add(k);
    const redactSet: Set<string> | null = merged;

    return (entry: LogEntry) => {
      let data = entry.data;
      if (data) {
        // Always run through deepRedactObj — handles circular refs AND redaction.
        // WeakSet scoped per-call to prevent cross-entry misclassification.
        const seen = new WeakSet();
        data = deepRedactObj(data, redactSet, seen);
      }

      const line = JSON.stringify({
        ts: entry.timestamp.toISOString(),
        level: entry.level,
        layer: entry.layer,
        msg: entry.message,
        data,
      });

      process.stderr.write(line + '\n');
    };
  }
}

/**
 * Recursively redact keys in an object tree.
 * Handles nested objects, arrays, and circular references.
 * WeakSet is passed per-call to avoid cross-entry state leakage.
 */
function deepRedactObj(
  obj: Record<string, unknown>,
  keys: Set<string>,
  seen: WeakSet<object>,
): Record<string, unknown> {
  if (seen.has(obj)) return { _circular: true };
  seen.add(obj);
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (keys.has(k)) {
      result[k] = '[REDACTED]';
    } else if (Array.isArray(v)) {
      result[k] = v.map(item => {
        if (item && typeof item === 'object' && !(item instanceof Date)) {
          return deepRedactObj(item as Record<string, unknown>, keys, seen);
        }
        return item;
      });
    } else if (v && typeof v === 'object' && !(v instanceof Date)) {
      result[k] = deepRedactObj(v as Record<string, unknown>, keys, seen);
    } else {
      result[k] = v;
    }
  }
  return result;
}
