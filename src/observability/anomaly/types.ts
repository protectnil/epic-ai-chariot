/**
 * Real-time anomaly detection — types
 *
 * Consumes a stream of normalized signals (typically derived from audit
 * events or federation tool-call telemetry) and emits a finding when
 * a configured rule fires. Findings flow into the existing AlertQueue
 * (src/observability/alerts.ts) via ChariotEmitter so the AI can
 * surface them on the next admin interaction.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** A normalized event observed by the detector. */
export interface AnomalySignal {
  /** When the underlying action occurred. */
  timestamp: Date;
  /** Tenant scope. Empty string for global / pre-IAM signals. */
  tenantId: string;
  /** Stable identifier of the actor (user id, session id, etc.). */
  actorId: string;
  /** Adapter the action targeted (e.g., 'stripe', 'datadog'). */
  adapterId: string;
  /** Tool name within the adapter (e.g., 'create_charge'). */
  toolName: string;
  /** True for tool calls that mutate / delete / write. */
  destructive: boolean;
  /** Optional structured detail (no inference; pass-through). */
  detail?: Record<string, unknown>;
}

export type AnomalySeverity = 'info' | 'warning' | 'urgent' | 'critical';

export interface AnomalyFinding {
  /** Stable rule id that produced the finding. */
  ruleId: string;
  /** Human-readable label, surfaced in the alert. */
  label: string;
  severity: AnomalySeverity;
  /** Suggested next action for the operator. */
  suggestedAction: string;
  /** When the rule decided to fire. */
  detectedAt: Date;
  /** The signal that tipped the rule (most recent contributor). */
  trigger: AnomalySignal;
  /** Free-form structured context the rule chose to attach. */
  context?: Record<string, unknown>;
}

/**
 * A detection rule. Stateful — rules retain a sliding-window history
 * across observe() calls. Implementations MUST tolerate out-of-order
 * timestamps gracefully (signals can arrive in non-chronological order
 * if multiple shards write to the audit chain concurrently).
 */
export interface AnomalyRule {
  readonly id: string;
  readonly label: string;
  /**
   * Observe a new signal. Returns a finding if this signal causes
   * the rule to fire; null otherwise. Rules MUST be deterministic
   * given the same signal sequence — non-determinism breaks
   * regression tests and replay debugging.
   */
  observe(signal: AnomalySignal): AnomalyFinding | null;
  /** Reset all sliding-window state. Used by tests. */
  reset(): void;
}
