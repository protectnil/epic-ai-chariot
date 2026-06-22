/**
 * Built-in anomaly detection rules.
 *
 * Each rule is stateful (sliding-window) and deterministic given an
 * input signal sequence. Defaults are conservative — prefer false
 * negatives over false positives. Operators tune via constructor opts.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type {
  AnomalyRule,
  AnomalySignal,
  AnomalyFinding,
  AnomalySeverity,
} from './types.js';

/**
 * Sliding-window bookkeeping helper. Stores timestamps within a
 * window; prunes anything older than `windowMs` from `now`.
 */
class SlidingWindow {
  private readonly entries: number[] = [];
  constructor(private readonly windowMs: number) {}

  add(epochMs: number): void {
    this.entries.push(epochMs);
    this.prune(epochMs);
  }

  countAt(nowMs: number): number {
    this.prune(nowMs);
    return this.entries.length;
  }

  reset(): void {
    this.entries.length = 0;
  }

  private prune(nowMs: number): void {
    const cutoff = nowMs - this.windowMs;
    while (this.entries.length > 0 && this.entries[0] < cutoff) {
      this.entries.shift();
    }
  }
}

// ────────────────────────────────────────────────────────────────────────
// Rule 1: Tool-call rate spike per actor
// ────────────────────────────────────────────────────────────────────────

export interface RateSpikeOptions {
  /** Window over which to count calls. Default 60s. */
  windowMs?: number;
  /** Threshold count within the window that triggers a finding. Default 100. */
  threshold?: number;
  /** Severity to emit when the threshold is crossed. Default 'warning'. */
  severity?: AnomalySeverity;
  /** Cooldown after firing before this actor can fire again. Default 5min. */
  cooldownMs?: number;
}

export class ToolCallRateSpikeRule implements AnomalyRule {
  readonly id = 'tool-call-rate-spike';
  readonly label = 'Tool call rate spike';

  private readonly windowMs: number;
  private readonly threshold: number;
  private readonly severity: AnomalySeverity;
  private readonly cooldownMs: number;
  private readonly windows = new Map<string, SlidingWindow>();
  private readonly lastFiredMs = new Map<string, number>();

  constructor(opts: RateSpikeOptions = {}) {
    this.windowMs = opts.windowMs ?? 60_000;
    this.threshold = opts.threshold ?? 100;
    this.severity = opts.severity ?? 'warning';
    this.cooldownMs = opts.cooldownMs ?? 5 * 60_000;
  }

  observe(signal: AnomalySignal): AnomalyFinding | null {
    const key = `${signal.tenantId}::${signal.actorId}`;
    let win = this.windows.get(key);
    if (!win) {
      win = new SlidingWindow(this.windowMs);
      this.windows.set(key, win);
    }
    const nowMs = signal.timestamp.getTime();
    win.add(nowMs);
    const count = win.countAt(nowMs);
    if (count < this.threshold) return null;

    const lastFired = this.lastFiredMs.get(key) ?? -Infinity;
    if (nowMs - lastFired < this.cooldownMs) return null;
    this.lastFiredMs.set(key, nowMs);

    return {
      ruleId: this.id,
      label: this.label,
      severity: this.severity,
      detectedAt: new Date(nowMs),
      trigger: signal,
      suggestedAction:
        `Investigate actor ${signal.actorId} in tenant ${signal.tenantId}: ` +
        `${count} tool calls in the last ${Math.round(this.windowMs / 1000)}s ` +
        `(threshold ${this.threshold}). Review recent audit rows for this actor.`,
      context: { count, windowMs: this.windowMs, threshold: this.threshold },
    };
  }

  reset(): void {
    this.windows.clear();
    this.lastFiredMs.clear();
  }
}

// ────────────────────────────────────────────────────────────────────────
// Rule 2: Destructive-tool burst per actor
// ────────────────────────────────────────────────────────────────────────

export interface DestructiveBurstOptions {
  windowMs?: number; // default 5 min
  threshold?: number; // default 5 destructive calls
  severity?: AnomalySeverity; // default 'urgent'
  cooldownMs?: number; // default 15 min
}

export class DestructiveToolBurstRule implements AnomalyRule {
  readonly id = 'destructive-tool-burst';
  readonly label = 'Destructive tool burst';

  private readonly windowMs: number;
  private readonly threshold: number;
  private readonly severity: AnomalySeverity;
  private readonly cooldownMs: number;
  private readonly windows = new Map<string, SlidingWindow>();
  private readonly lastFiredMs = new Map<string, number>();

  constructor(opts: DestructiveBurstOptions = {}) {
    this.windowMs = opts.windowMs ?? 5 * 60_000;
    this.threshold = opts.threshold ?? 5;
    this.severity = opts.severity ?? 'urgent';
    this.cooldownMs = opts.cooldownMs ?? 15 * 60_000;
  }

  observe(signal: AnomalySignal): AnomalyFinding | null {
    if (!signal.destructive) return null;

    const key = `${signal.tenantId}::${signal.actorId}`;
    let win = this.windows.get(key);
    if (!win) {
      win = new SlidingWindow(this.windowMs);
      this.windows.set(key, win);
    }
    const nowMs = signal.timestamp.getTime();
    win.add(nowMs);
    const count = win.countAt(nowMs);
    if (count < this.threshold) return null;

    const lastFired = this.lastFiredMs.get(key) ?? -Infinity;
    if (nowMs - lastFired < this.cooldownMs) return null;
    this.lastFiredMs.set(key, nowMs);

    return {
      ruleId: this.id,
      label: this.label,
      severity: this.severity,
      detectedAt: new Date(nowMs),
      trigger: signal,
      suggestedAction:
        `Actor ${signal.actorId} in tenant ${signal.tenantId} ran ${count} destructive ` +
        `tool calls in ${Math.round(this.windowMs / 60_000)} min (threshold ${this.threshold}). ` +
        'Verify intent or freeze the actor while investigating.',
      context: { count, windowMs: this.windowMs, threshold: this.threshold },
    };
  }

  reset(): void {
    this.windows.clear();
    this.lastFiredMs.clear();
  }
}

// ────────────────────────────────────────────────────────────────────────
// Rule 3: Cross-tenant drift — same actorId observed under multiple
// tenants in a short window. Catches operator misconfiguration where
// a session token is reused across tenant contexts, or an authn bug
// that lets an actor straddle tenant boundaries.
// ────────────────────────────────────────────────────────────────────────

export interface CrossTenantDriftOptions {
  windowMs?: number; // default 10 min
  severity?: AnomalySeverity; // default 'critical'
  cooldownMs?: number; // default 30 min
}

export class CrossTenantDriftRule implements AnomalyRule {
  readonly id = 'cross-tenant-drift';
  readonly label = 'Same actor observed across multiple tenants';

  private readonly windowMs: number;
  private readonly severity: AnomalySeverity;
  private readonly cooldownMs: number;
  // actorId → Map<tenantId, last-seen-ms>
  private readonly seen = new Map<string, Map<string, number>>();
  private readonly lastFiredMs = new Map<string, number>();

  constructor(opts: CrossTenantDriftOptions = {}) {
    this.windowMs = opts.windowMs ?? 10 * 60_000;
    this.severity = opts.severity ?? 'critical';
    this.cooldownMs = opts.cooldownMs ?? 30 * 60_000;
  }

  observe(signal: AnomalySignal): AnomalyFinding | null {
    const nowMs = signal.timestamp.getTime();
    let perActor = this.seen.get(signal.actorId);
    if (!perActor) {
      perActor = new Map();
      this.seen.set(signal.actorId, perActor);
    }
    perActor.set(signal.tenantId, nowMs);

    // Prune stale entries
    const cutoff = nowMs - this.windowMs;
    for (const [tid, ts] of perActor) {
      if (ts < cutoff) perActor.delete(tid);
    }

    if (perActor.size < 2) return null;

    const lastFired = this.lastFiredMs.get(signal.actorId) ?? -Infinity;
    if (nowMs - lastFired < this.cooldownMs) return null;
    this.lastFiredMs.set(signal.actorId, nowMs);

    const tenants = [...perActor.keys()].sort();

    return {
      ruleId: this.id,
      label: this.label,
      severity: this.severity,
      detectedAt: new Date(nowMs),
      trigger: signal,
      suggestedAction:
        `Actor ${signal.actorId} observed under tenants [${tenants.join(', ')}] ` +
        `within the last ${Math.round(this.windowMs / 60_000)} min. This usually indicates ` +
        'either a session-token reuse bug or an authn boundary failure. ' +
        'Revoke the actor session and audit the IAM mapping immediately.',
      context: { tenants, windowMs: this.windowMs },
    };
  }

  reset(): void {
    this.seen.clear();
    this.lastFiredMs.clear();
  }
}
