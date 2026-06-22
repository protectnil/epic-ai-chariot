/**
 * Anomaly detector — runs a configured set of rules over a signal
 * stream and dispatches findings to subscribers (typically the
 * existing AlertQueue from src/observability/alerts.ts).
 *
 * No I/O. No timers. The detector is a pure event processor; the
 * signal source (audit-event tail, federation interceptor, replay
 * harness) is the integrator's choice.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type {
  AnomalyRule,
  AnomalySignal,
  AnomalyFinding,
} from './types.js';

export type FindingCallback = (finding: AnomalyFinding) => void;

export class AnomalyDetector {
  private readonly rules: AnomalyRule[];
  private readonly callbacks: FindingCallback[] = [];

  constructor(rules: AnomalyRule[]) {
    this.rules = rules;
  }

  /**
   * Process a single signal. Each rule observes independently; all
   * findings (one per rule, at most) are dispatched in registration
   * order. Returns the findings that fired, useful for tests and for
   * synchronous integrators that want to act on findings directly.
   */
  observe(signal: AnomalySignal): AnomalyFinding[] {
    const findings: AnomalyFinding[] = [];
    for (const rule of this.rules) {
      let f: AnomalyFinding | null = null;
      try {
        f = rule.observe(signal);
      } catch {
        // Faulty rule must not break detection of the rest. Continue.
        continue;
      }
      if (f) {
        findings.push(f);
        for (const cb of this.callbacks) {
          try {
            cb(f);
          } catch {
            // Subscriber failure must not break dispatch to other subscribers.
          }
        }
      }
    }
    return findings;
  }

  onFinding(cb: FindingCallback): this {
    this.callbacks.push(cb);
    return this;
  }

  /** Reset all rule state. Use between test cases. */
  reset(): void {
    for (const r of this.rules) r.reset();
  }

  get ruleCount(): number {
    return this.rules.length;
  }
}
