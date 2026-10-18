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
import { createLogger } from '../../engine/logger.js';

// Production logging goes through the project logger (never console.*).
const moduleLog = createLogger('observability.anomaly');

export type FindingCallback = (finding: AnomalyFinding) => void;

export class AnomalyDetector {
  private readonly rules: AnomalyRule[];
  private readonly callbacks: FindingCallback[] = [];
  /** ruleId → failure count. A persistently-throwing rule is a silently
   * disabled detection class; track it so operators can see it. */
  private readonly ruleFailures = new Map<string, number>();
  /** Subscriber dispatch failure count. */
  private subscriberErrorCount = 0;

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
      } catch (err) {
        // Faulty rule must not break detection of the rest — but a rule
        // that always throws is a detection class silently switched off,
        // so count it and log once when it first starts failing.
        const failures = (this.ruleFailures.get(rule.id) ?? 0) + 1;
        this.ruleFailures.set(rule.id, failures);
        if (failures === 1) {
          moduleLog.error(
            `[AnomalyDetector] rule '${rule.id}' threw and is being skipped ` +
              `(logged once per rule; see failedRules for ongoing counts): ${String(err)}`,
          );
        }
        continue;
      }
      if (f) {
        findings.push(f);
        for (const cb of this.callbacks) {
          try {
            cb(f);
          } catch (err) {
            // Subscriber failure must not break dispatch to other
            // subscribers — but track it so it is not invisible.
            this.subscriberErrorCount++;
            if (this.subscriberErrorCount === 1) {
              moduleLog.error(
                `[AnomalyDetector] finding subscriber threw (logged once; ` +
                  `see subscriberErrors for ongoing count): ${String(err)}`,
              );
            }
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

  /** Rules that have thrown at least once, with failure counts. A rule
   * listed here is (partially or fully) disabled and needs attention. */
  get failedRules(): { ruleId: string; failures: number }[] {
    return [...this.ruleFailures.entries()].map(([ruleId, failures]) => ({ ruleId, failures }));
  }

  /** Total finding-subscriber dispatch failures since construction. */
  get subscriberErrors(): number {
    return this.subscriberErrorCount;
  }

  /** Reset all rule state. Use between test cases. */
  reset(): void {
    for (const r of this.rules) r.reset();
  }

  get ruleCount(): number {
    return this.rules.length;
  }
}
