/**
 * @epicai/chariot — Policy Engine
 * Evaluates dynamic policies against action context with priority ordering.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { AutonomyPolicy, ActionContext } from '../types/index.js';

/**
 * Callback fired when a policy's `condition` predicate throws during
 * evaluation. The faulty policy is skipped (fail-open at the policy
 * layer — TieredAutonomy.classifyAction still applies, default-deny
 * `'approve'` is returned for unmatched tools), but the operator must
 * be able to detect the misconfiguration. Wire from EpicAIConfig.autonomy.
 */
export type PolicyConditionErrorCallback = (info: {
  policyName: string;
  error: Error;
}) => void;

export interface PolicyEngineOptions {
  /**
   * Receives information when a policy's `condition` predicate throws.
   *
   * If omitted, a single warning line is written to `console.warn` so
   * the failure surfaces in stdout/journald — silent swallow is never
   * the default. Set this to a no-op function to suppress, or wire to
   * the engine observability emitter to route into the operator's
   * existing log pipeline.
   */
  onConditionError?: PolicyConditionErrorCallback;
}

export class PolicyEngine {
  private policies: AutonomyPolicy[] = [];
  private readonly onConditionError: PolicyConditionErrorCallback;

  constructor(options?: PolicyEngineOptions) {
    this.onConditionError =
      options?.onConditionError ??
      ((info) => {
         
        console.warn(
          `[chariot/policy-engine] policy "${info.policyName}" condition threw and was skipped: ${info.error.message}`,
        );
      });
  }

  addPolicy(policy: AutonomyPolicy): void {
    this.policies.push(policy);
    this.sortByPriority();
  }

  removePolicy(name: string): void {
    this.policies = this.policies.filter(p => p.name !== name);
  }

  listPolicies(): AutonomyPolicy[] {
    return [...this.policies];
  }

  /**
   * Evaluate all policies against the action context.
   * Returns the override tier from the first matching policy (highest priority),
   * or null if no policy matches.
   *
   * If a policy's `condition` predicate throws, the policy is skipped
   * (fail-open at this layer) and `onConditionError` is invoked. The
   * evaluation chain continues so a single buggy customer policy cannot
   * disable evaluation of every later policy.
   */
  evaluate(context: ActionContext): { tier: 'auto' | 'escalate' | 'approve'; policyName: string } | null {
    for (const policy of this.policies) {
      try {
        if (policy.condition(context)) {
          return { tier: policy.override, policyName: policy.name };
        }
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        try {
          this.onConditionError({ policyName: policy.name, error });
        } catch {
          // Don't let a faulty error callback break the evaluation chain.
        }
      }
    }
    return null;
  }

  private sortByPriority(): void {
    this.policies.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  }
}
