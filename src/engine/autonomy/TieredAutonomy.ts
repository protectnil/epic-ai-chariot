/**
 * @epicai/chariot — Tiered Autonomy
 * Governance layer: evaluate actions against tiers and policies,
 * manage approval workflows.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type {
  AutonomyRules,
  AutonomyPolicy,
  ActionContext,
  ActionDecision,
  PendingApproval,
  ApprovalQueueConfig,
} from '../types/index.js';
import { PolicyEngine, type PolicyConditionErrorCallback } from './PolicyEngine.js';
import { ApprovalQueue } from './ApprovalQueue.js';
import { RedisQueue } from './adapters/RedisQueue.js';

/**
 * Error thrown when MAX_PENDING_APPROVALS cap is exceeded for a tenant.
 */
export class ApprovalQueueCapExceededError extends Error {
  constructor(
    public readonly tenantId: string,
    public readonly currentCount: number,
    public readonly maxApprovals: number,
  ) {
    super(
      `Approval queue at capacity for tenant "${tenantId}": ${currentCount} pending approvals (max: ${maxApprovals})`,
    );
    this.name = 'ApprovalQueueCapExceededError';
  }
}

/**
 * Common interface for approval queue implementations (in-memory and Redis).
 */
export interface ApprovalQueueLike {
  enqueue(context: ActionContext, tier: 'escalate' | 'approve'): PendingApproval | Promise<PendingApproval>;
  approve(actionId: string, approver: string): ActionDecision | Promise<ActionDecision>;
  deny(actionId: string, approver: string, reason: string): ActionDecision | Promise<ActionDecision>;
  pending(): PendingApproval[] | Promise<PendingApproval[]>;
  pendingByTenant(tenantId: string): PendingApproval[] | Promise<PendingApproval[]>;
  destroy?(): void;
  onApprovalNeeded?(callback: (approval: PendingApproval) => void): void;
  onExpired?(callback: (approval: PendingApproval) => void): void;
}

export interface TieredAutonomyOptions {
  /**
   * Forwarded to PolicyEngine. Invoked when a policy `condition` predicate
   * throws during evaluation; the policy is skipped and the chain
   * continues. If omitted, PolicyEngine emits a single console.warn line
   * so the misconfiguration is operator-visible.
   */
  onPolicyConditionError?: PolicyConditionErrorCallback;
  /**
   * Maximum pending approvals per tenant. Default: 1000.
   * When a tenant's pending approval queue reaches this cap,
   * new approval requests are rejected with ApprovalQueueCapExceededError.
   */
  maxPendingApprovalsPerTenant?: number;
  /**
   * Callback invoked when an approval queue capacity rejection occurs.
   * Used for audit logging and observability.
   */
  onQueueCapacityRejected?: (
    tenantId: string,
    currentCount: number,
    maxCount: number,
    action: ActionContext,
  ) => void;
}

const DEFAULT_MAX_PENDING_APPROVALS = 1000;

export class TieredAutonomy {
  private readonly rules: AutonomyRules;
  private readonly policyEngine: PolicyEngine;
  private readonly approvalQueue: ApprovalQueueLike;
  private readonly isRedisQueue: boolean;
  private readonly maxPendingApprovalsPerTenant: number;
  private readonly onQueueCapacityRejected?: (
    tenantId: string,
    currentCount: number,
    maxCount: number,
    action: ActionContext,
  ) => void;

  constructor(
    rules: AutonomyRules,
    queueConfig?: ApprovalQueueConfig,
    options?: TieredAutonomyOptions,
  ) {
    // Coerce missing rule arrays so classifyAction() can iterate without a
    // runtime crash on partially-specified configs. The TypeScript signature
    // still requires all three arrays at the call site; this is belt-and-
    // suspenders for `as any` callers and for fuzz/property tests that build
    // configs by spread.
    this.rules = {
      auto: rules.auto ?? [],
      escalate: rules.escalate ?? [],
      approve: rules.approve ?? [],
    };
    this.policyEngine = new PolicyEngine({
      onConditionError: options?.onPolicyConditionError,
    });
    this.maxPendingApprovalsPerTenant =
      options?.maxPendingApprovalsPerTenant ?? DEFAULT_MAX_PENDING_APPROVALS;
    this.onQueueCapacityRejected = options?.onQueueCapacityRejected;

    if (queueConfig?.persistence === 'redis' && queueConfig.redis) {
      this.approvalQueue = new RedisQueue({
        host: queueConfig.redis.host,
        port: queueConfig.redis.port,
        password: queueConfig.redis.password,
        ttlMs: queueConfig.ttlMs,
      });
      this.isRedisQueue = true;
    } else {
      this.approvalQueue = new ApprovalQueue(queueConfig);
      this.isRedisQueue = false;
    }
  }

  /**
   * Evaluate an action against tiers and dynamic policies.
   * Async because Redis-backed queue enqueue is async.
   * Returns the real approval ID from the queue (not a synthetic one).
   */
  async evaluate(context: ActionContext): Promise<ActionDecision> {
    const policyResult = this.policyEngine.evaluate(context);

    let tier: 'auto' | 'escalate' | 'approve';
    let policyApplied: string | undefined;

    if (policyResult) {
      tier = policyResult.tier;
      policyApplied = policyResult.policyName;
    } else {
      tier = this.classifyAction(context.tool);
    }

    const timestamp = new Date();

    switch (tier) {
      case 'auto':
        return { id: crypto.randomUUID(), action: context.tool, tier, allowed: true, timestamp, policyApplied };

      case 'escalate': {
        // Check capacity before enqueueing
        const pendingForTenant = await this.approvalQueue.pendingByTenant(context.persona);
        if (pendingForTenant.length >= this.maxPendingApprovalsPerTenant) {
          this.onQueueCapacityRejected?.(
            context.persona,
            pendingForTenant.length,
            this.maxPendingApprovalsPerTenant,
            context,
          );
          throw new ApprovalQueueCapExceededError(
            context.persona,
            pendingForTenant.length,
            this.maxPendingApprovalsPerTenant,
          );
        }
        const approval = await this.approvalQueue.enqueue(context, 'escalate');
        return {
          id: approval.id,
          action: context.tool,
          tier,
          allowed: true,
          timestamp,
          policyApplied,
          reason: 'Escalated for human review',
        };
      }

      case 'approve': {
        // Check capacity before enqueueing
        const pendingForTenant = await this.approvalQueue.pendingByTenant(context.persona);
        if (pendingForTenant.length >= this.maxPendingApprovalsPerTenant) {
          this.onQueueCapacityRejected?.(
            context.persona,
            pendingForTenant.length,
            this.maxPendingApprovalsPerTenant,
            context,
          );
          throw new ApprovalQueueCapExceededError(
            context.persona,
            pendingForTenant.length,
            this.maxPendingApprovalsPerTenant,
          );
        }
        const approval = await this.approvalQueue.enqueue(context, 'approve');
        return {
          id: approval.id,
          action: context.tool,
          tier,
          allowed: false,
          timestamp,
          policyApplied,
          reason: 'Awaiting human approval',
        };
      }
    }
  }

  /**
   * Approve a pending action. Idempotent.
   */
  async approve(actionId: string, approver: string): Promise<ActionDecision> {
    return this.approvalQueue.approve(actionId, approver);
  }

  /**
   * Deny a pending action. Idempotent.
   */
  async deny(actionId: string, approver: string, reason: string): Promise<ActionDecision> {
    return this.approvalQueue.deny(actionId, approver, reason);
  }

  /**
   * Get all pending approvals.
   */
  async pending(): Promise<PendingApproval[]> {
    return this.approvalQueue.pending();
  }

  addPolicy(policy: AutonomyPolicy): this {
    this.policyEngine.addPolicy(policy);
    return this;
  }

  removePolicy(name: string): this {
    this.policyEngine.removePolicy(name);
    return this;
  }

  listPolicies(): AutonomyPolicy[] {
    return this.policyEngine.listPolicies();
  }

  onApprovalNeeded(callback: (approval: PendingApproval) => void): void {
    if (this.approvalQueue.onApprovalNeeded) {
      this.approvalQueue.onApprovalNeeded(callback);
    }
  }

  onExpired(callback: (approval: PendingApproval) => void): void {
    if (this.approvalQueue.onExpired) {
      this.approvalQueue.onExpired(callback);
    }
  }

  destroy(): void {
    if (this.approvalQueue.destroy) {
      this.approvalQueue.destroy();
    }
    if (this.isRedisQueue) {
      const redisQueue = this.approvalQueue as RedisQueue;
      redisQueue.disconnect().catch(() => { /* non-fatal */ });
    }
  }

  /**
   * Classify an action into a tier based on static rules.
   * Matches against both the full prefixed name (e.g. "vault:read") and the
   * unprefixed tool name (e.g. "read").
   */
  private classifyAction(toolName: string): 'auto' | 'escalate' | 'approve' {
    const unprefixed = toolName.includes(':') ? toolName.split(':').slice(1).join(':') : toolName;

    for (const action of this.rules.auto) {
      if (toolName === action || unprefixed === action) return 'auto';
    }
    for (const action of this.rules.escalate) {
      if (toolName === action || unprefixed === action) return 'escalate';
    }
    for (const action of this.rules.approve) {
      if (toolName === action || unprefixed === action) return 'approve';
    }

    return 'approve';
  }
}
