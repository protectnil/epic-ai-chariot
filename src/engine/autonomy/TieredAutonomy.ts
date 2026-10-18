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
  ObservabilityInfoSink,
} from '../types/index.js';
import { PolicyEngine, type PolicyConditionErrorCallback } from './PolicyEngine.js';
import { ApprovalQueue } from './ApprovalQueue.js';
import { RedisQueue } from './adapters/RedisQueue.js';
// CHARIOT::§16.1 Autonomy (rulings item 91/105) — the customer-facing
// event bus, distinct from the §8.12 `emitter` (ObservabilityInfoSink)
// this module already carries above (engine telemetry, not the
// operator-meaningful §16.1 taxonomy). Direct import, matching this
// repo's established pattern (VerifiedCatalog.ts, mfa.ts, loader.ts,
// FederationManager.ts).
import { chariotEmitter } from '../../observability/emitter.js';

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
  // CHARIOT::§7.6::4 — optional so pre-existing ApprovalQueueLike
  // implementations that predate this clause remain valid without change.
  cancelByServer?(server: string, reason: string): PendingApproval[] | Promise<PendingApproval[]>;
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
  /**
   * CHARIOT::§8.12::1 — optional ObservabilityEmitter (or any
   * ObservabilityInfoSink-structural equivalent) so the autonomy layer
   * emits through it, per "the orchestrator, federation, autonomy, and
   * resilience layers all emit through it." Omitted: evaluate() emits
   * nothing (default-disabled, matching Orchestrator's own stepEmitter
   * convention).
   */
  emitter?: ObservabilityInfoSink;
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
  private readonly emitter?: ObservabilityInfoSink;

  constructor(
    rules: AutonomyRules,
    queueConfig?: ApprovalQueueConfig,
    options?: TieredAutonomyOptions,
  ) {
    this.emitter = options?.emitter;
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

    // CHARIOT::§16.1 Autonomy (CHARIOT-SPEC.md:1348, rulings item 91/105)
    // — `autonomy.timed_out`. Self-registered (not left for an external
    // caller to wire) so it fires unconditionally whenever the underlying
    // queue supports expiry notification at all; `onExpired` supports
    // multiple registered callbacks (ApprovalQueue.ts's own
    // `expiredCallbacks` array), so this does not preclude a caller from
    // ALSO registering its own via the public onExpired() method below.
    // RedisQueue does not implement onExpired (TTL-based expiry with no
    // application-level notification, per TieredAutonomy.onExpired()'s
    // own guard) — this.approvalQueue.onExpired?.() below is a no-op in
    // that case, same as every other caller of this optional hook.
    this.approvalQueue.onExpired?.((approval) => {
      chariotEmitter.send('autonomy.timed_out', {
        severity: 'warning',
        data: { actionId: approval.id, tool: approval.action?.tool, tier: approval.tier },
      });
    });
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

    // §19::13: an explicitly identified write must never be auto-approved.
    // Missing MCP annotations are intentionally left unchanged for backwards
    // compatibility with existing static auto-rules and policy tests.
    const isExplicitWrite =
      context.readOnlyHint === false || context.destructiveHint === true;

    if (tier === 'auto' && isExplicitWrite) {
      tier = 'escalate';
    }

    const timestamp = new Date();

    switch (tier) {
      case 'auto': {
        const decision: ActionDecision = { id: crypto.randomUUID(), action: context.tool, tier, allowed: true, timestamp, policyApplied };
        this.emitDecision(context, decision);
        return decision;
      }

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
        const decision: ActionDecision = {
          id: approval.id,
          action: context.tool,
          tier,
          allowed: true,
          timestamp,
          policyApplied,
          reason: 'Escalated for human review',
        };
        this.emitDecision(context, decision);
        // CHARIOT::§16.1 Autonomy (CHARIOT-SPEC.md:1348, rulings item
        // 91/105) — both the 'escalate' and 'approve' tiers enqueue into
        // the approval queue for human review; `data.tier` distinguishes
        // them (feeds ChariotMetrics.getSummary().autonomy.byTier).
        chariotEmitter.send('autonomy.escalated', {
          data: { actionId: approval.id, tool: context.tool, tenantId: context.persona, tier },
        });
        return decision;
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
        const decision: ActionDecision = {
          id: approval.id,
          action: context.tool,
          tier,
          allowed: false,
          timestamp,
          policyApplied,
          reason: 'Awaiting human approval',
        };
        this.emitDecision(context, decision);
        // CHARIOT::§16.1 Autonomy (CHARIOT-SPEC.md:1348, rulings item
        // 91/105) — see the identical comment in the 'escalate' case above.
        chariotEmitter.send('autonomy.escalated', {
          data: { actionId: approval.id, tool: context.tool, tenantId: context.persona, tier },
        });
        return decision;
      }
    }
  }

  /**
   * CHARIOT::§8.12::1 emit site — the autonomy layer's evaluate() result,
   * for every one of the three tier outcomes (auto/escalate/approve).
   * No-ops when no emitter is wired.
   */
  private emitDecision(context: ActionContext, decision: ActionDecision): void {
    this.emitter?.info(
      'autonomy_decision',
      {
        tool: context.tool,
        server: context.server,
        tier: decision.tier,
        allowed: decision.allowed,
        policyApplied: decision.policyApplied,
      },
      'autonomy',
    );
  }

  /**
   * Approve a pending action. Idempotent.
   */
  async approve(actionId: string, approver: string): Promise<ActionDecision> {
    // CHARIOT::§16.1 Autonomy (CHARIOT-SPEC.md:1348, rulings item 91/105)
    // — approve()/deny() are documented idempotent (a replay on an
    // already-decided item returns the existing decision unchanged, per
    // ApprovalQueue.approve()'s own "Idempotent: already decided" branch).
    // Checking pending-membership BEFORE the call distinguishes a genuine
    // fresh transition from an idempotent replay, so a duplicate
    // approve() call (e.g. a UI double-submit or retried request) does
    // not double-emit or double-count in ChariotMetrics.
    const wasPending = (await this.approvalQueue.pending()).some((a) => a.id === actionId);
    const decision = await this.approvalQueue.approve(actionId, approver);
    if (wasPending) {
      chariotEmitter.send('autonomy.approved', {
        data: { actionId, approver, tool: decision.action, tier: decision.tier },
      });
    }
    return decision;
  }

  /**
   * Deny a pending action. Idempotent.
   */
  async deny(actionId: string, approver: string, reason: string): Promise<ActionDecision> {
    // See approve()'s comment above — same idempotent-replay guard.
    const wasPending = (await this.approvalQueue.pending()).some((a) => a.id === actionId);
    const decision = await this.approvalQueue.deny(actionId, approver, reason);
    if (wasPending) {
      chariotEmitter.send('autonomy.rejected', {
        data: { actionId, approver, tool: decision.action, tier: decision.tier, reason },
      });
    }
    return decision;
  }

  /**
   * Get all pending approvals.
   */
  async pending(): Promise<PendingApproval[]> {
    return this.approvalQueue.pending();
  }

  /**
   * CHARIOT::§7.6::4 — cancel every pending approval pointing at `server`.
   * Passthrough to the underlying queue implementation; no-ops (returns
   * an empty array) if the configured queue predates cancelByServer.
   */
  async cancelByServer(server: string, reason: string): Promise<PendingApproval[]> {
    if (!this.approvalQueue.cancelByServer) return [];
    return this.approvalQueue.cancelByServer(server, reason);
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
    // FIX (2026-09-30, release-blocking): the prior
    // `toolName.split(':').slice(1).join(':')` assumed the adapter id
    // itself contains no colon — false for a discovered adapter's
    // `discovered:<serviceId>` operational-namespace prefix
    // (src/engine/federation/configuredAdapterIds.ts). For
    // "discovered:server-abc123:get_widgets" the naive split left
    // "server-abc123:get_widgets" instead of "get_widgets", so an
    // autonomy rule written against the bare tool name (the documented,
    // common case per this method's own doc comment) would silently fail
    // to match for every discovered-adapter action. Mirrors the identical
    // colon-aware fix applied at FederationManager.ts's 4 sibling sites
    // and OfficialPartition.ts's adapterIdFromRetrievalId.
    const DISCOVERED_ADAPTER_ID_PREFIX = 'discovered:';
    let unprefixed: string;
    if (toolName.startsWith(DISCOVERED_ADAPTER_ID_PREFIX)) {
      const rest = toolName.slice(DISCOVERED_ADAPTER_ID_PREFIX.length);
      const idx = rest.indexOf(':');
      unprefixed = idx === -1 ? toolName : rest.slice(idx + 1);
    } else {
      unprefixed = toolName.includes(':') ? toolName.split(':').slice(1).join(':') : toolName;
    }

    for (const action of this.rules.auto) {
      if (toolName === action || unprefixed === action) return 'auto';
    }
    for (const action of this.rules.escalate) {
      if (toolName === action || unprefixed === action) return 'escalate';
    }
    for (const action of this.rules.approve) {
      if (toolName === action || unprefixed === action) return 'approve';
    }

    // CHARIOT::§3.5::15 — CH-11 (CHARIOT-SPEC.md:254, restated
    // CHARIOT-SPEC.md:553): "TieredAutonomy's unmatched-tier
    // default is `approve` (which yields `allowed: false` and routes through
    // the queue), not raw `deny`." An unmatched tool must not dispatch
    // without human action; 'escalate' here yields allowed:true (dispatches
    // immediately), so it fails CH-11 — only 'approve' blocks execution.
    return 'approve';
  }
}
