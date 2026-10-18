/**
 * Anomaly detector wiring — the missing link between the detector module
 * and the rest of Chariot observability.
 *
 * Before this file existed, AnomalyDetector / rules.ts / types.ts were fully
 * implemented but never instantiated anywhere: nothing constructed a
 * detector, registered rules, or called `.onFinding()`, so no finding could
 * ever reach an operator. This module:
 *
 *   1. Builds the default rule set (rate spike, destructive burst,
 *      cross-tenant drift, scope violation) into a single AnomalyDetector.
 *   2. Wires detector findings -> ChariotEmitter.send() -> AlertQueue
 *      (via the existing AlertQueue.asCallback() subscription contract).
 *   3. Exposes `reportToolDispatch()` as the one clean entry point the
 *      dispatch/federation layer calls per tool invocation to feed the
 *      detector. Callers do not construct AnomalySignal directly — this
 *      is the seam that keeps the signal shape decoupled from callers.
 *
 * No timers, no polling: this is push-based. The dispatch layer calls
 * reportToolDispatch() synchronously around/after each tool call; findings
 * (if any) are dispatched to subscribers before the call returns.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { ChariotEmitter } from '../emitter.js';
import { AlertQueue } from '../alerts.js';
import { AnomalyDetector } from './Detector.js';
import {
  ToolCallRateSpikeRule,
  DestructiveToolBurstRule,
  CrossTenantDriftRule,
  ScopeViolationRule,
} from './rules.js';
import type { AnomalyFinding, AnomalySignal } from './types.js';

/**
 * Shape of a single tool-dispatch event, as observed by the layer that
 * actually executes tool calls (federation/dispatch). This is intentionally
 * a plain data object — no class, no hidden defaults — so the dispatch
 * layer can construct it directly from information it already has at the
 * call site (the authorization decision, the tool descriptor, the request
 * context).
 *
 * grantedReadOnly and destructive are both REQUIRED: they are the two
 * fields the scope-violation rule depends on, and neither should ever be
 * silently defaulted by this module. The caller must know, from its own
 * authorization/tool-classification logic, whether the call was destructive
 * and what scope was actually granted to the acting token.
 */
export interface ToolDispatchReport {
  tenantId: string;
  actorId: string;
  toolName: string;
  adapterId: string;
  /** True if this tool call mutates/deletes/writes. */
  destructive: boolean;
  /** True if the acting token/principal's granted scope was read-only. */
  grantedReadOnly: boolean;
  /** Client source IP, when known to the dispatch layer. */
  sourceIp?: string;
  /** When the call occurred. Defaults to now() if omitted. */
  timestamp?: Date;
  /** Optional free-form detail, passed through to the signal untouched. */
  detail?: Record<string, unknown>;
  /**
   * §8.9::11 — the authenticated request-scoped principal identity, when the
   * dispatch carried one. Absent on the unauthenticated OSS/local path.
   * Rules that need role/attribute-sensitive behavior read it from the signal.
   */
  tenantContext?: {
    tenantId: string;
    principalId: string;
    roles: string[];
    tier: 'free' | 'pro' | 'enterprise';
    attributes: Record<string, string>;
  };
}

/**
 * Shared ChariotEmitter instance for anomaly findings. Exported so other
 * observability wiring (metrics, additional subscribers) can attach to the
 * same event stream instead of creating a parallel one.
 */
export const anomalyEmitter = new ChariotEmitter();

/**
 * Shared AlertQueue instance, subscribed to anomalyEmitter below. Exported
 * so a caller (e.g. an admin-facing MCP tool) can call getPending() /
 * formatForAI() / resolve() against the same queue findings land in.
 */
export const anomalyAlertQueue = new AlertQueue();
anomalyEmitter.on(anomalyAlertQueue.asCallback());

/**
 * The default detector: all four built-in rules registered in a fixed,
 * deterministic order (volume/burst rules first, then the single-event
 * scope-violation rule).
 */
export const anomalyDetector = new AnomalyDetector([
  new ToolCallRateSpikeRule(),
  new DestructiveToolBurstRule(),
  new CrossTenantDriftRule(),
  new ScopeViolationRule(),
]);

/** Convert a detector finding into a ChariotEvent and publish it. */
function publishFinding(finding: AnomalyFinding): void {
  anomalyEmitter.send('anomaly.finding', {
    severity: finding.severity,
    // A finding firing IS the alert — the detector already applied its own
    // thresholds/cooldowns (or, for scope-violation, deliberately applies
    // none). Downstream dedupe/noise-control is AlertQueue's job, not a
    // reason to withhold alertWorthy here.
    alertWorthy: true,
    message: `[${finding.ruleId}] ${finding.label}`,
    suggestedAction: finding.suggestedAction,
    data: {
      ruleId: finding.ruleId,
      tenantId: finding.trigger.tenantId,
      actorId: finding.trigger.actorId,
      adapterId: finding.trigger.adapterId,
      toolName: finding.trigger.toolName,
      destructive: finding.trigger.destructive,
      grantedReadOnly: finding.trigger.grantedReadOnly,
      sourceIp: finding.trigger.sourceIp,
      detectedAt: finding.detectedAt.toISOString(),
      context: finding.context,
    },
  });
}

anomalyDetector.onFinding(publishFinding);

/**
 * The dispatch-layer entry point. Call this once per tool dispatch (after
 * the authorization decision is known, whether or not the call was actually
 * allowed to execute) to feed the anomaly detector.
 *
 * Example (dispatch/federation call site):
 *
 *   reportToolDispatch({
 *     tenantId: actionContext.tenantId,
 *     actorId: actionContext.userId ?? 'unknown',
 *     toolName: toolCall.name,
 *     adapterId: serverName,
 *     destructive: tool.destructive,
 *     grantedReadOnly: decision.grantedScope === 'readOnly',
 *     sourceIp: requestContext.sourceIp,
 *   });
 *
 * Returns the findings that fired (usually empty array), mirroring
 * AnomalyDetector.observe(), for callers/tests that want to act on or
 * assert against findings synchronously.
 */
export function reportToolDispatch(report: ToolDispatchReport): AnomalyFinding[] {
  const signal: AnomalySignal = {
    timestamp: report.timestamp ?? new Date(),
    tenantId: report.tenantId,
    actorId: report.actorId,
    adapterId: report.adapterId,
    toolName: report.toolName,
    destructive: report.destructive,
    grantedReadOnly: report.grantedReadOnly,
    sourceIp: report.sourceIp,
    detail: report.detail,
    tenantContext: report.tenantContext,
  };
  return anomalyDetector.observe(signal);
}
