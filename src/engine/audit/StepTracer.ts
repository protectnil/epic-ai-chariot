/**
 * @epicai/chariot — Step Tracer
 * Per-step event emission and audit recording for step-level attribution
 * (which step introduced an error in a multi-step agent trace).
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { randomUUID } from 'node:crypto';
import type { StepKind, ActionRecord } from '../types/index.js';
import type { AuditTrail } from './AuditTrail.js';
import type { ObservabilityEmitter } from '../observability/EventEmitter.js';
import { classifyFailureModeSafe } from './classifyFailureMode.js';

export interface StepTracerParams {
  parentStepId: string | null;
  kind: StepKind;
  input: Record<string, unknown>;
  persona: string;
  server?: string;
  tool?: string;
  tier?: ActionRecord['tier'];
  fn: () => Promise<{ output: Record<string, unknown>; confidence: number | null }>;
}

export interface StepResult {
  stepId: string;
  output: Record<string, unknown>;
  confidence: number | null;
}

export interface StepEventParams {
  stepId: string;
  parentStepId: string | null;
  kind: StepKind;
  input: Record<string, unknown>;
  output?: Record<string, unknown>;
  confidence?: number | null;
  durationMs?: number;
}

/**
 * StepTracer wraps each step boundary in the Orchestrator execute loop.
 *
 * Two usage patterns are supported:
 *
 * 1. traceStep() — full wrap: creates UUID, audits pending, runs fn(), audits
 *    completion, and emits start/end step-trace events in one call.
 *
 * 2. emitStepStart() / emitStepEnd() — lightweight pair: used when the audit
 *    record is already managed by the Orchestrator (tool-call loop). This avoids
 *    double-recording in the audit trail while still emitting attribution events.
 *
 * All step records share the traceId assigned at StepTracer construction — one
 * traceId per Orchestrator.execute() invocation.
 */
export class StepTracer {
  readonly traceId: string;

  constructor(
    private readonly audit: AuditTrail,
    private readonly emitter: ObservabilityEmitter,
    traceId?: string,
  ) {
    this.traceId = traceId ?? randomUUID();
  }

  /**
   * Emit a step-trace 'start' event synchronously.
   * Used in the Orchestrator tool-call loop where the audit record is already
   * managed separately (to avoid double-recording).
   */
  emitStepStart(params: StepEventParams): void {
    this.emitter.emitEvent({
      type: 'step-trace',
      data: {
        stepId: params.stepId,
        parentStepId: params.parentStepId,
        traceId: this.traceId,
        kind: params.kind,
        phase: 'start',
        input: params.input,
        output: {},
        confidence: null,
        durationMs: 0,
      },
      timestamp: new Date(),
    });
  }

  /**
   * Emit a step-trace 'end' event synchronously.
   * Pair with emitStepStart() in the Orchestrator tool-call loop.
   */
  emitStepEnd(params: StepEventParams): void {
    this.emitter.emitEvent({
      type: 'step-trace',
      data: {
        stepId: params.stepId,
        parentStepId: params.parentStepId,
        traceId: this.traceId,
        kind: params.kind,
        phase: 'end',
        input: params.input,
        output: params.output ?? {},
        confidence: params.confidence ?? null,
        durationMs: params.durationMs ?? 0,
      },
      timestamp: new Date(),
    });
  }

  /**
   * Full wrap: audit + emit start/end step-trace events.
   * Use for steps that don't already have an audit record (retrieval, synthesis).
   */
  async traceStep(params: StepTracerParams): Promise<StepResult> {
    const stepId = randomUUID();
    const stepStart = Date.now();

    // Spec contract (§5.3): record the pending ActionRecord FIRST so the
    // hash-chained audit row exists before any observability event fires.
    // If the emitter throws or the process dies between record and start
    // event, the trail still has the step as pending and can be reconciled.
    const pendingRecord = await this.audit.record({
      action: `step:${params.kind}`,
      tool: params.tool ?? params.kind,
      server: params.server ?? 'chariot-internal',
      tier: params.tier ?? 'auto',
      status: 'pending',
      input: params.input,
      output: {},
      persona: params.persona,
      durationMs: 0,
      timestamp: new Date(),
      traceId: this.traceId,
      parentStepId: params.parentStepId ?? undefined,
      stepKind: params.kind,
      confidence: null,
    });

    // Emit start event AFTER the record is persisted.
    this.emitStepStart({
      stepId,
      parentStepId: params.parentStepId,
      kind: params.kind,
      input: params.input,
    });

    let output: Record<string, unknown> = {};
    let confidence: number | null = null;

    try {
      const result = await params.fn();
      output = result.output;
      confidence = result.confidence;

      const durationMs = Date.now() - stepStart;
      await this.audit.updateStatus(pendingRecord.id, 'completed', output, durationMs);

      this.emitStepEnd({
        stepId,
        parentStepId: params.parentStepId,
        kind: params.kind,
        input: params.input,
        output,
        confidence,
        durationMs,
      });

      return { stepId, output, confidence };
    } catch (err) {
      const durationMs = Date.now() - stepStart;
      const errMsg = err instanceof Error ? err.message : String(err);
      // Classify the thrown step failure so persisted records carry
      // failureMode through the three-layer chain (spec §7). Unknown
      // codes resolve to 'UNKNOWN' via classifyFailureModeSafe.
      const failureMode = classifyFailureModeSafe(undefined, errMsg);
      await this.audit.updateStatus(
        pendingRecord.id,
        'failed',
        { error: errMsg },
        durationMs,
        { failureMode },
      );

      this.emitStepEnd({
        stepId,
        parentStepId: params.parentStepId,
        kind: params.kind,
        input: params.input,
        output: { error: err instanceof Error ? err.message : String(err) },
        confidence: null,
        durationMs,
      });

      throw err;
    }
  }
}
