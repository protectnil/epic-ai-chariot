/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: first-call success (§CH-37)
 *
 * First-call success is THE release gate: 3.1.2 shipped at G15=0% precisely
 * because the selection number looked fine but nobody measured whether the very
 * first call routed correctly, built valid args, and dispatched. This module
 * decomposes that axis, measuring what is honestly measurable today and wiring
 * (never faking) what is not:
 *
 *   - routeCorrect      : measurable NOW — the full labeled tool set is within
 *                         top-k (selection-layer precondition).
 *   - argsValid         : data-driven from the catalog tool's input schema; the
 *                         routing catalog carries none today → 'unknown' with a
 *                         typed reason (never faked).
 *   - dispatchSucceeded : 'pending' — needs the Phase 4 hybrid retriever + a safe
 *                         dispatcher fixture; structure wired, success never assumed.
 *
 * Pure (no I/O): a `SchemaResolver` is injected so this stays unit-testable.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type {
  PerQueryResult,
  ArgsValidVerdict,
  DispatchVerdict,
  FirstCallPerQuery,
  FirstCallSuccessReport,
} from './types.js';

/** What the catalog knows about a tool's input schema (drives argsValid). */
export interface ToolSchemaInfo {
  hasInputSchema: boolean;
  /** Typed reason when there is no usable schema. */
  reason?: string;
}

/** Resolve a tool id to its schema availability (closure over the catalog). */
export type SchemaResolver = (toolId: string) => ToolSchemaInfo;

const DISPATCH_PENDING_REASON = 'needs-phase4-hybrid-retriever-and-safe-dispatcher-fixture';

/**
 * Can we validate the routed call's args? Returns 'unknown' (with a typed reason)
 * whenever the selected tool has no input schema OR there are no generated args
 * to check (this selection-only harness is LLM-free) — never a fabricated pass.
 */
export function assessArgsValid(
  routedToolId: string | undefined,
  resolve: SchemaResolver,
): { verdict: ArgsValidVerdict; reason?: string } {
  if (!routedToolId) return { verdict: 'unknown', reason: 'no-routed-tool' };
  const info = resolve(routedToolId);
  if (!info.hasInputSchema) {
    return { verdict: 'unknown', reason: info.reason ?? 'catalog-tool-has-no-input-schema' };
  }
  // Schema present, but a selection-only (LLM-free) harness generates no call
  // args, so there is nothing to validate yet. Honest unknown, distinct reason.
  return { verdict: 'unknown', reason: 'no-arg-generation-in-llm-free-selection-harness' };
}

/**
 * Decompose one query's first-call success. `routeCorrect` requires the FULL
 * labeled tool set within top-k (recall@k === 1); for single-label queries this
 * is "the right tool is retrievable". `firstCallSuccess` is null until both
 * argsValid and dispatchSucceeded are determinable — no end-to-end number is
 * assumed.
 */
export function assessFirstCall(r: PerQueryResult, resolve: SchemaResolver): FirstCallPerQuery {
  const routeCorrect = r.recallAtK >= 1;
  const routedToolId = r.returnedToolIds[0];
  const { verdict: argsValid, reason: argsValidReason } = assessArgsValid(routedToolId, resolve);
  const dispatchSucceeded: DispatchVerdict = 'pending';
  const determinable = argsValid !== 'unknown' && dispatchSucceeded !== 'pending';
  const firstCallSuccess = determinable
    ? routeCorrect && argsValid === 'valid' && (dispatchSucceeded as DispatchVerdict) === 'success'
    : null;
  return {
    id: r.id,
    routeCorrect,
    argsValid,
    ...(argsValidReason ? { argsValidReason } : {}),
    dispatchSucceeded,
    dispatchReason: DISPATCH_PENDING_REASON,
    firstCallSuccess,
    ...(r.bugRef ? { bugRef: r.bugRef } : {}),
    ...(r.pendingP4 ? { pendingP4: r.pendingP4 } : {}),
  };
}

function tally<T extends string>(items: readonly T[], keys: readonly T[]): Record<T, number> {
  const out = Object.fromEntries(keys.map((k) => [k, 0])) as Record<T, number>;
  for (const i of items) out[i] += 1;
  return out;
}

/** Aggregate the first-call-success axis over the gold set. */
export function summarizeFirstCall(
  results: readonly PerQueryResult[],
  k: number,
  resolve: SchemaResolver,
): FirstCallSuccessReport {
  const perQuery = results.map((r) => assessFirstCall(r, resolve));
  const routeCorrectCount = perQuery.filter((p) => p.routeCorrect).length;
  const argsValidBreakdown = tally(
    perQuery.map((p) => p.argsValid),
    ['valid', 'invalid', 'unknown'] as const,
  );
  const dispatchBreakdown = tally(
    perQuery.map((p) => p.dispatchSucceeded),
    ['success', 'failure', 'pending'] as const,
  );

  const determinable = perQuery.length > 0 && perQuery.every((p) => p.firstCallSuccess !== null);
  const firstCallSuccessRate = determinable
    ? perQuery.filter((p) => p.firstCallSuccess === true).length / perQuery.length
    : null;

  const reasons = new Set<string>();
  for (const p of perQuery) {
    if (p.argsValid === 'unknown' && p.argsValidReason) reasons.add(p.argsValidReason);
    if (p.dispatchSucceeded === 'pending' && p.dispatchReason) reasons.add(p.dispatchReason);
  }

  return {
    k,
    queryCount: perQuery.length,
    routeCorrectCount,
    routeCorrectRate: perQuery.length === 0 ? 0 : routeCorrectCount / perQuery.length,
    argsValidBreakdown,
    dispatchBreakdown,
    firstCallSuccessDeterminable: determinable,
    firstCallSuccessRate,
    pendingReasons: [...reasons].sort(),
    perQuery,
  };
}
