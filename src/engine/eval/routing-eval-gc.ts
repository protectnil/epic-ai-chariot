/**
 * Epic AI® Chariot — Routing Eval: G-C-grade route-correct assertion
 *
 * CHARIOT-SPEC §4.5 (verbatim, docs/spec/CHARIOT-SPEC.md ~line 329):
 * "Per `ADAPTER-STANDARD §3.3` (CH-37), route-correct means the exact
 * canonical `tool_id` ultimately selected by the Tier-2 reasoning LLM and
 * submitted for dispatch is the gold tool — not the router's top-1 offer
 * and not merely the correct adapter/server. Router Hit@1 and adapter/server
 * recall remain diagnostics only. The current `routing-eval.ts`
 * deduplicates by server and passes on expected-server-present, so it is
 * insufficient for G-C until extended to exact Tier-2-selected-tool
 * assertions."
 *
 * `routing-eval.ts`'s `runTier1`/`runTier2` both do exactly the flagged
 * thing:
 *   const uniqueServers = [...new Set(selected.map(t => t.server))];
 *   const hit = uniqueServers.includes(q.expectedServer);
 * — server-level, deduplicated, and blind to WHICH tool on that server was
 * offered. A query whose gold tool is `stripe:create_refund` passes that
 * check the instant ANY `stripe:*` tool appears in the shortlist, even
 * `stripe:list_customers`.
 *
 * `assertRouteCorrectGC` fixes exactly this: it checks the FULL ordered,
 * NON-deduplicated tool-id shortlist for the EXACT gold `tool_id`. It is a
 * distinct function/mode, not a patch to the existing server-level check —
 * `assertRouteCorrectServerDedup` below is the OLD check, extracted verbatim
 * so both can be exercised side by side on the same fixture (see
 * routing-eval-gc.test.ts).
 *
 * Scope note (honest, not a fabricated full G-C claim): this module checks
 * exact tool_id presence/rank in the Tier-1 shortlist the orchestrator LLM
 * would be offered. It does NOT simulate an actual Tier-2 LLM dispatch
 * selection — that full end-to-end measurement lives in
 * `eval/GateMetrics.ts` (`evaluateGcGate`), which already requires
 * `submittedToolId === goldToolId` against a real BIEN §2(e) G-C sampling
 * manifest + observation set. This module is the necessary-but-not-alone
 * precondition check for routing-eval.ts's own Tier-1 smoke suite, honestly
 * scoped the same way `eval/proof/types.ts`'s `routeCorrect` already is
 * ("the selection-layer precondition ... not yet determinable" until
 * args/dispatch are wired) — never overclaimed as the full G-C gate.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export interface GCAssertion {
  /** True iff the exact gold tool_id appears anywhere in the shortlist. */
  hit: boolean;
  /** 1-based position of the gold tool_id in the ORDERED shortlist, or null when absent. */
  rank: number | null;
}

/**
 * G-C-grade route-correct assertion (CHARIOT-SPEC §4.5; ADAPTER-STANDARD
 * §3.3 CH-37). `selectedToolIds` MUST be the raw, ORDERED, NON-deduplicated
 * tool-id shortlist exactly as Tier 1 emitted it (e.g. `selected.map(t =>
 * t.name)`) — passing a server-deduped list defeats the purpose of this
 * function and silently degrades it back to the insufficient check this
 * replaces.
 */
export function assertRouteCorrectGC(
  selectedToolIds: readonly string[],
  expectedToolId: string,
): GCAssertion {
  const idx = selectedToolIds.indexOf(expectedToolId);
  return { hit: idx !== -1, rank: idx === -1 ? null : idx + 1 };
}

/**
 * The OLD (§4.5-flagged-insufficient) check, extracted verbatim from
 * `routing-eval.ts`'s `runTier1`/`runTier2` for direct side-by-side testing
 * against `assertRouteCorrectGC` on the same fixture: server-level,
 * deduplicated, passes on expected-server-present regardless of WHICH tool
 * from that server was offered.
 */
export function assertRouteCorrectServerDedup(
  selectedServers: readonly string[],
  expectedServer: string,
): boolean {
  const uniqueServers = [...new Set(selectedServers)];
  return uniqueServers.includes(expectedServer);
}
