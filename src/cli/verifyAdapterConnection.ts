/**
 * @epicai/chariot — connection verification for the setup wizard.
 * CHARIOT-SPEC.md:1411 (§17.2 step 6): "Connection verification — light
 * read-only call per adapter; report tools discovered." CHARIOT::§17.2::13.
 *
 * Pure DECISION/REPORTING layer: `verifyAdapterConnection` takes an
 * injectable `ConnectionDispatcher` (the actual network/subprocess call)
 * and an independently-enforced timeout, and returns a typed result. The
 * wizard's default dispatcher reuses the SAME live one-shot dispatch code
 * `cmdQuery` already uses (SDK `Client` + `StreamableHTTPClientTransport`/
 * `StdioClientTransport`, `confineStdioCommand`, `enforceNpxStdioGate`),
 * calling `listTools()` ONLY — never a tool invocation — because
 * `tools/list` is itself the read-only call the clause asks for; no
 * separate "cheapest read-only tool" call is needed on the MCP transports.
 *
 * CH-50 (tool-count honesty, CHARIOT-SPEC.md §17.3): the discovered live
 * count is compared against the catalog's declared `tools[]`/`toolCount`
 * — a mismatch is reported, never silently accepted.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { AdapterEntry } from '../engine/server/ChariotState.js';

export interface DispatchSuccess {
  ok: true;
  toolCount: number;
}
export interface DispatchFailure {
  ok: false;
  reason: string;
}
export type DispatchOutcome = DispatchSuccess | DispatchFailure;

/**
 * The injectable live-call layer. `timeoutMs` is advisory — the
 * dispatcher SHOULD respect it internally (e.g. an AbortController on the
 * transport), but `verifyAdapterConnection` enforces its own independent
 * timeout via `Promise.race` regardless, so a dispatcher that ignores it
 * still can't hang the wizard.
 */
export type ConnectionDispatcher = (
  adapter: AdapterEntry,
  timeoutMs: number,
) => Promise<DispatchOutcome>;

export interface VerifyAdapterConnectionResult {
  adapterId: string;
  ok: boolean;
  toolCount?: number;
  latencyMs: number;
  reason?: string;
  /** CH-50 — true when a successful `toolCount` disagrees with the catalog's declared tool count. */
  countMismatch?: boolean;
  /** The catalog's declared tool count, for the mismatch message. Present whenever the catalog states one. */
  declaredToolCount?: number;
}

function declaredToolCount(adapter: AdapterEntry): number | undefined {
  return adapter.tools?.length ?? adapter.rest?.toolCount ?? adapter.mcp?.toolCount;
}

/**
 * CHARIOT::§17.2::13. Races `dispatch(adapter, timeoutMs)` against an
 * independently-enforced timeout; NEVER throws — every failure mode
 * (dispatcher rejection, dispatcher timeout, dispatcher returning
 * `ok:false`) collapses to `{ ok: false, reason }`.
 */
export async function verifyAdapterConnection(
  adapter: AdapterEntry,
  dispatch: ConnectionDispatcher,
  timeoutMs = 5000,
): Promise<VerifyAdapterConnectionResult> {
  const start = Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<DispatchFailure>((resolve) => {
    timer = setTimeout(() => resolve({ ok: false, reason: 'timeout' }), timeoutMs);
  });

  let outcome: DispatchOutcome;
  try {
    outcome = await Promise.race([dispatch(adapter, timeoutMs), timeoutPromise]);
  } catch (err) {
    outcome = { ok: false, reason: err instanceof Error ? err.message : String(err) };
  } finally {
    if (timer) clearTimeout(timer);
  }

  const latencyMs = Date.now() - start;

  if (!outcome.ok) {
    return { adapterId: adapter.id, ok: false, latencyMs, reason: outcome.reason };
  }

  const declared = declaredToolCount(adapter);
  const countMismatch = declared !== undefined && declared !== outcome.toolCount;
  return {
    adapterId: adapter.id,
    ok: true,
    toolCount: outcome.toolCount,
    latencyMs,
    countMismatch,
    declaredToolCount: declared,
  };
}
