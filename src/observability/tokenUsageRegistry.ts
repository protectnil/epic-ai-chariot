/**
 * @epicai/chariot — process-wide token-usage-by-adapter registry.
 *
 * CHARIOT::§16.3::1 (rulings item 91(3), gate finding 114(i)) — "any
 * process that embeds the SDK feeds the gateway metrics without a second
 * wiring site." Before this file: the ONLY way to connect an EpicAI
 * instance's TokenTracker to a ChariotMetrics instance was
 * `chariotMetrics.setTokenUsageSource(epicAI)` — a per-ChariotMetrics-
 * instance call some external caller would have to make explicitly. No
 * code path in this repo made that call (EpicAI.ts's own build report:
 * `new EpicAI(` — 0 hits outside tests; ChariotMetrics is owned by the
 * separate `chariot serve` CLI/gateway path, which never imports
 * EpicAI/Orchestrator/TokenTracker). This registry is a SECOND, automatic
 * seam: EpicAI's constructor registers itself here; ChariotMetrics.getSummary()
 * consults this registry when no per-instance setTokenUsageSource() source
 * was explicitly set — so any process that constructs an EpicAI agent
 * ALSO feeds whatever ChariotMetrics instance that same process later
 * constructs, with zero coordination between the two call sites.
 *
 * Process-wide, single most-recent-registration-wins (documented, not a
 * merge/stack): a second EpicAI instance constructed in the same process
 * REPLACES the first as the registered source. This is a deliberate,
 * simple contract — a real multi-agent-per-process deployment that needs
 * per-instance attribution should use the explicit
 * `chariotMetrics.setTokenUsageSource(...)` override instead of relying on
 * this ambient registry.
 */

import type { TokenUsageByAdapterSource } from './metrics.js';

let registeredSource: TokenUsageByAdapterSource | null = null;

/**
 * Register the process-wide token-usage-by-adapter source. The most
 * recently registered source wins; registering again (e.g. a second
 * EpicAI instance in the same process) replaces the prior registration.
 */
export function registerTokenUsageSource(source: TokenUsageByAdapterSource): void {
  registeredSource = source;
}

/** Read the currently registered source, or null if none has registered. */
export function getRegisteredTokenUsageSource(): TokenUsageByAdapterSource | null {
  return registeredSource;
}

/** Test seam — clears the registration so tests don't leak state across files/runs. */
export function clearRegisteredTokenUsageSource(): void {
  registeredSource = null;
}
