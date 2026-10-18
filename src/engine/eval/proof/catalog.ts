/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: production-faithful catalog
 *
 * The proof artifact must measure the SAME tool documents the live router
 * indexes — otherwise the numbers describe a fiction. Rather than re-deriving
 * the tool-build logic (registry-vs-catalog preference, rest/mcp toolName
 * resolution, low-quality-description drops, dispatchability filtering, curated
 * overlay), this module imports and calls the exported production functions
 * directly: `loadAllAdapters()` + `buildToolsForRouting()` from ChariotState.
 * Whatever the live full-catalog index contains, this returns byte-identically.
 *
 * Read-only: this module imports from `../../server` and `../../federation`;
 * it does not modify either.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { Tool } from '../../types/index.js';
import { loadAllAdapters, buildToolsForRouting } from '../../server/ChariotState.js';

export interface ProductionCatalog {
  /** Tool documents exactly as the live full-catalog ToolPreFilter indexes them. */
  tools: Tool[];
  /**
   * Set of every tool id for O(1) gold-label validation. The id is the tool's
   * `name`, which `buildToolsForRouting` already emits as `${adapterId}:${method}`
   * (e.g. `pubmed:search_pubmed`) — the fully-qualified identifier the orchestrator
   * LLM selects and the dispatcher routes on. We do NOT re-prefix with `server`
   * (which equals the adapterId) because that would double the prefix
   * (`pubmed:pubmed:search_pubmed`).
   */
  toolIds: Set<string>;
  /** id → tool, for O(1) schema/parameter lookup (first-call argsValid check). */
  toolById: Map<string, Tool>;
  /** Distinct server (adapter) count. */
  serverCount: number;
  /** Number of adapters kept after dispatchability/quality filtering. */
  adapterCount: number;
  /**
   * Tool ids (§CH-37 `${server}:${method}` granularity) whose owning adapter
   * carries `requiresCustomerAuth: true` (AS §1.2a). CHARIOT-SPEC §4.5
   * requires Recall@8 for this class to be reported SEPARATELY from the
   * pooled headline — see `auth-segment.ts`.
   */
  requiresCustomerAuthToolIds: Set<string>;
  /**
   * Count of adapters in THIS catalog under test flagged
   * `requiresCustomerAuth: true`. Zero is a real, reportable state (a
   * catalog-population gap, per §4.5) — never silently treated the same as
   * "the gold set just doesn't cover this class".
   */
  requiresCustomerAuthAdapterCount: number;
}

/**
 * Load the production full-catalog tool set. Honors `CHARIOT_ADAPTER_CATALOG_PATH`
 * through `loadAllAdapters()` (so an air-gapped/alternate bundle can be pointed
 * at without code change). The result is the `fullCatalogFilter` view from
 * `loadChariotState()` — every published adapter, not just the locally
 * configured ones — which is the correct universe for a routing benchmark.
 */
export async function loadProductionCatalog(): Promise<ProductionCatalog> {
  const adapters = await loadAllAdapters();
  const tools = buildToolsForRouting(adapters);
  const toolIds = new Set<string>();
  const toolById = new Map<string, Tool>();
  const servers = new Set<string>();
  for (const t of tools) {
    const id = toolIdOf(t);
    toolIds.add(id);
    toolById.set(id, t);
    servers.add(t.server);
  }
  // AS §1.2a / §4.5: join tool ids back to their owning adapter's
  // requiresCustomerAuth flag via `server` (== adapter.id — see toolIdOf).
  // Tool objects from buildToolsForRouting do not carry this flag directly,
  // so it is looked up from the adapter list, not re-derived from the id.
  const requiresCustomerAuthServers = new Set(
    adapters.filter((a) => a.requiresCustomerAuth === true).map((a) => a.id),
  );
  const requiresCustomerAuthToolIds = new Set<string>();
  for (const t of tools) {
    if (requiresCustomerAuthServers.has(t.server)) requiresCustomerAuthToolIds.add(toolIdOf(t));
  }
  return {
    tools,
    toolIds,
    toolById,
    serverCount: servers.size,
    adapterCount: adapters.length,
    requiresCustomerAuthToolIds,
    requiresCustomerAuthAdapterCount: requiresCustomerAuthServers.size,
  };
}

/**
 * Single source of truth for a tool's id. `buildToolsForRouting` already emits
 * `name` as `${adapterId}:${method}` (server === adapterId), so `name` IS the
 * fully-qualified `${server}:${method}` identifier — the exact string the
 * orchestrator LLM is offered and the dispatcher routes on. Return it verbatim;
 * re-prefixing with `server` would double the adapter id.
 */
export function toolIdOf(t: Tool): string {
  return t.name;
}
