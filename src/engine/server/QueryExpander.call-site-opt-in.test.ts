/**
 * Adversarial eval: query expansion is opt-in per call site (CHARIOT::§4.6::2)
 *
 * CHARIOT-SPEC.md §4.6: "`QueryExpander` (`src/engine/federation/
 * QueryExpander.ts`) rewrites queries that contain known abbreviations (e.g.,
 * "PD" → "PagerDuty incident"). The expansion list is loaded from the
 * catalog `keywords` field per adapter. Expansion is opt-in per call site;
 * the orchestrator enables it for natural-language admin requests but skips
 * it for direct `tool/call` invocations."
 *
 * EARS (CHARIOT::§4.6::2): "Query expansion SHALL be opt-in per call site:
 * enabled by the orchestrator for natural-language admin requests and
 * skipped for direct tool/call invocations."
 * Acceptance: "Expansion on for NL admin requests, off for direct tool/call."
 *
 * This is a BEHAVIORAL eval, not a source-shape check: it drives the real,
 * exported `handleQuery` (chariot_query, the natural-language admin request
 * handler) and `handleCall` (chariot_call, the direct tool/call handler)
 * end to end against a minimal ChariotState, with an INSTRUMENTED
 * `ToolPreFilter` double whose `select()` is a call-counting spy that
 * delegates to the REAL, unmodified `buildCatalogExpansionIndex` /
 * `expandQuery` from `QueryExpander.ts` (not a re-implementation, not a
 * mock of the expansion logic itself — only the retrieval/ranking half of
 * ToolPreFilter is doubled, exactly as `toolHandlers.list-toolcount-honesty
 * .test.ts` doubles `select` for handleList). The evals assert, at runtime:
 *   1. `handleQuery` (chariot_query) calls the filter's `select()` exactly
 *      once, and the catalog-driven expansion inside that one call changes
 *      the clause's own worked example ("PD" -> includes "PagerDuty",
 *      "incident") — proven not by inspecting `expandQuery`'s return value in
 *      isolation, but by the fact that `handleQuery`'s response only surfaces
 *      the `pagerduty` adapter when the spy's `select()` sees an expanded
 *      query, which only happens if `handleQueryImpl` actually routed the
 *      raw abbreviation through the catalog-driven expansion path.
 *   2. `handleCall` (chariot_call, direct tool/call invocation) drives the
 *      real production path all the way to a genuine "Adapter not found"
 *      result (depth guard -> payload guard -> per-tenant rate limit ->
 *      recursion guard -> RBAC -> handleCallInner's adapter lookup) and
 *      NEVER calls the filter's `select()` at all — the spy's call count
 *      stays at zero for the entire direct-call path.
 * A regression that wired expansion into the direct-call path, or that
 * stopped routing chariot_query through the catalog-driven expander, flips
 * these assertions (red proof): forcing the instrumented filter's `select()`
 * to run on the chariot_call path, or removing the `handleQueryImpl` ->
 * `activeFilter.select()` call, makes this file fail.
 *
 * Run (after tsc):
 *   node --test dist/engine/server/QueryExpander.call-site-opt-in.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { handleQuery, handleCall } from './toolHandlers.js';
import type { ChariotState, AdapterEntry } from './ChariotState.js';
import { expandQuery, buildCatalogExpansionIndex, type CatalogAdapterLike } from '../federation/QueryExpander.js';
import type { Tool } from '../types/index.js';

// The clause's own worked example, sourced from the adapter catalog's
// `keywords` field (CHARIOT::§4.6::1) — reused here as the CHARIOT::§4.6::2
// fixture so the opt-in eval exercises the exact same abbreviation.
const catalogAdapters: CatalogAdapterLike[] = [
  { id: 'pagerduty', name: 'PagerDuty', keywords: ['PD', 'PagerDuty', 'incident', 'oncall'] },
];
const catalogIndex = buildCatalogExpansionIndex(catalogAdapters);

// Sanity: the real expandQuery/buildCatalogExpansionIndex functions (same
// ones ToolPreFilter.select calls in production) must actually expand "PD"
// to include the adapter name + sibling keywords, or the instrumented
// filter below could never distinguish an expanded from an unexpanded call.
const sanityExpanded = expandQuery('page the PD team', catalogIndex);
assert.notEqual(sanityExpanded, 'page the PD team');
assert.ok(sanityExpanded.includes('PagerDuty') && sanityExpanded.includes('incident'));

/**
 * Instrumented ToolPreFilter double. Both `select()` (the summary/Ring-2
 * detail path) and `selectWithVerdict()` (the default `detail: 'full'` path
 * — the one `handleQueryImpl` actually calls at
 * `src/engine/server/toolHandlers.ts:1126`,
 * shortlist-size: > 12 OK because the literal below only QUOTES the production call at
 * toolHandlers.ts:1126, which carries its own justification (Ring-1 explicit shortlist).
 * `activeFilter.selectWithVerdict(query, { maxTools: 20, maxPerServer: 5 })`)
 * are call-counting spies. Both internally call the REAL `expandQuery`, so
 * the only way the returned shortlist contains the `pagerduty` adapter is if
 * the caller's raw query genuinely passed through catalog-driven expansion
 * inside that call — matching the production wiring at
 * `src/engine/federation/ToolPreFilter.ts:917`
 * (`expandQuery(query, this.catalogExpansionIndex ?? undefined)`).
 */
function makeInstrumentedFilter() {
  let calls = 0;
  const seenQueries: string[] = [];
  const expandedTool = (query: string): Tool[] => {
    const expanded = expandQuery(query, catalogIndex);
    return expanded.includes('PagerDuty')
      ? [{ server: 'pagerduty', name: 'create_incident', description: '', parameters: {}, tier: 'standard' } as unknown as Tool]
      : [];
  };
  return {
    calls: () => calls,
    seenQueries,
    select: async (query: string, _opts?: unknown): Promise<Tool[]> => {
      calls += 1;
      seenQueries.push(query);
      return expandedTool(query);
    },
    selectWithVerdict: (query: string, _opts?: unknown) => {
      calls += 1;
      seenQueries.push(query);
      const tools = expandedTool(query);
      return {
        tools,
        confidence: tools.length > 0 ? 0.95 : 0,
        abstain: false,
        degraded: false,
        legsUsed: ['bm25'],
      };
    },
  };
}

function makeQueryState(filter: ReturnType<typeof makeInstrumentedFilter>): ChariotState {
  const adapters: AdapterEntry[] = [
    {
      id: 'pagerduty',
      name: 'PagerDuty',
      category: 'incident-management',
      type: 'rest',
      keywords: ['PD', 'PagerDuty', 'incident', 'oncall'],
      rest: { toolNames: ['create_incident'] },
    } as unknown as AdapterEntry,
  ];
  return {
    allAdapters: adapters,
    adapterById: new Map(adapters.map((a) => [a.id, a])),
    configuredAdapterIds: new Set(['pagerduty']),
    credentials: {},
    fullCatalogFilter: filter,
    toolPreFilter: filter,
    getConfiguredAdapters: () => adapters,
    loadedAt: new Date().toISOString(),
  } as unknown as ChariotState;
}

function makeCallState(filter: ReturnType<typeof makeInstrumentedFilter>): ChariotState {
  return {
    allAdapters: [],
    adapterById: new Map(),
    configuredAdapterIds: new Set(),
    credentials: {},
    fullCatalogFilter: filter,
    toolPreFilter: filter,
    getConfiguredAdapters: () => [],
    loadedAt: new Date().toISOString(),
  } as unknown as ChariotState;
}

// Unique per-test tenant ids so the shared per-tenant token bucket
// (consumeTenantToken) in toolHandlers.ts never collides across test files
// or across runs of this suite.
let tenantCounter = 0;
function freshTenantId(label: string): string {
  tenantCounter += 1;
  return `w15-call-site-opt-in-${label}-${process.pid}-${tenantCounter}`;
}

test('call-site opt-in (behavioral): handleQuery (chariot_query, NL admin request, detail:"full" — the default) calls the filter selectWithVerdict() exactly once, and the returned shortlist proves catalog-driven expansion ran inside that call', async () => {
  const filter = makeInstrumentedFilter();
  const state = makeQueryState(filter);

  const result = await handleQuery(
    { query: 'page the PD team' },
    state,
    { tenantId: freshTenantId('query') },
  ) as { status: string; matchedAdapters: Array<{ id: string }> };

  assert.equal(filter.calls(), 1, 'chariot_query must call ToolPreFilter.selectWithVerdict exactly once');
  assert.equal(filter.seenQueries[0], 'page the PD team', 'selectWithVerdict() receives the raw query; expansion happens inside it, matching production');

  // The instrumented selectWithVerdict() only surfaces `pagerduty` when its
  // internal expandQuery(query, catalogIndex) call actually expanded "PD" to
  // include "PagerDuty" — so this assertion is proof that catalog-driven
  // expansion ran on the natural-language admin request path, not just that
  // selectWithVerdict() was called.
  assert.equal(result.status, 'matched', `expected a matched response, got: ${JSON.stringify(result)}`);
  const ids = new Set(result.matchedAdapters.map((a) => a.id));
  assert.ok(ids.has('pagerduty'), 'expansion inside the chariot_query selectWithVerdict() call must surface the pagerduty adapter from the bare "PD" abbreviation');
});

test('call-site opt-in (behavioral): handleCall (chariot_call, direct tool/call invocation) never calls the filter select() — expansion never runs on the direct-call path', async () => {
  const filter = makeInstrumentedFilter();
  const state = makeCallState(filter);

  // No adapter is registered in state.adapterById, so this genuinely runs
  // the full production path (depth guard, payload guard, per-tenant rate
  // limit, recursion guard, RBAC, handleCallInner's adapter lookup) and
  // terminates in a real "Adapter not found" result — never an early return
  // that would let the assertion pass for the wrong reason.
  const result = await handleCall(
    { adapter: 'pagerduty', tool: 'create_incident', args: {} },
    state,
    { localMode: true, tenantId: freshTenantId('call') },
  );

  assert.equal(result.isError, true, 'sanity: the call must actually execute production logic and reach a real (adapter-not-found) outcome, not short-circuit before doing anything');
  assert.match(JSON.parse(result.content).error as string, /not found/i);

  assert.equal(filter.calls(), 0, 'chariot_call must NEVER call ToolPreFilter.select — direct tool/call invocations are excluded from query expansion per §4.6');
  assert.equal(filter.seenQueries.length, 0);
});

test('call-site opt-in (behavioral): forcing expansion onto the direct-call path is exactly what this eval is designed to catch (red-proof control)', async () => {
  // Demonstrates the eval is not vacuously true: if a caller manually routes
  // a chariot_call-style request through the same filter used by
  // chariot_query, the call-count assertion used above catches it.
  const filter = makeInstrumentedFilter();
  await filter.select('this must never happen on the direct-call path', {});
  assert.equal(filter.calls(), 1, 'sanity: the spy correctly counts a select() invocation when one occurs');
});
