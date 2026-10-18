/**
 * Regression eval — CHARIOT::§17.3::8,9,10 (CH-50) tool-count honesty for
 * chariot_list.
 *
 * CHARIOT-SPEC.md §17.3: "The tool counts surfaced by `chariot_query`/
 * `chariot_list` ... for a given adapter MUST equal that adapter's bundle
 * `toolCount` — the authoritative count carried in the signed bundle.
 * Showing '0 tools' for an adapter whose bundle `toolCount` is non-zero
 * (observed for `paypal`/`grafana-api`/`aws`, each with `toolCount`=25) is
 * forbidden; the count presented to the user or agent is the bundle count,
 * never a stale or empty runtime tally."
 *
 * Before this fix, handleList (toolHandlers.ts, chariot_list) computed
 * toolCount as `(a.rest?.toolNames ?? a.mcp?.toolNames ?? ...).length` — a
 * runtime name-list length that NEVER read `a.rest?.toolCount` /
 * `a.mcp?.toolCount`. handleQuery (chariot_query) already read the bundle
 * field correctly (CH-50 fixed there first) — this was the second half of
 * the same bug class recurring in the sibling handler.
 *
 * Run (after tsc):
 *   node --test dist/engine/server/toolHandlers.list-toolcount-honesty.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { handleList } from './toolHandlers.js';
import type { ChariotState, AdapterEntry } from './ChariotState.js';

function makeState(adapters: AdapterEntry[]): ChariotState {
  return {
    allAdapters: adapters,
    adapterById: new Map(adapters.map(a => [a.id, a])),
    configuredAdapterIds: new Set(adapters.map(a => a.id)),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => adapters,
    loadedAt: new Date().toISOString(),
  } as unknown as ChariotState;
}

test('chariot_list reports the bundle toolCount (rest), not the toolNames length, for paypal/grafana-api/aws', async () => {
  // The exact reproduction from the EARS text: bundle toolCount=25 for
  // each adapter, but the runtime toolNames array is empty/unpopulated —
  // this is precisely the shape that produced "0 tools" pre-fix.
  const adapters: AdapterEntry[] = [
    { id: 'paypal', name: 'paypal', category: 'finance', type: 'rest', rest: { toolCount: 25, toolNames: [] } },
    { id: 'grafana-api', name: 'grafana-api', category: 'observability', type: 'rest', rest: { toolCount: 25, toolNames: [] } },
    { id: 'aws', name: 'aws', category: 'cloud', type: 'mcp', mcp: { toolCount: 25, toolNames: [] } },
  ];
  const state = makeState(adapters);

  const result = await handleList({}, state) as { adapters: Array<{ id: string; toolCount: number }> };
  const byId = new Map(result.adapters.map(a => [a.id, a.toolCount]));

  assert.equal(byId.get('paypal'), 25, 'paypal toolCount must equal bundle toolCount (25), not toolNames.length (0)');
  assert.equal(byId.get('grafana-api'), 25, 'grafana-api toolCount must equal bundle toolCount (25), not toolNames.length (0)');
  assert.equal(byId.get('aws'), 25, 'aws (mcp) toolCount must equal bundle toolCount (25), not toolNames.length (0)');
});

test('chariot_list never surfaces 0 for an adapter whose bundle toolCount is non-zero', async () => {
  const adapters: AdapterEntry[] = [
    { id: 'paypal', name: 'paypal', category: 'finance', type: 'rest', rest: { toolCount: 25, toolNames: [] } },
  ];
  const state = makeState(adapters);

  const result = await handleList({}, state) as { adapters: Array<{ id: string; toolCount: number }> };
  assert.notEqual(result.adapters[0]?.toolCount, 0);
  assert.equal(result.adapters[0]?.toolCount, 25);
});

test('chariot_list falls back to the runtime name-list length only when the bundle stamped no toolCount', async () => {
  const adapters: AdapterEntry[] = [
    { id: 'no-count-adapter', name: 'no-count-adapter', category: 'misc', type: 'rest', rest: { toolNames: ['a', 'b', 'c'] } },
  ];
  const state = makeState(adapters);

  const result = await handleList({}, state) as { adapters: Array<{ id: string; toolCount: number }> };
  assert.equal(result.adapters[0]?.toolCount, 3, 'with no bundle toolCount stamped, falls back to toolNames.length');
});
