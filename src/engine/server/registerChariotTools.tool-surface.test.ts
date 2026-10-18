/**
 * Regression eval — C4AMD::§2::1 (rulings item 25) MCP client-visible tool
 * surface conformance.
 *
 * C4AMD (spec amendment) §2, "Product contract":
 *   "Chariot exposes only three client-visible MCP tools: `chariot_query`,
 *   `chariot_call`, and `chariot_list`."
 *
 * CHARIOT-SPEC.md §17.3 ("MCP tool registration (CH-16)"):
 *   "`src/engine/server/registerChariotTools.ts` is the single registration
 *   site for tools the AI client sees. The current registration surface is
 *   **three** tools: ... All three tools dispatch through `handleQuery`,
 *   `handleCall`, `handleList` in `src/engine/server/toolHandlers.ts`."
 *
 * CHARIOT-SPEC.md §22.2 ("Dogfood Configuration", Posture A):
 *   "The MCP gateway exposes exactly 3 tools (`chariot_query`, `chariot_call`,
 *   `chariot_list`) per §17.3."
 *
 * Before this fix, registerChariotTools registered SEVEN additional tools
 * unconditionally alongside the three the clauses above allow:
 * chariot_remember, chariot_resolve_entity, chariot_recall,
 * chariot_compare_entities, chariot_forget, chariot_entity_profile, and
 * chariot_validate_claim. Neither C4AMD §2 nor CHARIOT §17.3/§22.2 admits a
 * conditional home for any of the seven on the MCP surface, so this eval
 * asserts the registered tool-name set equals EXACTLY the three-tool set and
 * fails on any additional registration.
 *
 * Run (after tsc):
 *   node --test dist/engine/server/registerChariotTools.tool-surface.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { registerChariotTools, CLIENT_VISIBLE_TOOL_NAMES } from './registerChariotTools.js';
import type { ChariotState } from './ChariotState.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

// The seven tools the pre-fix code registered unconditionally, in addition
// to the three the clauses allow. Named explicitly (rather than derived) so
// this list can never silently track a future registerChariotTools edit.
const FORMERLY_UNCONDITIONAL_EXTRA_TOOLS = [
  'chariot_remember',
  'chariot_resolve_entity',
  'chariot_recall',
  'chariot_compare_entities',
  'chariot_forget',
  'chariot_entity_profile',
  'chariot_validate_claim',
] as const;

function captureRegisteredNames(): { server: McpServer; names: string[] } {
  const names: string[] = [];
  const fakeServer = {
    tool(name: string, ..._rest: unknown[]) {
      names.push(name);
    },
  };
  return { server: fakeServer as unknown as McpServer, names };
}

test('C4AMD::§2::1 — registerChariotTools registers exactly {chariot_query, chariot_call, chariot_list}', () => {
  const { server, names } = captureRegisteredNames();
  const state = {} as unknown as ChariotState;

  registerChariotTools(server, state, { tenantId: 'test-tenant', localMode: true });

  assert.deepEqual(
    [...names].sort(),
    [...CLIENT_VISIBLE_TOOL_NAMES].sort(),
    'registered MCP tool names must equal exactly the C4AMD §2 / CHARIOT §17.3+§22.2 allowed set',
  );
});

test('C4AMD::§2::1 — none of the seven formerly-unconditional extra tools are registered', () => {
  const { server, names } = captureRegisteredNames();
  const state = {} as unknown as ChariotState;

  registerChariotTools(server, state, { tenantId: 'test-tenant', localMode: true });

  for (const forbidden of FORMERLY_UNCONDITIONAL_EXTRA_TOOLS) {
    assert.ok(
      !names.includes(forbidden),
      `${forbidden} must not be registered on the MCP surface (no conditional home in C4AMD §2 or CHARIOT §17.3/§22.2)`,
    );
  }
});
