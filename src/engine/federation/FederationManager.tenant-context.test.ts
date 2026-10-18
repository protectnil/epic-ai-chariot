/**
 * Prove-on-revert for CHARIOT §8.9::11 — "TenantContext SHALL carry
 * request-scoped {tenantId, principalId, roles, attributes} through the
 * entire dispatch chain."
 *
 * The defect: FederationManager.callTool accepted only a bare `tenantId`
 * string plus a reduced CallToolActorContext {actorId, principalType,
 * readOnlyScope, sourceIp}. roles and attributes were resolved at the
 * authenticated boundary (trust/TenantContext.ts populates them from the JWT)
 * and then dropped before dispatch, so the egress-policy decision and the
 * anomaly report never saw the identity they are supposed to authorize on.
 *
 * These assertions observe the REAL dispatch path (no source-shape matching):
 * an egress auditor registered on the live ConnectionPool receives the actual
 * EgressContext that the policy decision was made with.
 *
 * Run (after tsc): node --test dist/engine/federation/FederationManager.tenant-context.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { FederationManager } from './FederationManager.js';
import type { MCPAdapter } from './adapters/base.js';
import type { Tool, ToolResult, ConnectionStatus } from '../types/index.js';
import type { TenantContext, EgressContext } from '../trust/types.js';

class FakeAdapter implements MCPAdapter {
  status: ConnectionStatus = 'connected';
  callCount = 0;

  constructor(readonly name: string, private readonly tools: Tool[]) {}

  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async listTools(): Promise<Tool[]> { return this.tools; }
  async ping(): Promise<number> { return 1; }
  async callTool(name: string, _args: Record<string, unknown>): Promise<ToolResult> {
    this.callCount += 1;
    return {
      content: JSON.stringify({ ok: true, name }),
      isError: false,
      server: this.name,
      tool: name,
      durationMs: 1,
      outcome: 'success',
    };
  }
}

/** readOnlyHint:true so the annotation gate does not short-circuit before egress. */
function makeTool(server: string, name: string): Tool {
  return {
    name,
    description: `test tool ${name}`,
    parameters: { type: 'object', properties: {} },
    server,
    tier: 'direct',
    annotations: { readOnlyHint: true },
  };
}

const ADAPTER = 'ctx-adapter';
const URL = 'https://api.installed-vendor.example.com/mcp';

async function wire(): Promise<{ manager: FederationManager; seen: EgressContext[] }> {
  const adapter = new FakeAdapter(ADAPTER, [makeTool(ADAPTER, 'ping')]);
  const manager = new FederationManager({
    servers: [{ name: ADAPTER, transport: 'streamable-http', url: URL }],
  });
  await manager.connect(ADAPTER, { name: ADAPTER, transport: 'streamable-http', url: URL }, adapter);

  const seen: EgressContext[] = [];
  manager.getPool().onEgressDecision((_decision, ctx) => { seen.push(ctx); });
  return { manager, seen };
}

const TENANT_CONTEXT: TenantContext = {
  tenantId: 'tenant-a',
  principalId: 'user-42',
  roles: ['finance-admin'],
  tier: 'enterprise',
  attributes: { region: 'eu', clearance: 'high' },
};

test('§8.9::11: authenticated roles + attributes reach the egress policy decision', async () => {
  const { manager, seen } = await wire();

  const result = await manager.callTool(`${ADAPTER}:ping`, {}, 'tenant-a', {
    actorId: 'user-42',
    tenantContext: TENANT_CONTEXT,
  });
  assert.equal(result.isError, false, 'dispatch should be allowed');

  assert.equal(seen.length, 1, 'exactly one egress decision observed');
  const ctx = seen[0];
  assert.equal(ctx.tenantId, 'tenant-a');
  assert.equal(ctx.principalId, 'user-42', 'principalId must reach the policy decision');
  assert.deepEqual(ctx.roles, ['finance-admin'], 'roles must reach the policy decision');
  assert.deepEqual(
    ctx.attributes,
    { region: 'eu', clearance: 'high' },
    'attributes must reach the policy decision',
  );
});

test('§8.9::11: the unauthenticated path asserts NO roles or attributes', async () => {
  const { manager, seen } = await wire();

  // No tenantContext — the OSS/local path. It must not gain an identity it
  // does not have: absent, never synthesized (createDevContext would assert
  // roles:['admin'] and is deliberately not used here).
  await manager.callTool(`${ADAPTER}:ping`, {});

  assert.equal(seen.length, 1);
  const ctx = seen[0];
  assert.equal(ctx.principalId, undefined, 'no principal asserted when unauthenticated');
  assert.equal(ctx.roles, undefined, 'no roles asserted when unauthenticated');
  assert.equal(ctx.attributes, undefined, 'no attributes asserted when unauthenticated');
});

test('§8.9::11: a positional tenantId conflicting with the authenticated tenant is rejected', async () => {
  const { manager } = await wire();

  // Silently preferring one would let a mismatched positional id mask the
  // authenticated tenant — the dispatch must fail closed instead.
  await assert.rejects(
    () => manager.callTool(`${ADAPTER}:ping`, {}, 'tenant-b', { tenantContext: TENANT_CONTEXT }),
    /does not match actor\.tenantContext\.tenantId/,
  );
});

test('§8.9::11: the authenticated tenant wins when no positional tenantId is given', async () => {
  const { manager, seen } = await wire();

  await manager.callTool(`${ADAPTER}:ping`, {}, undefined, { tenantContext: TENANT_CONTEXT });

  assert.equal(seen[0]?.tenantId, 'tenant-a', 'tenant comes from the authenticated context');
});
