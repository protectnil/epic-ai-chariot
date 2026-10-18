/**
 * Chariot 4.0.0 security-gap closure — FederationManager.callTool() gates.
 *
 * Covers three of the five Wiz-audited gaps fixed in this change:
 *
 *   - gap #2 (annotation gate): a tool with NO `annotations.readOnlyHint
 *     === true` (or an explicit `destructiveHint === true`) must require
 *     approval before dispatch, REGARDLESS of the adapter catalog's
 *     manual `requiresApproval` flag (there is no catalog wired at all in
 *     these tests — the point is the gate fires without one).
 *   - gap #7 (unverified-adapter gate): a `verifiedCatalog` lookup
 *     reporting 'failed' is an outright refusal; 'pending'/'stale' force
 *     the same approval gate even for an otherwise read-only-annotated
 *     tool; 'verified' is a no-op.
 *   - T4 wiring: callTool() reports every dispatch decision to the shared
 *     anomaly detector via reportToolDispatch(), and a destructive call
 *     made under an (asserted) read-only-scoped actor fires the
 *     'scope-violation' finding.
 *
 * Run (after `tsc`):
 *   node --test dist/engine/federation/FederationManager.annotation-gate.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { FederationManager } from './FederationManager.js';
import type { MCPAdapter } from './adapters/base.js';
import type { Tool, ToolResult, ConnectionStatus } from '../types/index.js';
import type { AdapterVerificationLookup } from '../trust/types.js';
import { anomalyAlertQueue } from '../../observability/anomaly/wiring.js';

// ── fake adapter ─────────────────────────────────────────────────────────

class FakeAdapter implements MCPAdapter {
  status: ConnectionStatus = 'connected';
  callCount = 0;

  constructor(readonly name: string, private readonly tools: Tool[]) {}

  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async listTools(): Promise<Tool[]> {
    return this.tools;
  }
  async ping(): Promise<number> {
    return 1;
  }
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

function makeTool(server: string, name: string, annotations?: Tool['annotations']): Tool {
  return {
    name,
    description: `test tool ${name}`,
    parameters: { type: 'object', properties: {} },
    server,
    tier: 'direct',
    ...(annotations ? { annotations } : {}),
  };
}

/** Explicit permissive egress config so gap #9's default-deny does not
 *  interfere with these annotation/verification-gate assertions — each
 *  test below is scoped to a different gate. */
const PERMISSIVE_EGRESS = { defaultEffect: 'allow' as const };

let adapterSeq = 0;
/** Every call gets its OWN adapter/server name. The anomaly AlertQueue
 *  dedupes by `${event.type}:${adapterId}` (see src/observability/alerts.ts)
 *  — sharing an adapter name across tests would let an unrelated finding
 *  from one test's dispatch (e.g. cross-tenant-drift, since several tests
 *  here reuse the default actorId 'unknown' across different tenantIds)
 *  silently suppress another test's finding via that dedupe window. Unique
 *  names per test keep each test's alert-queue assertions isolated. */
function nextAdapterName(): string {
  adapterSeq += 1;
  return `fake-adapter-${adapterSeq}`;
}

async function buildManager(
  toolNames: Array<{ name: string; annotations?: Tool['annotations'] }>,
  options: ConstructorParameters<typeof FederationManager>[1] = {},
): Promise<{ manager: FederationManager; adapter: FakeAdapter; adapterName: string }> {
  const adapterName = nextAdapterName();
  const tools = toolNames.map((t) => makeTool(adapterName, t.name, t.annotations));
  const adapter = new FakeAdapter(adapterName, tools);
  const manager = new FederationManager(
    { servers: [], egressPolicy: PERMISSIVE_EGRESS },
    options,
  );
  await manager.connect(adapterName, { name: adapterName, transport: 'stdio', command: 'true' }, adapter);
  return { manager, adapter, adapterName };
}

// ── gap #2: annotation gate ─────────────────────────────────────────────

test('gap #2: tool with no annotations requires approval even with no catalog wired', async () => {
  const { manager, adapter, adapterName } = await buildManager([{ name: 'unannotated' }]);
  const result = await manager.callTool(`${adapterName}:unannotated`, {});
  assert.equal(result.isError, true, 'unannotated tool must be gated');
  assert.equal(result.outcome, 'escalated');
  assert.equal(adapter.callCount, 0, 'dispatch must not reach the adapter');
  assert.match(String(result.content), /approval_required/);
});

test('gap #2: destructiveHint===true forces approval even when readOnlyHint is also set', async () => {
  const { manager, adapter, adapterName } = await buildManager([
    { name: 'destructive-tool', annotations: { readOnlyHint: true, destructiveHint: true } },
  ]);
  const result = await manager.callTool(`${adapterName}:destructive-tool`, {});
  assert.equal(result.isError, true);
  assert.equal(adapter.callCount, 0);
});

test('gap #2: readOnlyHint===true with no destructiveHint dispatches without approval (no regression)', async () => {
  const { manager, adapter, adapterName } = await buildManager([
    { name: 'safe-tool', annotations: { readOnlyHint: true } },
  ]);
  const result = await manager.callTool(`${adapterName}:safe-tool`, {});
  assert.equal(result.isError, false, 'verifiably read-only tool must not be gated');
  assert.equal(adapter.callCount, 1);
});

test('gap #2: pre-approving the (tenant, adapter, tool, args) key lets a gated call through', async () => {
  const { manager, adapter, adapterName } = await buildManager([{ name: 'unannotated' }]);
  const first = await manager.callTool(`${adapterName}:unannotated`, { x: 1 }, 'tenant-a');
  assert.equal(first.isError, true);
  const approvalMatch = /"approvalKey":"([^"]+)"/.exec(String(first.content));
  assert.ok(approvalMatch, 'approval_required response must carry an approvalKey');
  manager.getApprovalRegistry().approve(approvalMatch![1]);
  const second = await manager.callTool(`${adapterName}:unannotated`, { x: 1 }, 'tenant-a');
  assert.equal(second.isError, false, 'pre-approved key must let the same call through');
  assert.equal(adapter.callCount, 1);
});

// ── gap #7: unverified-adapter gate ─────────────────────────────────────

function fakeVerifiedCatalog(status: 'verified' | 'failed' | 'pending' | 'stale'): AdapterVerificationLookup {
  return { getVerification: () => ({ status }) };
}

test("gap #7: 'failed' verification status is an outright refusal", async () => {
  const { manager, adapter, adapterName } = await buildManager(
    [{ name: 'safe-tool', annotations: { readOnlyHint: true } }],
    { verifiedCatalog: fakeVerifiedCatalog('failed') },
  );
  const result = await manager.callTool(`${adapterName}:safe-tool`, {});
  assert.equal(result.isError, true);
  assert.equal(result.outcome, 'explicit_failure');
  assert.equal(adapter.callCount, 0);
});

test("gap #7: 'pending' verification status forces approval even for a read-only-annotated tool", async () => {
  const { manager, adapter, adapterName } = await buildManager(
    [{ name: 'safe-tool', annotations: { readOnlyHint: true } }],
    { verifiedCatalog: fakeVerifiedCatalog('pending') },
  );
  const result = await manager.callTool(`${adapterName}:safe-tool`, {});
  assert.equal(result.isError, true);
  assert.equal(result.outcome, 'escalated');
  assert.equal(adapter.callCount, 0);
});

test("gap #7: 'verified' status is a no-op (no regression for verified adapters)", async () => {
  const { manager, adapter, adapterName } = await buildManager(
    [{ name: 'safe-tool', annotations: { readOnlyHint: true } }],
    { verifiedCatalog: fakeVerifiedCatalog('verified') },
  );
  const result = await manager.callTool(`${adapterName}:safe-tool`, {});
  assert.equal(result.isError, false);
  assert.equal(adapter.callCount, 1);
});

// ── T4 wiring: reportToolDispatch / scope-violation ─────────────────────

test('T4 wiring: a destructive call under an asserted read-only-scoped actor fires scope-violation', async () => {
  const { manager, adapterName } = await buildManager([
    { name: 'destructive-tool', annotations: { destructiveHint: true } },
  ]);
  const pendingBefore = anomalyAlertQueue.getPending().length;
  await manager.callTool(
    `${adapterName}:destructive-tool`,
    {},
    'tenant-scope-test',
    { actorId: 'agent-007', readOnlyScope: true },
  );
  const pendingAfter = anomalyAlertQueue.getPending();
  assert.ok(
    pendingAfter.length > pendingBefore,
    'scope-violation finding must be enqueued when a read-only-scoped actor issues a destructive call',
  );
  const found = pendingAfter.some(
    (a) => (a.event.message ?? '').includes('scope-violation') && a.event.data.actorId === 'agent-007',
  );
  assert.ok(found, 'the enqueued alert must reference the scope-violation rule and the offending actor');
});
