/**
 * Regression test — Chariot 4.0.0, post-185c123 egress default-on fix.
 *
 * Commit 185c123 made FederationManager synthesize a deny-by-default
 * `AccessPolicyEngine` egress policy whenever `FederationConfig.egressPolicy`
 * is omitted (Gap #9 / Wiz 4). That closed a real hole (egress enforcement
 * was previously never wired at all, so every outbound dispatch was
 * silently allow-all) but introduced a *latent regression*: the synthesized
 * policy had ZERO allow rules, so a deployment that never wrote explicit
 * egress config could not reach ANY of its own installed adapters —
 * network (`streamable-http`) OR stdio (stdio dispatch is also evaluated
 * by `evaluateEgress`, under a synthetic `stdio:<name>` host — see
 * `resolveEgressTargetOrDeny`'s doc comment) — out of the box.
 *
 * The fix (`buildInstalledAdapterEgressAllowlist` in FederationManager.ts)
 * seeds the omitted-config default with one narrow allow rule per adapter
 * declared in `config.servers` — the exact list `connectAll()` dispatches
 * to — scoped to both that adapter's name and its own declared
 * destination. This test proves all three required invariants under the
 * OMITTED-egressPolicy default (no explicit egressPolicy passed anywhere
 * below):
 *
 *   (a) dispatch to an adapter DECLARED in `config.servers`
 *       (`streamable-http`, catalog-installed) is ALLOWED.
 *   (b) dispatch to a `streamable-http` adapter connected OUTSIDE
 *       `config.servers` (i.e. an undeclared destination) is DENIED.
 *   (c) dispatch to a `stdio` adapter DECLARED in `config.servers` is
 *       ALLOWED — stdio is unaffected by the default-deny regression.
 *
 * Run (after `tsc`):
 *   node --test dist/engine/federation/FederationManager.egress-default-allowlist.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { FederationManager } from './FederationManager.js';
import type { MCPAdapter } from './adapters/base.js';
import type { Tool, ToolResult, ConnectionStatus } from '../types/index.js';

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

/** readOnlyHint:true so the annotation gate (gap #2) does not force an
 *  approval-required response before dispatch ever reaches the egress
 *  gate — these tests are scoped to egress, not the approval gate. */
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

test('egress default allowlist: declared streamable-http adapter is ALLOWED, undeclared host is DENIED, declared stdio adapter is ALLOWED', async () => {
  const declaredNetName = 'catalog-net-adapter';
  const declaredStdioName = 'catalog-stdio-adapter';
  const undeclaredNetName = 'undeclared-net-adapter';

  const declaredNetTool = makeTool(declaredNetName, 'ping');
  const declaredStdioTool = makeTool(declaredStdioName, 'ping');
  const undeclaredNetTool = makeTool(undeclaredNetName, 'ping');

  const declaredNetAdapter = new FakeAdapter(declaredNetName, [declaredNetTool]);
  const declaredStdioAdapter = new FakeAdapter(declaredStdioName, [declaredStdioTool]);
  const undeclaredNetAdapter = new FakeAdapter(undeclaredNetName, [undeclaredNetTool]);

  // NO egressPolicy passed — this is the omitted-config default path that
  // 185c123 made deny-by-default. `config.servers` declares exactly the
  // two adapters that should be auto-allowed; `undeclaredNetName` is
  // deliberately NOT in this list.
  const manager = new FederationManager({
    servers: [
      {
        name: declaredNetName,
        transport: 'streamable-http',
        url: 'https://api.installed-vendor.example.com/mcp',
      },
      {
        name: declaredStdioName,
        transport: 'stdio',
        command: 'true',
      },
    ],
  });

  await manager.connect(
    declaredNetName,
    { name: declaredNetName, transport: 'streamable-http', url: 'https://api.installed-vendor.example.com/mcp' },
    declaredNetAdapter,
  );
  await manager.connect(
    declaredStdioName,
    { name: declaredStdioName, transport: 'stdio', command: 'true' },
    declaredStdioAdapter,
  );
  // Connected OUTSIDE config.servers — simulates a destination the
  // operator never declared/installed via the catalog.
  await manager.connect(
    undeclaredNetName,
    { name: undeclaredNetName, transport: 'streamable-http', url: 'https://not-declared.example.com/mcp' },
    undeclaredNetAdapter,
  );

  // (a) declared streamable-http adapter — ALLOWED.
  const declaredNetResult = await manager.callTool(`${declaredNetName}:ping`, {});
  assert.equal(declaredNetResult.isError, false, `declared network adapter should be allowed, got: ${JSON.stringify(declaredNetResult)}`);
  assert.equal(declaredNetAdapter.callCount, 1);

  // (b) undeclared host — DENIED, dispatch never reaches the adapter.
  const undeclaredResult = await manager.callTool(`${undeclaredNetName}:ping`, {});
  assert.equal(undeclaredResult.isError, true, 'undeclared-host adapter should be denied by default');
  const undeclaredContent = Array.isArray(undeclaredResult.content)
    ? JSON.stringify(undeclaredResult.content)
    : String(undeclaredResult.content);
  assert.match(undeclaredContent, /denied by policy/);
  assert.equal(undeclaredNetAdapter.callCount, 0, 'adapter must never be invoked when egress denies the dispatch');

  // (c) declared stdio adapter — ALLOWED (stdio unaffected).
  const stdioResult = await manager.callTool(`${declaredStdioName}:ping`, {});
  assert.equal(stdioResult.isError, false, `declared stdio adapter should be allowed, got: ${JSON.stringify(stdioResult)}`);
  assert.equal(declaredStdioAdapter.callCount, 1);
});
