/**
 * CHARIOT §8.7::5 — CHARIOT-SPEC.md:781: "`RateLimiter.ts` — per-server
 * token bucket. Used by federation to back-pressure adapter calls when an
 * upstream returns 429." Also CHARIOT-SPEC.md:728: "An LLM that generates
 * a high-volume tool-call loop is back-pressured by the token bucket."
 *
 * Prove-on-revert: this test fails if EITHER half of the wiring is removed.
 *
 *   - Remove the `this.rateLimiter.penalize(tool.server)` call on a 429:
 *     the second dispatch to the SAME server still has spare tokens (the
 *     bucket here is sized at 5, only 1 is consumed by the pre-dispatch
 *     gate itself) and reaches the adapter a second time.
 *   - Remove the pre-dispatch `await this.rateLimiter.waitForAllowance(...)`
 *     gate entirely: even with penalize() still firing, nothing consults
 *     the drained bucket before the second dispatch, so it still reaches
 *     the adapter.
 *
 * Either regression shows up as `adapterA.callCount === 2` below, where the
 * fixed code holds it at 1.
 *
 * Run (after tsc): node --test dist/engine/federation/FederationManager.rate-limit-backpressure.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { FederationManager } from './FederationManager.js';
import type { MCPAdapter } from './adapters/base.js';
import type { Tool, ToolResult, ConnectionStatus } from '../types/index.js';

/** readOnlyHint:true so the destructive-annotation approval gate does not
 * short-circuit dispatch before the rate-limit gate is reached. */
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

/** Always answers with an upstream-429-shaped error, the same recognizable
 * shape ErrorClassifier's 'Rate limited' rule matches ('429' substring). */
class RateLimitedAdapter implements MCPAdapter {
  status: ConnectionStatus = 'connected';
  callCount = 0;
  constructor(readonly name: string, private readonly tools: Tool[]) {}
  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async listTools(): Promise<Tool[]> { return this.tools; }
  async ping(): Promise<number> { return 1; }
  async callTool(name: string): Promise<ToolResult> {
    this.callCount += 1;
    return {
      content: JSON.stringify({ error: '429 Too Many Requests' }),
      isError: true,
      server: this.name,
      tool: name,
      durationMs: 1,
      outcome: 'explicit_failure',
    };
  }
}

/** Always succeeds — used for the unaffected-server (isolation) side. */
class OkAdapter implements MCPAdapter {
  status: ConnectionStatus = 'connected';
  callCount = 0;
  constructor(readonly name: string, private readonly tools: Tool[]) {}
  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async listTools(): Promise<Tool[]> { return this.tools; }
  async ping(): Promise<number> { return 1; }
  async callTool(name: string): Promise<ToolResult> {
    this.callCount += 1;
    return {
      content: JSON.stringify({ ok: true }),
      isError: false,
      server: this.name,
      tool: name,
      durationMs: 1,
      outcome: 'success',
    };
  }
}

const SRV_A = 'srv-a';
const SRV_B = 'srv-b';

async function wire(): Promise<{ manager: FederationManager; adapterA: RateLimitedAdapter; adapterB: OkAdapter }> {
  const adapterA = new RateLimitedAdapter(SRV_A, [makeTool(SRV_A, 'ping')]);
  const adapterB = new OkAdapter(SRV_B, [makeTool(SRV_B, 'ping')]);

  const manager = new FederationManager(
    {
      servers: [
        { name: SRV_A, transport: 'streamable-http', url: 'https://a.installed-vendor.example.com/mcp' },
        { name: SRV_B, transport: 'streamable-http', url: 'https://b.installed-vendor.example.com/mcp' },
      ],
    },
    {
      // maxRequests:5 so the pre-dispatch gate itself (which always
      // consumes exactly one token per call) leaves 4 tokens spare after
      // the first call — any SECOND gated denial can only be explained by
      // penalize() draining the bucket on the 429, not by the bucket
      // running out on its own. windowMs is large enough that a drained
      // bucket's required wait (200000ms) exceeds waitForAllowance's
      // default 30000ms maxWaitMs, so the second call to A throws
      // synchronously instead of the test sleeping 200s.
      rateLimit: { maxRequests: 5, windowMs: 1_000_000 },
    },
  );

  await manager.connect(SRV_A, { name: SRV_A, transport: 'streamable-http', url: 'https://a.installed-vendor.example.com/mcp' }, adapterA);
  await manager.connect(SRV_B, { name: SRV_B, transport: 'streamable-http', url: 'https://b.installed-vendor.example.com/mcp' }, adapterB);

  return { manager, adapterA, adapterB };
}

test('§8.7::5: a 429 from server A back-pressures the NEXT call to server A', async () => {
  const { manager, adapterA } = await wire();

  const first = await manager.callTool(`${SRV_A}:ping`, {});
  assert.equal(first.isError, true, 'first call surfaces the upstream 429');
  assert.equal(adapterA.callCount, 1, 'first call reached the adapter');

  const second = await manager.callTool(`${SRV_A}:ping`, {});
  assert.equal(second.isError, true, 'second call is refused by the rate-limit gate');
  assert.equal(second.errorClass, 'rate_limit', 'refusal is typed as rate_limit, not a generic failure');
  assert.equal(
    adapterA.callCount,
    1,
    'second call never reached the adapter — the penalized bucket gated it before dispatch',
  );
});

test('§8.7::5: a 429 on server A does not back-pressure an unrelated server B', async () => {
  const { manager, adapterA, adapterB } = await wire();

  await manager.callTool(`${SRV_A}:ping`, {}); // penalizes A only
  assert.equal(adapterA.callCount, 1);

  const bResult = await manager.callTool(`${SRV_B}:ping`, {});
  assert.equal(bResult.isError, false, 'B is dispatched normally');
  assert.equal(adapterB.callCount, 1, "B was never gated by A's penalty");
});
