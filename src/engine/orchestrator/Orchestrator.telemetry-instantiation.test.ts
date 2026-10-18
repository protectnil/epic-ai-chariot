/**
 * CHARIOT::§8.12::4/::5 (W34-4b) — production instantiation: "the
 * Orchestrator owns one RunTelemetryCollector per run and one TokenTracker
 * per EpicAI instance; recordTokens() at the real token-usage sites (both
 * LLM call sites' usage responses), recordAudit() at the audit-write
 * site; the snapshot is retrievable from the run/stream result."
 *
 * Defect this catches: RunTelemetryCollector/TokenTracker were exported
 * but never instantiated anywhere in production code (0 hits for
 * `new RunTelemetryCollector`/`new TokenTracker` repo-wide before this
 * change) — RunResult had no telemetry field at all.
 *
 * Run (after tsc):
 *   node --test dist/engine/orchestrator/Orchestrator.telemetry-instantiation.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Orchestrator } from './Orchestrator.js';
import { FederationManager } from '../federation/FederationManager.js';
import { ToolPreFilter } from '../federation/ToolPreFilter.js';
import { PersonaManager } from '../persona/PersonaManager.js';
import { AuditTrail } from '../audit/AuditTrail.js';
import { TieredAutonomy } from '../autonomy/TieredAutonomy.js';
import { TokenTracker } from '../observability/TokenTracker.js';
import type { MCPAdapter } from '../federation/adapters/base.js';
import type { ConnectionStatus, LLMFunction, Tool, ToolResult } from '../types/index.js';

// RCA (chariot-verify-wave1, applied here proactively — see the identical
// fix + full explanation in Orchestrator.mfa-generator-invalidation.test.ts):
// Orchestrator falls back to a fresh, never-`.index()`ed ToolPreFilter when
// none is passed in deps, so dispatch is never reached without this.
function indexedPreFilter(tool: Tool): ToolPreFilter {
  const preFilter = new ToolPreFilter();
  preFilter.index([tool]);
  return preFilter;
}

class RealAdapter implements MCPAdapter {
  status: ConnectionStatus = 'connected';
  constructor(readonly name: string, private readonly tools: Tool[]) {}
  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async listTools(): Promise<Tool[]> { return this.tools; }
  async ping(): Promise<number> { return 1; }
  async callTool(name: string): Promise<ToolResult> {
    return { content: 'ok', isError: false, server: this.name, tool: name, durationMs: 1, outcome: 'success' };
  }
}

test('§8.12::4: RunResult.telemetry is populated with real counts after run()', async () => {
  const serverName = 'srv';
  const tool: Tool = { name: 'search_repos', description: 'searches', parameters: { type: 'object', properties: {} }, server: serverName, tier: 'orchestrated', annotations: { readOnlyHint: true } };
  const adapter = new RealAdapter(serverName, [tool]);
  const federation = new FederationManager({ servers: [{ name: serverName, transport: 'stdio', command: 'true' }] });
  await federation.connect(serverName, { name: serverName, transport: 'stdio', command: 'true' }, adapter);
  const persona = new PersonaManager();
  persona.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });
  const audit = new AuditTrail({ store: 'memory', integrity: 'none' });
  // CHARIOT-verify-wave2 RCA (see Orchestrator.mfa-generator-invalidation.test.ts's
  // full RCA doc comment): FederationManager namespaces every listed tool's
  // name as `${server}:${originalName}`; autonomy rules and the mocked
  // orchestratorLLM's toolCalls[].name must use that namespaced form.
  const autonomy = new TieredAutonomy({ auto: ['srv:search_repos'], escalate: [], approve: [] });
  const tokenTracker = new TokenTracker();

  // Every orchestratorLLM invocation (this loop calls it once per
  // iteration — including the empty-toolCalls call that ends the loop, NOT
  // just once per turn) reports usage, so token totals stay fully
  // deterministic regardless of how many planning iterations run.
  let calls = 0;
  const orchestratorLLM: LLMFunction = async () => {
    calls++;
    if (calls === 1) {
      return { content: null, toolCalls: [{ id: '1', name: 'srv:search_repos', arguments: {} }], finishReason: 'tool_calls', usage: { inputTokens: 40, outputTokens: 10, totalTokens: 50 } };
    }
    return { content: null, toolCalls: [], finishReason: 'stop', usage: { inputTokens: 5, outputTokens: 1, totalTokens: 6 } };
  };
  const generatorLLM: LLMFunction = async () => ({ content: 'final answer', toolCalls: [], finishReason: 'stop', usage: { inputTokens: 80, outputTokens: 20, totalTokens: 100 } });

  const orchestrator = new Orchestrator({ orchestratorLLM, generatorLLM, federation, autonomy, persona, audit, maxIterations: 6, tokenTracker, toolPreFilter: indexedPreFilter(tool) });

  const result = await orchestrator.run('find the repo', 'user-1');

  // RunResult.telemetry — additive, OPTIONAL field (round-2 finding: made
  // optional because JSONResponse.collect() is a second, generic RunResult
  // constructor with no snapshot to offer — see the field's doc comment in
  // types/index.ts). Orchestrator.run() itself always populates it though,
  // so the non-null assertions below are safe for THIS constructor.
  assert.ok(result.telemetry, 'RunResult must carry a telemetry snapshot');
  const telemetry = result.telemetry!;
  assert.equal(telemetry.toolCalls, 1, 'one real dispatch happened');
  assert.equal(telemetry.auditRecords, 1, 'one audit.record() call happened');
  assert.equal(calls, 2, 'sanity: the loop called orchestratorLLM twice (dispatch iteration + the empty-toolCalls iteration that ends the loop)');
  assert.equal(telemetry.tokenIn, 40 + 5 + 80, 'tokenIn sums ALL recorded generator calls (2 planning + 1 synthesis)');
  assert.equal(telemetry.tokenOut, 10 + 1 + 20);
  assert.equal(telemetry.latencyMs, telemetry.durationMs);

  // TokenTracker (cross-run ledger, injected via deps) — populated too.
  const summary = tokenTracker.summary();
  assert.equal(summary.entries.length, 3, 'one record() call per recorded generator call (2 planning + 1 synthesis)');
  assert.ok(summary.byAdapter['srv'], 'the dispatch-attributed calls (2nd planning call + synthesis) are attributed to the last-dispatched adapter (srv)');
  assert.equal(summary.totalTokens, 40 + 10 + 5 + 1 + 80 + 20);

  autonomy.destroy();
});

test('§8.12::4: without deps.tokenTracker wired, run() still works — recordGeneratorUsage no-ops the cross-run side', async () => {
  const serverName = 'srv2';
  const tool: Tool = { name: 'ping', description: 'pings', parameters: { type: 'object', properties: {} }, server: serverName, tier: 'orchestrated', annotations: { readOnlyHint: true } };
  const adapter = new RealAdapter(serverName, [tool]);
  const federation = new FederationManager({ servers: [{ name: serverName, transport: 'stdio', command: 'true' }] });
  await federation.connect(serverName, { name: serverName, transport: 'stdio', command: 'true' }, adapter);
  const persona = new PersonaManager();
  persona.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });
  const audit = new AuditTrail({ store: 'memory', integrity: 'none' });
  const autonomy = new TieredAutonomy({ auto: ['srv2:ping'], escalate: [], approve: [] });

  let calls = 0;
  const orchestratorLLM: LLMFunction = async () => {
    calls++;
    if (calls === 1) return { content: null, toolCalls: [{ id: '1', name: 'srv2:ping', arguments: {} }], finishReason: 'tool_calls' };
    return { content: null, toolCalls: [], finishReason: 'stop' };
  };
  const generatorLLM: LLMFunction = async () => ({ content: 'pong', toolCalls: [], finishReason: 'stop' });

  // No tokenTracker in deps.
  const orchestrator = new Orchestrator({ orchestratorLLM, generatorLLM, federation, autonomy, persona, audit, maxIterations: 6, toolPreFilter: indexedPreFilter(tool) });
  const result = await orchestrator.run('ping it');

  // A dispatched-tool turn's narrative gets a "\n\nSources: [...]" suffix
  // appended (Orchestrator.ts:1227) — startsWith, not exact equality.
  assert.ok(result.response.startsWith('pong'), `got: ${result.response}`);
  assert.ok(result.telemetry, 'the per-run RunTelemetryCollector is unconditional (not gated on tokenTracker)');
  const telemetry = result.telemetry!;
  // No response.usage provided either — estimateTokens() fallback still produces non-negative numbers.
  assert.ok(telemetry.tokenIn >= 0);
  assert.ok(telemetry.tokenOut >= 0);

  autonomy.destroy();
});
