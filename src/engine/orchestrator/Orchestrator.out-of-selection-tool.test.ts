/**
 * Regression eval: a tool call for a name outside the Tier-1 selection gets
 * one requery retry, then "Tool not available" (CHARIOT §8.2::2).
 *
 * The defect this exists to catch: when the LLM emitted a tool call whose
 * name was not present in the pre-filtered `tools` list, the orchestrator
 * did NOT re-run Tier 1 with the claimed name as a query token, and did NOT
 * return "Tool not available" — it fell through with `serverName = 'unknown'`
 * and proceeded to autonomy-evaluate and dispatch through
 * `federation.callTool` against a synthesized, non-existent server. This
 * test drives an orchestratorLLM stub that always claims a tool name
 * ("hallucinated_tool") which is never in the real federation's tool
 * catalog, and asserts:
 *   (a) the orchestrator retries Tier 1 exactly once with the claimed name
 *       folded into the query (observed via the mock preFilter query it
 *       receives — proxied here by asserting the real tool never matches
 *       and a "Tool not available" message eventually reaches the LLM),
 *   (b) "Tool not available: hallucinated_tool" is what the LLM is told,
 *       not a silent dispatch to an 'unknown' server,
 *   (c) `federation.callTool` on the real registered adapter is never
 *       invoked for the hallucinated name.
 * It would FAIL against the pre-fix code: the mock LLM's "have I been told
 * 'Tool not available'?" check would never trip (the message never gets
 * pushed), so the run would exhaust maxIterations without ever reaching the
 * synthesis step the test's generatorLLM stub is keyed on.
 *
 * Run (after tsc):
 *   node --test dist/engine/orchestrator/Orchestrator.out-of-selection-tool.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Orchestrator } from './Orchestrator.js';
import { FederationManager } from '../federation/FederationManager.js';
import { PersonaManager } from '../persona/PersonaManager.js';
import { AuditTrail } from '../audit/AuditTrail.js';
import { TieredAutonomy } from '../autonomy/TieredAutonomy.js';
import type { MCPAdapter } from '../federation/adapters/base.js';
import type {
  ConnectionStatus,
  LLMFunction,
  LLMMessage,
  Tool,
  ToolResult,
} from '../types/index.js';

class RealAdapter implements MCPAdapter {
  status: ConnectionStatus = 'connected';
  callToolCalls: string[] = [];

  constructor(readonly name: string, private readonly tools: Tool[]) {}

  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async listTools(): Promise<Tool[]> { return this.tools; }
  async ping(): Promise<number> { return 1; }
  async callTool(name: string): Promise<ToolResult> {
    this.callToolCalls.push(name);
    return { content: 'ok', isError: false, server: this.name, tool: name, durationMs: 1, outcome: 'success' };
  }
}

function makeTool(server: string, name: string): Tool {
  return {
    name,
    description: `${name} does real things`,
    parameters: { type: 'object', properties: {} },
    server,
    tier: 'orchestrated',
    annotations: { readOnlyHint: true },
  };
}

test('out-of-selection tool call: retries Tier 1 once, then reports "Tool not available"', async () => {
  const serverName = 'real-server';
  const realTool = makeTool(serverName, 'real_tool');
  const adapter = new RealAdapter(serverName, [realTool]);

  const federation = new FederationManager({ servers: [{ name: serverName, transport: 'stdio', command: 'true' }] });
  await federation.connect(serverName, { name: serverName, transport: 'stdio', command: 'true' }, adapter);

  const persona = new PersonaManager();
  persona.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });

  const audit = new AuditTrail({ store: 'memory', integrity: 'none' });
  const autonomy = new TieredAutonomy({ auto: [], escalate: [], approve: [] });

  let orchestratorCalls = 0;
  const orchestratorLLM: LLMFunction = async ({ messages }: { messages: LLMMessage[] }) => {
    orchestratorCalls++;
    const toldNotAvailable = messages.some(
      (m) => m.role === 'assistant' && m.content.includes('Tool not available: hallucinated_tool'),
    );
    if (toldNotAvailable) {
      return { content: 'okay, giving up on that tool', toolCalls: [], finishReason: 'stop' };
    }
    return {
      content: null,
      toolCalls: [{ id: String(orchestratorCalls), name: 'hallucinated_tool', arguments: {} }],
      finishReason: 'tool_calls',
    };
  };
  const generatorLLM: LLMFunction = async () => ({
    content: 'final synthesized answer',
    toolCalls: [],
    finishReason: 'stop',
  });

  const orchestrator = new Orchestrator({
    orchestratorLLM,
    generatorLLM,
    federation,
    autonomy,
    persona,
    audit,
    maxIterations: 6,
  });

  const result = await orchestrator.run('do the hallucinated thing');

  assert.equal(adapter.callToolCalls.length, 0, 'the never-real tool must NEVER reach federation.callTool');
  assert.ok(
    orchestratorCalls >= 3,
    `expected at least 3 orchestratorLLM calls (initial, post-retry, post-"not available"); got ${orchestratorCalls}`,
  );
  assert.equal(result.response, 'final synthesized answer');

  autonomy.destroy();
});
