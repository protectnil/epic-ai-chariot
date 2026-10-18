/**
 * CHARIOT §8.2::3 — CHARIOT-SPEC.md:679: "WHEN an MFA-required tool is
 * dispatched the generator instance for that turn SHALL be bound to the
 * MFA assertion. A revoked MFA invalidates the generator without affecting
 * the rest of the agent state."
 *
 * Drives the real Orchestrator + real mfa.ts assertion primitives (backed
 * by the in-process Redis shim, session.ts's own already-blessed
 * Redis-absent test double — no mocking library, no fake assertion store)
 * through three invariants:
 *
 *   1. BIND: dispatching a tool with `annotations.requiresMfa: true` mints
 *      a real MFA assertion (observed by intercepting the shim's own
 *      `set()` call for the `ent:mfa-assertion-epoch:` key Orchestrator's
 *      internal mintMfaAssertion() writes — no internal Orchestrator state
 *      is reached into for this).
 *   2. INVALIDATION: revoking that captured assertion mid-turn (before the
 *      turn's synthesis generator call) makes the NEXT generator call
 *      throw MfaAssertionRevokedError — the tool itself still dispatched
 *      (proving the invalidation is a synthesis-time check, not a
 *      dispatch-time block) but the final answer is never synthesized.
 *   3. ISOLATION: a SECOND, independent execute() call (a different turn)
 *      started AFTER the first turn's assertion was revoked completes
 *      normally — its own dispatch mints its OWN fresh assertion, and
 *      revoking turn 1's assertion never touches it.
 *
 * Run (after tsc):
 *   node --test dist/engine/orchestrator/Orchestrator.mfa-generator-invalidation.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { RedisClientType } from 'redis';

import { Orchestrator, MfaAssertionRevokedError } from './Orchestrator.js';
import { FederationManager } from '../federation/FederationManager.js';
import { PersonaManager } from '../persona/PersonaManager.js';
import { AuditTrail } from '../audit/AuditTrail.js';
import { TieredAutonomy } from '../autonomy/TieredAutonomy.js';
import { revokeMfaAssertion } from '../../iam/services/mfa.js';
import { setRedisClient } from '../../iam/services/session.js';
import { createInProcessRedisShim } from '../../iam/inProcessRedisShim.js';
import type { MCPAdapter } from '../federation/adapters/base.js';
import type { ConnectionStatus, LLMFunction, Tool, ToolResult } from '../types/index.js';

const ASSERTION_KEY_PREFIX = 'ent:mfa-assertion-epoch:';

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

/**
 * RCA #2 (chariot-verify-wave2, corrects the wave1 "RCA"): passing a
 * pre-`.index()`ed ToolPreFilter in deps (the wave1 fix) does NOTHING —
 * Orchestrator.execute() unconditionally OVERWRITES the preFilter's index
 * every run from `this.deps.federation.listOrchestratedTools()`
 * (Orchestrator.ts: "this.preFilter.index(orchestratedTools);"), so
 * whatever was pre-seeded in deps.toolPreFilter is immediately discarded.
 * The REAL root causes, found by driving the compiled FederationManager
 * directly (`node` against dist/):
 *   (a) FederationManager namespaces every listed tool's `name` as
 *       `${server}:${originalName}` (confirmed: `listOrchestratedTools()`
 *       on a tool registered as `transfer_funds` under adapter
 *       `mfa-server` returns `name: "mfa-server:transfer_funds"`). Every
 *       mocked orchestratorLLM's `toolCalls[].name` below used the BARE
 *       name, so `tools.find(t => t.name === toolCall.name)` never
 *       matched — same "Tool not available" symptom, different cause than
 *       the wave1 guess.
 *   (b) FederationManager.callTool() itself refuses to dispatch a tool
 *       whose `annotations.readOnlyHint` is not exactly `true` — it
 *       returns `{isError:true, outcome:'escalated', reason:
 *       'not_verifiably_read_only'}` and never reaches the adapter's own
 *       callTool(). `makeMfaTool()` set `readOnlyHint: false` (meant to
 *       look "risk-appropriate" for an MFA-gated tool) which tripped
 *       this — a DIFFERENT gate than TieredAutonomy's own §19::13
 *       auto->escalate forcing rule. Fixed to `readOnlyHint: true`; MFA
 *       gating is orthogonal to federation's own read-only dispatch gate.
 * Both confirmed against real compiled code, not guessed — see the chat
 * report for the exact debug commands run.
 */
function makeMfaTool(server: string, name: string): Tool {
  return {
    name,
    description: `${name} requires MFA`,
    parameters: { type: 'object', properties: {} },
    server,
    tier: 'orchestrated',
    annotations: { readOnlyHint: true, requiresMfa: true },
  };
}

/** Wraps an InProcessRedisShim so `set()` calls on the MFA-assertion-epoch
 * namespace are observable from the test without reaching into
 * Orchestrator's private `mfaBinding` state. */
function interceptingShim(onAssertionWrite: (assertionId: string) => void) {
  const real = createInProcessRedisShim();
  const originalSet = real.set.bind(real);
  real.set = async (key: string, val: string, opts?: Parameters<typeof originalSet>[2]) => {
    if (key.startsWith(ASSERTION_KEY_PREFIX)) {
      onAssertionWrite(key.slice(ASSERTION_KEY_PREFIX.length));
    }
    return originalSet(key, val, opts);
  };
  return real;
}

test('§8.2::3: dispatching an MFA-required tool mints a real, observable MFA assertion (BIND)', async (t) => {
  const shim = createInProcessRedisShim();
  setRedisClient(shim as unknown as RedisClientType);
  t.after(() => setRedisClient(undefined as unknown as RedisClientType));

  const serverName = 'mfa-server';
  const tool = makeMfaTool(serverName, 'transfer_funds');
  const adapter = new RealAdapter(serverName, [tool]);

  let capturedAssertionId: string | null = null;
  const observingShim = interceptingShim((id) => { capturedAssertionId = id; });
  setRedisClient(observingShim as unknown as RedisClientType);

  const federation = new FederationManager({ servers: [{ name: serverName, transport: 'stdio', command: 'true' }] });
  await federation.connect(serverName, { name: serverName, transport: 'stdio', command: 'true' }, adapter);

  const persona = new PersonaManager();
  persona.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });
  const audit = new AuditTrail({ store: 'memory', integrity: 'none' });
  const autonomy = new TieredAutonomy({ auto: ['mfa-server:transfer_funds'], escalate: [], approve: [] });

  let calls = 0;
  const orchestratorLLM: LLMFunction = async () => {
    calls++;
    if (calls === 1) {
      return { content: null, toolCalls: [{ id: '1', name: 'mfa-server:transfer_funds', arguments: {} }], finishReason: 'tool_calls' };
    }
    return { content: null, toolCalls: [], finishReason: 'stop' };
  };
  const generatorLLM: LLMFunction = async () => ({ content: 'done', toolCalls: [], finishReason: 'stop' });

  const orchestrator = new Orchestrator({ orchestratorLLM, generatorLLM, federation, autonomy, persona, audit, maxIterations: 6 });

  const result = await orchestrator.run('transfer money', 'user-1', undefined, 'session-1');

  assert.equal(adapter.callToolCalls.length, 1, 'the MFA-required tool must have actually dispatched');
  assert.ok(capturedAssertionId, 'mintMfaAssertion() must have written a real ent:mfa-assertion-epoch: key on dispatch');
  // A dispatched-tool turn's narrative gets a "\n\nSources: [...]" suffix
  // appended (Orchestrator.ts:1227) — startsWith, not exact equality.
  assert.ok(result.response.startsWith('done'), `turn completes normally when the assertion is never revoked; got: ${result.response}`);

  autonomy.destroy();
});

test('§8.2::3: revoking the bound MFA assertion mid-turn invalidates ONLY that turn\'s generator (INVALIDATION + ISOLATION)', async (t) => {
  const serverName = 'mfa-server-2';
  const tool = makeMfaTool(serverName, 'delete_account');
  const adapterA = new RealAdapter(serverName, [tool]);

  let capturedAssertionId: string | null = null;
  const shim = interceptingShim((id) => { capturedAssertionId = id; });
  setRedisClient(shim as unknown as RedisClientType);
  t.after(() => setRedisClient(undefined as unknown as RedisClientType));

  const federationA = new FederationManager({ servers: [{ name: serverName, transport: 'stdio', command: 'true' }] });
  await federationA.connect(serverName, { name: serverName, transport: 'stdio', command: 'true' }, adapterA);
  const personaA = new PersonaManager();
  personaA.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });
  const auditA = new AuditTrail({ store: 'memory', integrity: 'none' });
  const autonomyA = new TieredAutonomy({ auto: ['mfa-server-2:delete_account'], escalate: [], approve: [] });

  let planCallsA = 0;
  let generatorCallsA = 0;
  const orchestratorLLMA: LLMFunction = async () => {
    planCallsA++;
    if (planCallsA === 1) {
      return { content: null, toolCalls: [{ id: '1', name: 'mfa-server-2:delete_account', arguments: {} }], finishReason: 'tool_calls' };
    }
    return { content: null, toolCalls: [], finishReason: 'stop' };
  };
  const generatorLLMA: LLMFunction = async () => {
    generatorCallsA++;
    return { content: 'should never reach here', toolCalls: [], finishReason: 'stop' };
  };

  const orchestratorA = new Orchestrator({
    orchestratorLLM: orchestratorLLMA,
    generatorLLM: generatorLLMA,
    federation: federationA,
    autonomy: autonomyA,
    persona: personaA,
    audit: auditA,
    maxIterations: 6,
  });

  // Drive turn A far enough to bind (dispatch the MFA tool), then revoke
  // the captured assertion, THEN let the generator (synthesis) call happen.
  let threw: unknown = null;
  try {
    for await (const event of orchestratorA.stream('delete my account', 'user-1', undefined, 'session-1')) {
      if (event && typeof event === 'object' && 'type' in event && (event as { type: string }).type === 'action') {
        // Tool just dispatched — the assertion must already be captured by now.
        assert.ok(capturedAssertionId, 'assertion must be minted by the time the action event fires');
        await revokeMfaAssertion(capturedAssertionId as string);
      }
    }
  } catch (err) {
    threw = err;
  }

  assert.ok(threw instanceof MfaAssertionRevokedError, `expected MfaAssertionRevokedError, got ${String(threw)}`);
  assert.equal(adapterA.callToolCalls.length, 1, 'the tool dispatch itself must have happened before invalidation (it is a synthesis-time check)');
  assert.equal(generatorCallsA, 0, 'the synthesis generator must NEVER have been called after revocation');

  autonomyA.destroy();

  // ISOLATION — a second, independent turn (different server/adapter,
  // fresh Orchestrator, fresh assertion) started AFTER turn A's revocation
  // must complete normally: its own bind is unaffected by turn A's revoke.
  const serverNameB = 'mfa-server-3';
  const toolB = makeMfaTool(serverNameB, 'export_data');
  const adapterB = new RealAdapter(serverNameB, [toolB]);
  const federationB = new FederationManager({ servers: [{ name: serverNameB, transport: 'stdio', command: 'true' }] });
  await federationB.connect(serverNameB, { name: serverNameB, transport: 'stdio', command: 'true' }, adapterB);
  const personaB = new PersonaManager();
  personaB.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });
  const auditB = new AuditTrail({ store: 'memory', integrity: 'none' });
  const autonomyB = new TieredAutonomy({ auto: ['mfa-server-3:export_data'], escalate: [], approve: [] });

  let planCallsB = 0;
  const orchestratorLLMB: LLMFunction = async () => {
    planCallsB++;
    if (planCallsB === 1) {
      return { content: null, toolCalls: [{ id: '1', name: 'mfa-server-3:export_data', arguments: {} }], finishReason: 'tool_calls' };
    }
    return { content: null, toolCalls: [], finishReason: 'stop' };
  };
  const generatorLLMB: LLMFunction = async () => ({ content: 'turn B completed', toolCalls: [], finishReason: 'stop' });

  const orchestratorB = new Orchestrator({
    orchestratorLLM: orchestratorLLMB,
    generatorLLM: generatorLLMB,
    federation: federationB,
    autonomy: autonomyB,
    persona: personaB,
    audit: auditB,
    maxIterations: 6,
  });

  const resultB = await orchestratorB.run('export my data', 'user-2', undefined, 'session-2');

  assert.equal(adapterB.callToolCalls.length, 1, 'turn B\'s own MFA-required tool must dispatch normally');
  assert.ok(resultB.response.startsWith('turn B completed'), `turn B must complete normally — unaffected by turn A's revoked assertion; got: ${resultB.response}`);

  autonomyB.destroy();
});

test('§8.2::3: a non-MFA turn is entirely unaffected (no binding, no assertion minted)', async () => {
  const shim = createInProcessRedisShim();
  setRedisClient(shim as unknown as RedisClientType);

  const serverName = 'plain-server';
  const plainTool: Tool = {
    name: 'list_files',
    description: 'lists files',
    parameters: { type: 'object', properties: {} },
    server: serverName,
    tier: 'orchestrated',
    annotations: { readOnlyHint: true },
  };
  const adapter = new RealAdapter(serverName, [plainTool]);
  const federation = new FederationManager({ servers: [{ name: serverName, transport: 'stdio', command: 'true' }] });
  await federation.connect(serverName, { name: serverName, transport: 'stdio', command: 'true' }, adapter);
  const persona = new PersonaManager();
  persona.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });
  const audit = new AuditTrail({ store: 'memory', integrity: 'none' });
  const autonomy = new TieredAutonomy({ auto: ['plain-server:list_files'], escalate: [], approve: [] });

  let calls = 0;
  const orchestratorLLM: LLMFunction = async () => {
    calls++;
    if (calls === 1) {
      return { content: null, toolCalls: [{ id: '1', name: 'plain-server:list_files', arguments: {} }], finishReason: 'tool_calls' };
    }
    return { content: null, toolCalls: [], finishReason: 'stop' };
  };
  const generatorLLM: LLMFunction = async () => ({ content: 'no mfa needed', toolCalls: [], finishReason: 'stop' });

  const orchestrator = new Orchestrator({ orchestratorLLM, generatorLLM, federation, autonomy, persona, audit, maxIterations: 6 });
  const result = await orchestrator.run('list my files');

  assert.ok(result.response.startsWith('no mfa needed'), `got: ${result.response}`);
  assert.equal(adapter.callToolCalls.length, 1);

  autonomy.destroy();
});
