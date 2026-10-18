/**
 * Regression eval — CHARIOT::§8.4::3 / §8.4.1 (zero-daylight rulings audit,
 * item 17): "§8.4/§8.4.1 persona prompt-builder path is dead in production
 * (buildSystemPrompt called without context; ...)".
 *
 * The defect this exists to catch: `Orchestrator.execute()` called
 * `this.deps.persona.buildSystemPrompt()` with NO arguments. Because
 * `SystemPromptBuilder.build()`'s memory-header section (§8.4::3) and
 * tool-context section only execute when a `ConversationContext` is passed,
 * that code was unreachable on the real dispatch path — recent memory
 * entries never reached the "system prompt header" the clause requires,
 * even though the orchestrator itself had already retrieved them (they were
 * instead pushed as a separately-formatted, separately-wrapped ad hoc
 * system message, duplicating SystemPromptBuilder's own memory-section
 * logic under different formatting).
 *
 * This test drives a real `Orchestrator.run()` call with a userId that has
 * a pre-seeded high-importance memory, using a spy PersonaManager subclass
 * to observe the exact `ConversationContext` argument
 * `buildSystemPrompt` receives, and asserts:
 *   (a) buildSystemPrompt is called WITH a context object (not undefined)
 *       when a userId is present — the "dead path" defect,
 *   (b) that context's `retrievedMemories` contains the seeded memory,
 *   (c) the memory content actually appears in the system-role message
 *       handed to the orchestrator LLM (end-to-end, not just at the
 *       PersonaManager call boundary).
 *
 * It would FAIL against the pre-fix code: `buildSystemPrompt` would be
 * observed called with `undefined`, and (b)/(c) would never be satisfied via
 * the persona-builder path (the memory content only appeared via the old ad
 * hoc separately-wrapped message, which this test does not special-case).
 *
 * Run (after tsc):
 *   node --test dist/engine/orchestrator/Orchestrator.persona-context-wiring.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Orchestrator } from './Orchestrator.js';
import { FederationManager } from '../federation/FederationManager.js';
import { PersonaManager } from '../persona/PersonaManager.js';
import { PersistentMemory } from '../memory/PersistentMemory.js';
import { InMemoryStore } from '../memory/adapters/InMemoryStore.js';
import { AuditTrail } from '../audit/AuditTrail.js';
import { TieredAutonomy } from '../autonomy/TieredAutonomy.js';
import { ObservabilityEmitter } from '../observability/EventEmitter.js';
import type { ConversationContext, LLMFunction, LLMMessage, StreamEvent } from '../types/index.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

class SpyPersonaManager extends PersonaManager {
  calls: Array<ConversationContext | undefined> = [];
  override buildSystemPrompt(context?: ConversationContext): string {
    this.calls.push(context);
    return super.buildSystemPrompt(context);
  }
}

test('CHARIOT::§8.4::3 — production Orchestrator.execute() calls persona.buildSystemPrompt() WITH a ConversationContext carrying retrieved memory, and that memory reaches the LLM-facing system message', async () => {
  const TENANT = 'local';
  const USER = 'athlete-42';

  const memoryStore = new PersistentMemory({ store: new InMemoryStore(), cacheTTLMs: 0 });
  await memoryStore.etch(TENANT, USER, {
    type: 'preference',
    content: 'the athlete prefers Instagram deals over TikTok',
    importance: 'high',
  });

  const federation = new FederationManager({ servers: [] });

  const persona = new SpyPersonaManager();
  persona.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help athletes.' });

  const audit = new AuditTrail({ store: 'memory', integrity: 'none' });
  const autonomy = new TieredAutonomy({ auto: [], escalate: [], approve: [] });

  let capturedMessages: LLMMessage[] = [];
  const orchestratorLLM: LLMFunction = async ({ messages }: { messages: LLMMessage[] }) => {
    capturedMessages = messages;
    return { content: 'no tools needed', toolCalls: [], finishReason: 'stop' };
  };
  const generatorLLM: LLMFunction = async () => ({
    content: 'final answer',
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
    memory: memoryStore,
    tenantId: TENANT,
    maxIterations: 3,
  });

  await orchestrator.run('what deals should I take?', USER);

  assert.equal(persona.calls.length, 1, 'buildSystemPrompt must be called exactly once per run');
  const context = persona.calls[0];
  assert.notEqual(context, undefined, 'buildSystemPrompt must be called WITH a context, not the no-arg overload, when a userId is present (the "dead path" defect)');
  assert.equal(context!.userId, USER);
  assert.ok(typeof context!.runId === 'string' && context!.runId.length > 0, 'runId must be a non-empty per-run identifier');
  assert.equal(context!.retrievedMemories.length, 1);
  assert.equal(context!.retrievedMemories[0].content, 'the athlete prefers Instagram deals over TikTok');

  const systemMessage = capturedMessages.find((m) => m.role === 'system');
  assert.ok(systemMessage, 'a system message must reach the orchestrator LLM');
  assert.ok(
    systemMessage!.content.includes('the athlete prefers Instagram deals over TikTok'),
    'the memory content must reach the LLM-facing system message via the persona-built prompt header',
  );

  autonomy.destroy();
});

test('CHARIOT::§8.4::3 — no userId: buildSystemPrompt falls back to the no-context overload (no memory to surface, vocabulary/anchor unaffected)', async () => {
  const federation = new FederationManager({ servers: [] });

  const persona = new SpyPersonaManager();
  persona.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });

  const audit = new AuditTrail({ store: 'memory', integrity: 'none' });
  const autonomy = new TieredAutonomy({ auto: [], escalate: [], approve: [] });

  const orchestratorLLM: LLMFunction = async () => ({ content: 'ok', toolCalls: [], finishReason: 'stop' });
  const generatorLLM: LLMFunction = async () => ({ content: 'final', toolCalls: [], finishReason: 'stop' });

  const orchestrator = new Orchestrator({
    orchestratorLLM,
    generatorLLM,
    federation,
    autonomy,
    persona,
    audit,
    maxIterations: 3,
  });

  await orchestrator.run('anonymous question');

  assert.equal(persona.calls.length, 1);
  assert.equal(persona.calls[0], undefined, 'without a userId there is no per-user memory to surface, so the no-context overload is used');

  autonomy.destroy();
});

test('CHARIOT::§8.4::3 — runId is the StepTracer traceId when stepEmitter is wired, and a fresh UUID when it is not', async () => {
  const TENANT = 'local';
  const USER = 'athlete-runid';

  const federation = new FederationManager({ servers: [] });
  const audit = new AuditTrail({ store: 'memory', integrity: 'none' });

  const orchestratorLLM: LLMFunction = async () => ({ content: 'ok', toolCalls: [], finishReason: 'stop' });
  const generatorLLM: LLMFunction = async () => ({ content: 'final', toolCalls: [], finishReason: 'stop' });

  // Case 1: stepEmitter wired — runId must equal the StepTracer traceId
  // emitted on the same run's step-trace events (the producer at
  // Orchestrator.ts's `sessionId: stepTracer?.traceId ?? randomUUID()`
  // line, now `runId`).
  {
    const persona = new SpyPersonaManager();
    persona.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });
    const autonomy = new TieredAutonomy({ auto: [], escalate: [], approve: [] });
    const stepEmitter = new ObservabilityEmitter();
    const traceIds: string[] = [];
    stepEmitter.onEvent((event: StreamEvent) => {
      if (event.type === 'step-trace') traceIds.push(event.data.traceId);
    });

    const orchestrator = new Orchestrator({
      orchestratorLLM,
      generatorLLM,
      federation,
      autonomy,
      persona,
      audit,
      tenantId: TENANT,
      maxIterations: 3,
      stepEmitter,
    });

    await orchestrator.run('what deals should I take?', USER);

    assert.equal(persona.calls.length, 1);
    const context = persona.calls[0];
    assert.notEqual(context, undefined);
    assert.ok(traceIds.length > 0, 'at least one step-trace event must be emitted when stepEmitter is wired');
    assert.ok(traceIds.every((id) => id === traceIds[0]), 'every step-trace event in one run shares the same traceId');
    assert.equal(context!.runId, traceIds[0], 'runId must be exactly the StepTracer traceId when stepEmitter is wired, not an independently minted UUID');

    autonomy.destroy();
  }

  // Case 2: no stepEmitter — runId falls back to a fresh UUID (the
  // "closest honest stand-in", never a fabricated session id).
  {
    const persona = new SpyPersonaManager();
    persona.register({ name: 'default', tone: 'neutral', domain: 'general', systemPrompt: 'You help.' });
    const autonomy = new TieredAutonomy({ auto: [], escalate: [], approve: [] });

    const orchestrator = new Orchestrator({
      orchestratorLLM,
      generatorLLM,
      federation,
      autonomy,
      persona,
      audit,
      tenantId: TENANT,
      maxIterations: 3,
    });

    await orchestrator.run('what deals should I take?', USER);

    assert.equal(persona.calls.length, 1);
    const context = persona.calls[0];
    assert.notEqual(context, undefined);
    assert.ok(UUID_RE.test(context!.runId), 'without a stepEmitter, runId must be a fresh UUID (randomUUID fallback)');

    autonomy.destroy();
  }
});
