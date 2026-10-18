/**
 * CHARIOT::§16.3::1 / gate finding 114(i) (thread 01a06d96-0132-71b2-92f4-a87dd7611393)
 * — "constructing an EpicAI instance registers its TokenTracker with the
 * process-wide registry so ANY ChariotMetrics instance in the same
 * process picks it up automatically."
 *
 * Full integration: construct a real EpicAI agent, drive one real run()
 * through it (LLM usage reported, no tool dispatch needed — the
 * planning+synthesis calls alone are enough to populate TokenTracker, see
 * Orchestrator.ts's recordGeneratorUsage()), then construct a SEPARATE,
 * unrelated ChariotMetrics instance and prove its getSummary().tokenUsageByAdapter
 * reflects the EpicAI instance's real numbers with NO explicit
 * setTokenUsageSource() call — only the constructor-time registration.
 *
 * Run (after tsc):
 *   node --test dist/engine/EpicAI.token-usage-registration.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { EpicAI } from './EpicAI.js';
import { RegistryLoader } from './federation/RegistryLoader.js';
import { ChariotMetrics } from '../observability/metrics.js';
import { clearRegisteredTokenUsageSource } from '../observability/tokenUsageRegistry.js';
import type { EpicAIConfig, EpicAIAgent } from './types/index.js';

function minimalConfig(llm: EpicAIConfig['orchestrator']['llm']): EpicAIConfig {
  return {
    orchestrator: { provider: 'ollama', model: 'test-model', llm },
    federation: { servers: [] },
    autonomy: { tiers: { auto: [], escalate: [], approve: [] } },
    persona: { name: 'test-persona', tone: 'neutral', domain: 'test', systemPrompt: 'test prompt' },
    audit: { store: 'memory', integrity: 'none' },
  };
}

async function withMockedRegistryLoader<T>(fn: () => Promise<T>): Promise<T> {
  const original = RegistryLoader.prototype.loadAndWire;
  RegistryLoader.prototype.loadAndWire = async function () {
    return { loaded: [], skipped: [], totalInRegistry: 0 };
  };
  try {
    return await fn();
  } finally {
    RegistryLoader.prototype.loadAndWire = original;
  }
}

test('gate finding 114(i): a ChariotMetrics instance with no explicit source, in a process with NO EpicAI instance, reports the absence marker', () => {
  clearRegisteredTokenUsageSource();
  const metrics = new ChariotMetrics();
  assert.deepEqual(metrics.getSummary().tokenUsageByAdapter, { available: false, reason: 'no orchestrator in this process' });
});

test('gate finding 114(i): constructing + running an EpicAI instance makes a SEPARATE, unrelated ChariotMetrics instance carry real byAdapter numbers, with zero explicit wiring', async () => {
  clearRegisteredTokenUsageSource();

  let agent: EpicAIAgent | undefined;
  try {
    await withMockedRegistryLoader(async () => {
      // No tool dispatch needed: the planning + synthesis LLM calls alone
      // populate TokenTracker (Orchestrator.ts recordGeneratorUsage(),
      // attributed to the 'orchestrator' sentinel adapter when no tool
      // has been dispatched this turn — see the W34-4b build report).
      const llm = async () => ({
        content: 'the answer',
        toolCalls: [],
        finishReason: 'stop' as const,
        usage: { inputTokens: 111, outputTokens: 22, totalTokens: 133 },
      });
      agent = await EpicAI.create(minimalConfig(llm));
      await agent.start();
      await agent.run('a question');
    });

    // The KEY assertion: a BRAND NEW, unrelated ChariotMetrics instance —
    // never told about `agent`, never had setTokenUsageSource() called —
    // still reports real numbers, purely via the constructor-time
    // registration in tokenUsageRegistry.ts.
    const metrics = new ChariotMetrics();
    const summary = metrics.getSummary().tokenUsageByAdapter;
    assert.ok(!('available' in summary), 'must be real data, not the absence marker, once an EpicAI instance has run');
    const byAdapter = summary as Record<string, { tokens: number; costUsd: number }>;
    assert.ok(byAdapter['orchestrator'], 'the orchestrator-sentinel-attributed entry must be present');
    assert.ok(byAdapter['orchestrator'].tokens > 0, `expected positive tokens, got ${JSON.stringify(byAdapter)}`);
  } finally {
    if (agent) await agent.stop();
    clearRegisteredTokenUsageSource();
  }
});

test('gate finding 114(i): two EpicAI instances in the same process -> the MOST RECENTLY constructed one wins (documented)', async () => {
  clearRegisteredTokenUsageSource();

  let agentA: EpicAIAgent | undefined;
  let agentB: EpicAIAgent | undefined;
  try {
    await withMockedRegistryLoader(async () => {
      const llmA = async () => ({ content: 'a', toolCalls: [], finishReason: 'stop' as const, usage: { inputTokens: 10, outputTokens: 1, totalTokens: 11 } });
      agentA = await EpicAI.create(minimalConfig(llmA));
      await agentA.start();
      await agentA.run('question A'); // registered by A's constructor already; this just gives A real numbers

      const llmB = async () => ({ content: 'b', toolCalls: [], finishReason: 'stop' as const, usage: { inputTokens: 999, outputTokens: 888, totalTokens: 1887 } });
      agentB = await EpicAI.create(minimalConfig(llmB));
      await agentB.start();
      await agentB.run('question B'); // B's CONSTRUCTOR already replaced A's registration; this just gives B real numbers
    });

    const metrics = new ChariotMetrics();
    const summary = metrics.getSummary().tokenUsageByAdapter as Record<string, { tokens: number; costUsd: number }>;
    // A's numbers are small (10+1), B's are large (999+888) — if the
    // registry reported A (the FIRST-registered), tokens would be small.
    assert.ok(byAdapterTotalTokens(summary) >= 999, `expected B's larger numbers to win; got ${JSON.stringify(summary)}`);
  } finally {
    if (agentA) await agentA.stop();
    if (agentB) await agentB.stop();
    clearRegisteredTokenUsageSource();
  }
});

function byAdapterTotalTokens(byAdapter: Record<string, { tokens: number; costUsd: number }>): number {
  return Object.values(byAdapter).reduce((sum, v) => sum + v.tokens, 0);
}
