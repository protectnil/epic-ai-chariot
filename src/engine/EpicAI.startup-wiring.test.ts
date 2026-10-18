/**
 * CHARIOT::§7.5::1 / §7.7::2 — EpicAI.start() production-wiring tests.
 *
 * CHARIOT-SPEC.md:625-627 (§7.5, quoted verbatim, on-disk):
 *   "`src/engine/federation/RegistryLoader.ts` is the bridge between the
 *   catalog (declarative) and the federation manager (runtime). It
 *   instantiates each catalog-listed adapter, wires it into the pool,
 *   registers its tools with `ToolPreFilter`, and exposes a `reload()`
 *   for runtime adapter unload (1.4.0+ behavior)."
 *
 * Before this fix, RegistryLoader.loadAndWire()/reload() existed but
 * nothing in the runtime startup path (EpicAI.start()) ever called them —
 * only a stray doc-comment mentioned RegistryLoader outside its own
 * definition and test file. This file proves EpicAI.start() actually
 * calls RegistryLoader.loadAndWire() and constructs+starts a
 * KillListWatcher, using the smallest real seam available: EpicAI
 * constructs RegistryLoader/KillListWatcher internally (no constructor
 * injection point exists on EpicAIConfig for either), so this spies on
 * the REAL classes' prototype methods — genuine code, not a fake target —
 * short-circuiting `RegistryLoader.prototype.loadAndWire` before it does
 * any real bundle-catalog I/O or adapter connect attempts (those are
 * exercised in isolation by RegistryLoader.wire-and-reload.test.ts and
 * the AdapterCatalog test suite; re-exercising them here through a live
 * `start()` call would make this test slow and dependent on which
 * credential env vars happen to be set).
 *
 * CHARIOT-SPEC.md:639-643 (§7.7, quoted verbatim, on-disk):
 *   "`src/engine/federation/KillListWatcher.ts` exists in the codebase
 *   and runs as part of the federation startup sequence. ... The current
 *   state: the watcher polls and finds the feed empty, emits a single
 *   INFO log per startup, and has no runtime effect."
 * The second test here is CHARIOT::§7.7::2's failure-class fix: parsing
 * CHARIOT_KILL_LIST_INTERVAL_MS/CHARIOT_KILL_LIST_MAX_QUIESCENCE_MS must
 * not throw when there is no feed URL to apply them to (a value that "has
 * no runtime effect" cannot be allowed to block startup by being
 * malformed) — it MUST still throw once a URL makes the value meaningful.
 *
 * Run (after `tsc`):
 *   node --test dist/engine/EpicAI.startup-wiring.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { EpicAI } from './EpicAI.js';
import { RegistryLoader } from './federation/RegistryLoader.js';
import { KillListWatcher } from './federation/KillListWatcher.js';
import { ToolPreFilter } from './federation/ToolPreFilter.js';
import type { EpicAIConfig, EpicAIAgent } from './types/index.js';
import type { Tool } from './types/index.js';

function minimalConfig(): EpicAIConfig {
  return {
    // `llm` supplied directly — createOrchestratorLLM() returns it before
    // ever touching the provider switch (OrchestratorProvider.ts:59:
    // "if (config.llm) return config.llm;"), so no real Ollama/vLLM
    // process or network call is needed to construct/start the agent.
    orchestrator: {
      provider: 'ollama',
      model: 'test-model',
      llm: async () => ({ content: '', toolCalls: [], finishReason: 'stop' }),
    },
    federation: { servers: [] },
    autonomy: { tiers: { auto: [], escalate: [], approve: [] } },
    persona: { name: 'test-persona', tone: 'neutral', domain: 'test', systemPrompt: 'test prompt' },
    audit: { store: 'memory', integrity: 'none' },
  };
}

test('CHARIOT::§7.5::1 — EpicAI.start() calls RegistryLoader.loadAndWire() and constructs+starts a KillListWatcher', async () => {
  let loadAndWireCalls = 0;
  const originalLoadAndWire = RegistryLoader.prototype.loadAndWire;
  // Short-circuit — do not call through. This still proves the REAL
  // production code path invokes the REAL RegistryLoader class's real
  // method (prototype identity is shared between this test file and
  // EpicAI.ts's `new RegistryLoader(...)` — same module instance), without
  // this test also depending on real bundle-catalog I/O or credential env
  // vars (covered elsewhere — see file docstring).
  RegistryLoader.prototype.loadAndWire = async function (this: RegistryLoader) {
    loadAndWireCalls += 1;
    // Prove it was constructed with a real federation target wired in
    // (not the pre-1.4.0-compatible `{}` no-op configuration) — reflection
    // access to the private `options` field, the same technique this
    // codebase's own test-double comments describe using for AdapterCatalog.
    const options = (this as unknown as { options: { federation?: unknown } }).options;
    assert.ok(options?.federation, 'RegistryLoader must be constructed with a federation target');
    return { loaded: [], skipped: [], totalInRegistry: 0 };
  };

  let watcherStartCalls = 0;
  const originalWatcherStart = KillListWatcher.prototype.start;
  KillListWatcher.prototype.start = function (this: KillListWatcher) {
    watcherStartCalls += 1;
    // No CHARIOT_KILL_LIST_URL is set in this test's environment (asserted
    // below), so the real start() takes its documented §7.7::2 no-op path —
    // one INFO log, no timer, no network call — safe to call through.
    return originalWatcherStart.call(this);
  };

  const savedUrl = process.env.CHARIOT_KILL_LIST_URL;
  delete process.env.CHARIOT_KILL_LIST_URL;

  let agent: EpicAIAgent | undefined;
  try {
    agent = await EpicAI.create(minimalConfig());
    await agent.start();

    assert.equal(loadAndWireCalls, 1, 'EpicAI.start() must call RegistryLoader.loadAndWire() exactly once');
    assert.equal(watcherStartCalls, 1, 'EpicAI.start() must construct a KillListWatcher and call start() on it');
  } finally {
    RegistryLoader.prototype.loadAndWire = originalLoadAndWire;
    KillListWatcher.prototype.start = originalWatcherStart;
    if (savedUrl === undefined) delete process.env.CHARIOT_KILL_LIST_URL;
    else process.env.CHARIOT_KILL_LIST_URL = savedUrl;
    if (agent) await agent.stop();
  }
});

test('CHARIOT::§7.5::1 — EpicAIAgent.reloadAdapters() delegates to RegistryLoader.reload() and throws before start()', async () => {
  const originalLoadAndWire = RegistryLoader.prototype.loadAndWire;
  RegistryLoader.prototype.loadAndWire = async function () {
    return { loaded: [], skipped: [], totalInRegistry: 0 };
  };
  let reloadCalls = 0;
  const originalReload = RegistryLoader.prototype.reload;
  RegistryLoader.prototype.reload = async function () {
    reloadCalls += 1;
    return { loaded: [], skipped: [], totalInRegistry: 0 };
  };

  const savedUrl = process.env.CHARIOT_KILL_LIST_URL;
  delete process.env.CHARIOT_KILL_LIST_URL;

  const agent = await EpicAI.create(minimalConfig());
  try {
    await assert.rejects(
      () => agent.reloadAdapters(),
      /Agent not started/,
      'reloadAdapters() before start() must throw, not silently no-op',
    );

    await agent.start();
    await agent.reloadAdapters();
    assert.equal(reloadCalls, 1, 'reloadAdapters() must delegate to RegistryLoader.reload() exactly once');
  } finally {
    RegistryLoader.prototype.loadAndWire = originalLoadAndWire;
    RegistryLoader.prototype.reload = originalReload;
    if (savedUrl === undefined) delete process.env.CHARIOT_KILL_LIST_URL;
    else process.env.CHARIOT_KILL_LIST_URL = savedUrl;
    await agent.stop();
  }
});

// ── CHARIOT::§7.7::2 — kill-list tuning env vars must not gate startup ─────
// when there is no feed URL for them to apply to, but must still validate
// once a URL makes them meaningful.

test('CHARIOT::§7.7::2 — a malformed CHARIOT_KILL_LIST_INTERVAL_MS does NOT throw when CHARIOT_KILL_LIST_URL is unset', async () => {
  const originalLoadAndWire = RegistryLoader.prototype.loadAndWire;
  RegistryLoader.prototype.loadAndWire = async function () {
    return { loaded: [], skipped: [], totalInRegistry: 0 };
  };

  const savedUrl = process.env.CHARIOT_KILL_LIST_URL;
  const savedInterval = process.env.CHARIOT_KILL_LIST_INTERVAL_MS;
  delete process.env.CHARIOT_KILL_LIST_URL;
  process.env.CHARIOT_KILL_LIST_INTERVAL_MS = 'not-a-number';

  let agent: EpicAIAgent | undefined;
  try {
    agent = await EpicAI.create(minimalConfig());
    // Must not throw — §7.7::2: "has no runtime effect" when unwired.
    await agent.start();
  } finally {
    RegistryLoader.prototype.loadAndWire = originalLoadAndWire;
    if (savedUrl === undefined) delete process.env.CHARIOT_KILL_LIST_URL;
    else process.env.CHARIOT_KILL_LIST_URL = savedUrl;
    if (savedInterval === undefined) delete process.env.CHARIOT_KILL_LIST_INTERVAL_MS;
    else process.env.CHARIOT_KILL_LIST_INTERVAL_MS = savedInterval;
    if (agent) await agent.stop();
  }
});

test('CHARIOT::§7.7::2 — a malformed CHARIOT_KILL_LIST_INTERVAL_MS DOES throw when CHARIOT_KILL_LIST_URL is set', async () => {
  const originalLoadAndWire = RegistryLoader.prototype.loadAndWire;
  RegistryLoader.prototype.loadAndWire = async function () {
    return { loaded: [], skipped: [], totalInRegistry: 0 };
  };

  const savedUrl = process.env.CHARIOT_KILL_LIST_URL;
  const savedInterval = process.env.CHARIOT_KILL_LIST_INTERVAL_MS;
  process.env.CHARIOT_KILL_LIST_URL = 'https://example.invalid/kill-list.json';
  process.env.CHARIOT_KILL_LIST_INTERVAL_MS = 'not-a-number';

  const agent = await EpicAI.create(minimalConfig());
  try {
    await assert.rejects(
      () => agent.start(),
      /Invalid CHARIOT_KILL_LIST_INTERVAL_MS/,
      'a configured feed URL must make the malformed tuning value fail closed',
    );
  } finally {
    RegistryLoader.prototype.loadAndWire = originalLoadAndWire;
    if (savedUrl === undefined) delete process.env.CHARIOT_KILL_LIST_URL;
    else process.env.CHARIOT_KILL_LIST_URL = savedUrl;
    if (savedInterval === undefined) delete process.env.CHARIOT_KILL_LIST_INTERVAL_MS;
    else process.env.CHARIOT_KILL_LIST_INTERVAL_MS = savedInterval;
    // start() threw before `this.started = true` — do not call stop().
  }
});

// ── CHARIOT::§7.5::1 — F5 fix: ONE shared ToolPreFilter instance ───────────
//
// Gate round 2 rejected relying on Orchestrator's private re-index: the
// spec text is "registers its tools with `ToolPreFilter`" — RegistryLoader
// must actually call `.index()` on SOME ToolPreFilter, and that instance
// must be the one Orchestrator queries, not a disconnected one. EpicAI now
// constructs exactly one `ToolPreFilter` and threads it through both.
//
// Seam: EpicAI constructs RegistryLoader/Orchestrator internally with no
// injection point, so this uses RegistryLoader's OWN documented
// seam-injection technique (see RegistryLoader.wire-and-reload.test.ts's
// file docstring: overriding the public `load()` method, which is public
// and not final) via a prototype patch — `load()` returns a fixed, empty
// RegistryLoadResult so no real bundle-catalog adapters are connected,
// while the REAL (untouched) `loadAndWire()` body still runs, including
// its real call to `toolPreFilter.index(federation.listTools())`. A real
// (non-fake) `ToolPreFilter.prototype.index` spy confirms that call fires;
// reflection into the started agent's private fields confirms identity.

test('CHARIOT::§7.5::1 — EpicAI wires ONE ToolPreFilter instance that RegistryLoader.loadAndWire() indexes and Orchestrator queries', async () => {
  const originalLoad = RegistryLoader.prototype.load;
  RegistryLoader.prototype.load = function (this: RegistryLoader) {
    return { loaded: [], skipped: [], totalInRegistry: 0 };
  };

  const indexCalls: Tool[][] = [];
  const originalIndex = ToolPreFilter.prototype.index;
  ToolPreFilter.prototype.index = function (this: ToolPreFilter, tools: Tool[]) {
    indexCalls.push(tools);
    return originalIndex.call(this, tools);
  };

  const savedUrl = process.env.CHARIOT_KILL_LIST_URL;
  delete process.env.CHARIOT_KILL_LIST_URL;

  let agent: EpicAIAgent | undefined;
  try {
    agent = await EpicAI.create(minimalConfig());
    await agent.start();

    assert.ok(
      indexCalls.length >= 1,
      'RegistryLoader.loadAndWire() must call ToolPreFilter.index() (CHARIOT-SPEC.md:627 "registers its tools with ToolPreFilter")',
    );

    const internals = agent as unknown as {
      toolPreFilter: ToolPreFilter;
      orchestrator: { preFilter: ToolPreFilter } | null;
    };
    assert.ok(internals.orchestrator, 'orchestrator must be constructed by the end of start()');
    assert.equal(
      internals.orchestrator!.preFilter,
      internals.toolPreFilter,
      'Orchestrator must query the SAME ToolPreFilter instance RegistryLoader just indexed (identity, ===)',
    );
  } finally {
    RegistryLoader.prototype.load = originalLoad;
    ToolPreFilter.prototype.index = originalIndex;
    if (savedUrl === undefined) delete process.env.CHARIOT_KILL_LIST_URL;
    else process.env.CHARIOT_KILL_LIST_URL = savedUrl;
    if (agent) await agent.stop();
  }
});

test('CHARIOT::§7.5::1 — Orchestrator falls back to a private ToolPreFilter when no shared instance is supplied (pre-existing-caller compatibility)', async () => {
  // Import lazily so this file's other tests (which patch prototypes) are
  // unaffected by module-init order.
  const { Orchestrator } = await import('./orchestrator/Orchestrator.js');
  const orch = new Orchestrator({
    orchestratorLLM: async () => ({ content: '', toolCalls: [], finishReason: 'stop' }),
    generatorLLM: async () => ({ content: '', toolCalls: [], finishReason: 'stop' }),
    federation: {
      listOrchestratedTools: () => [],
      listTools: () => [],
    } as unknown as import('./federation/FederationManager.js').FederationManager,
    autonomy: {} as unknown as import('./autonomy/TieredAutonomy.js').TieredAutonomy,
    persona: {} as unknown as import('./persona/PersonaManager.js').PersonaManager,
    audit: {} as unknown as import('./audit/AuditTrail.js').AuditTrail,
  });
  const internals = orch as unknown as { preFilter: ToolPreFilter };
  assert.ok(internals.preFilter instanceof ToolPreFilter, 'a private ToolPreFilter must still be constructed when toolPreFilter is omitted');
});
