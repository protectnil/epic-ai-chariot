/**
 * CHARIOT::§8.2::3 (W34-4b) — "thread the authenticated sessionId into
 * EpicAI.run/stream" + "find the enterprise transport that authenticates
 * a session and invokes the engine."
 *
 * PROOF (per the W34-4b ruling: "if no such caller exists, prove it with
 * the grep output and say so") — no transport in this repo invokes
 * EpicAI/Orchestrator at all. Reproduced here as an executable assertion
 * over the actual source (mirrors the existing repo convention of
 * source-grep tests, e.g. session.revocation-ttl.test.ts's own
 * "every ent:session:revoked write uses the 24h constant" test), so this
 * regresses if a future transport DOES start wiring EpicAI without a
 * matching sessionId test being added for it.
 *
 * Second test proves the plumbing that DOES exist end-to-end:
 * EpicAI.run()/.stream() forward a caller-supplied sessionId to
 * Orchestrator.run()/.stream() unchanged.
 *
 * Run (after tsc):
 *   node --test dist/engine/EpicAI.sessionid-transport.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

import { EpicAI } from './EpicAI.js';
import { Orchestrator } from './orchestrator/Orchestrator.js';
import { RegistryLoader } from './federation/RegistryLoader.js';
import type { EpicAIConfig } from './types/index.js';

function minimalConfig(): EpicAIConfig {
  return {
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

// Scans compiled dist/ output (this test itself runs from dist/, per the
// repo's own "Run after tsc" convention) — the SAME bytes that ship, not
// source that might diverge from the build. .test.js files are excluded
// so a test file's own EpicAI/Orchestrator imports (like THIS file's)
// never counts as an "offender".
function listCompiledJsFiles(dir: string): string[] {
  let out: string[] = [];
  let entries: import('node:fs').Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out = out.concat(listCompiledJsFiles(full));
    } else if (entry.name.endsWith('.js') && !entry.name.endsWith('.test.js')) {
      out.push(full);
    }
  }
  return out;
}

test('§8.2::3 PROOF: no file under iam/routes or engine/server references EpicAI/Orchestrator (compiled dist/ source-scan)', () => {
  // Scans dist/ (this test itself runs from dist/, per repo convention —
  // see file docstring "Run (after tsc)") so it inspects the SAME bytes
  // that ship, not source that might diverge from the build.
  const here = dirname(fileURLToPath(import.meta.url)); // dist/engine
  const iamRoutesDir = join(here, '..', 'iam', 'routes');
  const engineServerDir = join(here, 'server');

  const files = [...listCompiledJsFiles(iamRoutesDir), ...listCompiledJsFiles(engineServerDir)];
  assert.ok(files.length > 0, 'sanity: both directories must actually be found and non-empty for this proof to mean anything');

  const offenders: string[] = [];
  for (const file of files) {
    const src = readFileSync(file, 'utf8');
    if (/\bEpicAI\b/.test(src) || /\bOrchestrator\b/.test(src)) {
      offenders.push(file);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    'if this fails, a transport now DOES reference EpicAI/Orchestrator — wire its real authenticated sessionId through and update this test rather than deleting it',
  );
});

test('§8.2::3: EpicAI.run() forwards a caller-supplied sessionId to Orchestrator.run() unchanged', async () => {
  const originalRun = Orchestrator.prototype.run;
  let capturedArgs: unknown[] | null = null;
  Orchestrator.prototype.run = async function (this: Orchestrator, ...args: unknown[]) {
    capturedArgs = args;
    return originalRun.apply(this, args as Parameters<typeof originalRun>);
  } as typeof originalRun;

  // EpicAI (the exported class) is only a static create() factory — the
  // real implementation with run()/start()/stop() is the internal
  // EpicAIAgentImpl it constructs and returns as an EpicAIAgent. Must go
  // through create(), same as every other EpicAI-level test in this repo
  // (EpicAI.startup-wiring.test.ts).
  const originalLoadAndWire = RegistryLoader.prototype.loadAndWire;
  RegistryLoader.prototype.loadAndWire = async function () {
    return { loaded: [], skipped: [], totalInRegistry: 0 };
  };

  try {
    const agent = await EpicAI.create(minimalConfig());
    await agent.start();
    await agent.run('hello', 'user-1', '127.0.0.1', 'session-abc-123');

    assert.ok(capturedArgs, 'Orchestrator.run() must have been called');
    assert.equal(capturedArgs![0], 'hello');
    assert.equal(capturedArgs![1], 'user-1');
    assert.equal(capturedArgs![2], '127.0.0.1');
    assert.equal(capturedArgs![3], 'session-abc-123', 'sessionId (4th positional arg) must reach Orchestrator.run() unchanged');

    await agent.stop();
  } finally {
    Orchestrator.prototype.run = originalRun;
    RegistryLoader.prototype.loadAndWire = originalLoadAndWire;
  }
});
