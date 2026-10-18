/**
 * Prove-on-revert for CHARIOT §8.2::5 — "Each loop phase (pre-filter, prompt
 * build, generator call, dispatch, result merge) SHALL emit a span via the
 * observability emitter, with configurable latency budgets."
 *
 * Defect this catches: stepTracer.emitStepStart/emitStepEnd was called ONLY
 * around tool dispatch ('tool-call'). Pre-filter, prompt build, generator call
 * and result merge emitted no span at all — they were only accumulated as
 * wall-clock numbers (retrievalMs/orchestratorMs/generatorMs) folded into the
 * run summary, so no per-phase span reached the observability emitter and no
 * latency budget existed for any phase.
 *
 * Phase→StepKind mapping deliberately reuses the members that already existed
 * and were never emitted (`retrieval`, `orchestrator-plan`, `synthesis`) rather
 * than adding synonyms; only `result-merge` is new, because no existing kind
 * denoted merging a tool result into conversation state.
 *
 * Run (after tsc): node --test dist/engine/orchestrator/Orchestrator.phase-spans.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('./Orchestrator.js', import.meta.url)), 'utf8');
// Interfaces and string-literal unions are ERASED from the emitted .js, so the
// type-level assertions below read the declaration files, which are the
// authoritative record of the compiled contract.
const declSrc = readFileSync(
  fileURLToPath(new URL('./Orchestrator.d.ts', import.meta.url)),
  'utf8',
);
const typesSrc = readFileSync(
  fileURLToPath(new URL('../types/index.d.ts', import.meta.url)),
  'utf8',
);

test('§8.2::5: all five loop phases are traced', () => {
  for (const [phase, kind] of [
    ['pre-filter', 'retrieval'],
    ['prompt build', 'orchestrator-plan'],
    ['generator call', 'synthesis'],
    ['dispatch', 'tool-call'],
    ['result merge', 'result-merge'],
  ] as const) {
    assert.ok(
      src.includes(`'${kind}'`),
      `phase "${phase}" must be traced with StepKind '${kind}'`,
    );
  }
});

test('§8.2::5: the four previously-untraced phases go through tracePhase', () => {
  for (const kind of ['retrieval', 'orchestrator-plan', 'synthesis', 'result-merge']) {
    assert.ok(
      new RegExp(`tracePhase\\(\\s*'${kind}'`).test(src),
      `phase ${kind} must emit a span via tracePhase`,
    );
  }
});

test('§8.2::5: tracePhase emits BOTH a start and an end span', () => {
  const fn = src.slice(src.indexOf('const tracePhase'));
  const body = fn.slice(0, fn.indexOf('\n    };'));
  assert.ok(/emitStepStart\(/.test(body), 'tracePhase must emit a start span');
  const ends = body.match(/emitStepEnd\(/g) ?? [];
  assert.ok(
    ends.length >= 2,
    'tracePhase must emit an end span on BOTH the success and throw paths',
  );
});

test('§8.2::5: latency budgets are configurable per phase', () => {
  for (const key of ['preFilter', 'promptBuild', 'generatorCall', 'dispatch', 'resultMerge']) {
    assert.ok(
      new RegExp(`${key}\\??:`).test(declSrc),
      `LatencyBudgetsMs must expose a configurable ${key} budget`,
    );
  }
  assert.ok(
    /latencyBudgetsMs\??:/.test(declSrc),
    'OrchestratorDeps must accept latencyBudgetsMs',
  );
});

test('§8.2::5: a breached budget is reported, and does not abort the run', () => {
  assert.ok(
    /orchestrator_latency_budget_breached/.test(src),
    'a budget breach must be reported as telemetry',
  );
  const idx = src.indexOf('orchestrator_latency_budget_breached');
  const around = src.slice(Math.max(0, idx - 200), idx + 200);
  assert.ok(
    !/throw\s/.test(around),
    'a budget breach is a performance signal and must not throw',
  );
});

test("§8.2::5: 'result-merge' was added to StepKind, and no synonym duplicates an existing kind", () => {
  assert.ok(typesSrc.includes('result-merge'), "StepKind must include 'result-merge'");
  for (const invented of ['pre-filter', 'prompt-build', 'generator-call']) {
    assert.ok(
      !new RegExp(`\\|\\s*'${invented}'`).test(typesSrc),
      `StepKind must not add '${invented}' — an existing member already denotes that phase`,
    );
  }
});
