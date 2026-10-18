/**
 * @epicai/chariot — tests for src/cli/localBackendStep.ts
 * CHARIOT::§17.2::6
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { planLocalBackendStep, installCommandFor } from './localBackendStep.js';
import type { ModelRecommendation } from './modelRecommendation.js';

const rec: ModelRecommendation = { backend: 'mlx-lm', sizeClass: '<=3B', reason: 'test' };

describe('planLocalBackendStep — CHARIOT::§17.2::6 (exactly three options)', () => {
  it('auto-download with a recommendation returns a download action naming the backend', () => {
    const action = planLocalBackendStep(null, 'auto-download', rec, 'darwin');
    assert.equal(action.kind, 'download');
    assert.equal((action as { backend?: string }).backend, 'mlx-lm');
    assert.equal((action as { sizeClass?: string }).sizeClass, '<=3B');
  });

  it('auto-download with no recommendation returns download-unavailable, not a silent default', () => {
    const action = planLocalBackendStep(null, 'auto-download', null, 'darwin');
    assert.equal(action.kind, 'download-unavailable');
  });

  it('"I have one running" with a detected backend uses it directly', () => {
    const action = planLocalBackendStep({ backend: 'Ollama', port: 11434 }, 'have-one-running', rec, 'darwin');
    assert.deepEqual(action, { kind: 'use-detected', backend: 'Ollama', port: 11434 });
  });

  it('"I have one running" with nothing detected prompts for a custom URL instead of failing', () => {
    const action = planLocalBackendStep(null, 'have-one-running', rec, 'darwin');
    assert.deepEqual(action, { kind: 'prompt-custom-url' });
  });

  it('skip always returns skip regardless of detection/recommendation', () => {
    assert.deepEqual(
      planLocalBackendStep({ backend: 'Ollama', port: 11434 }, 'skip', rec, 'darwin'),
      { kind: 'skip' },
    );
    assert.deepEqual(planLocalBackendStep(null, 'skip', null, 'linux'), { kind: 'skip' });
  });
});

describe('installCommandFor', () => {
  it('llama.cpp on darwin uses brew', () => {
    assert.deepEqual(installCommandFor('llama.cpp', 'darwin'), { bin: 'brew', argv: ['install', 'llama.cpp'] });
  });
  it('llama.cpp on linux has no single command — manual instructions only', () => {
    assert.equal(installCommandFor('llama.cpp', 'linux').manualInstructionsOnly, true);
  });
  it('vllm and mlx-lm install via pip3 on any platform', () => {
    assert.deepEqual(installCommandFor('vllm', 'linux'), { bin: 'pip3', argv: ['install', 'vllm'] });
    assert.deepEqual(installCommandFor('mlx-lm', 'darwin'), { bin: 'pip3', argv: ['install', 'mlx-lm'] });
  });
});
