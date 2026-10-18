/**
 * @epicai/chariot — tests for src/cli/modelRecommendation.ts
 * CHARIOT::§17.2::5
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { recommendModel } from './modelRecommendation.js';
import type { HardwareInfo } from './hardware.js';

const GIB = 1024 * 1024 * 1024;

function hw(overrides: Partial<HardwareInfo>): HardwareInfo {
  return {
    cpuModel: 'test-cpu',
    cpuCores: 8,
    ramTotalBytes: 16 * GIB,
    gpu: null,
    gpuAbsentReason: 'none-detected',
    ...overrides,
  };
}

describe('recommendModel — CHARIOT::§17.2::5', () => {
  it('recommends mlx-lm at 7-13B for Apple Silicon with >=32 GiB unified memory', () => {
    const rec = recommendModel(
      hw({
        ramTotalBytes: 64 * GIB,
        gpu: { vendor: 'apple-silicon', name: 'Apple M3 Max', vramBytes: null, unifiedMemory: true },
      }),
    );
    assert.equal(rec?.backend, 'mlx-lm');
    assert.equal(rec?.sizeClass, '7-13B');
  });

  it('recommends mlx-lm at <=3B for Apple Silicon below 32 GiB (boundary: 31 GiB)', () => {
    const rec = recommendModel(
      hw({
        ramTotalBytes: 31 * GIB,
        gpu: { vendor: 'apple-silicon', name: 'Apple M2', vramBytes: null, unifiedMemory: true },
      }),
    );
    assert.equal(rec?.backend, 'mlx-lm');
    assert.equal(rec?.sizeClass, '<=3B');
  });

  it('treats exactly 32 GiB as the 7-13B boundary (inclusive)', () => {
    const rec = recommendModel(
      hw({
        ramTotalBytes: 32 * GIB,
        gpu: { vendor: 'apple-silicon', name: 'Apple M3', vramBytes: null, unifiedMemory: true },
      }),
    );
    assert.equal(rec?.sizeClass, '7-13B');
  });

  it('recommends vllm at 7-13B for NVIDIA with >=12 GiB VRAM', () => {
    const rec = recommendModel(
      hw({ gpu: { vendor: 'nvidia', name: 'RTX 4090', vramBytes: 24 * GIB, unifiedMemory: false } }),
    );
    assert.equal(rec?.backend, 'vllm');
    assert.equal(rec?.sizeClass, '7-13B');
  });

  it('recommends vllm at <=3B for NVIDIA below 12 GiB VRAM', () => {
    const rec = recommendModel(
      hw({ gpu: { vendor: 'nvidia', name: 'GTX 1660', vramBytes: 6 * GIB, unifiedMemory: false } }),
    );
    assert.equal(rec?.backend, 'vllm');
    assert.equal(rec?.sizeClass, '<=3B');
  });

  it('recommends vllm at <=3B (conservative) when NVIDIA VRAM is unreported', () => {
    const rec = recommendModel(
      hw({ gpu: { vendor: 'nvidia', name: 'Unknown Tesla', vramBytes: null, unifiedMemory: false } }),
    );
    assert.equal(rec?.backend, 'vllm');
    assert.equal(rec?.sizeClass, '<=3B');
  });

  it('recommends llama.cpp at <=3B for no-GPU hosts with >=16 GiB RAM', () => {
    const rec = recommendModel(hw({ ramTotalBytes: 16 * GIB, gpu: null }));
    assert.equal(rec?.backend, 'llama.cpp');
    assert.equal(rec?.sizeClass, '<=3B');
  });

  it('returns null (no local recommendation) for no-GPU hosts below 16 GiB RAM', () => {
    const rec = recommendModel(hw({ ramTotalBytes: 15 * GIB, gpu: null }));
    assert.equal(rec, null);
  });

  it('never names a vendor model, only a backend + size class', () => {
    const rec = recommendModel(
      hw({ gpu: { vendor: 'nvidia', name: 'RTX 4090', vramBytes: 24 * GIB, unifiedMemory: false } }),
    );
    assert.notEqual(rec, null);
    assert.deepEqual(Object.keys(rec as object).sort(), ['backend', 'reason', 'sizeClass']);
    assert.ok(['llama.cpp', 'vllm', 'mlx-lm'].includes(rec!.backend));
  });
});
