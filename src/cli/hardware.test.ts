/**
 * @epicai/chariot — tests for src/cli/hardware.ts
 * CHARIOT::§17.2::1, ::2, ::3
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isNodeVersionSupported,
  detectRuntimes,
  detectGpu,
  detectHardware,
  type RuntimeDetectionDeps,
  type GpuDetectionDeps,
  type HardwareDetectionDeps,
} from './hardware.js';

describe('isNodeVersionSupported — CHARIOT::§17.2::1', () => {
  it('accepts v20.0.0 (boundary, exactly the minimum)', () => {
    assert.equal(isNodeVersionSupported('v20.0.0'), true);
  });
  it('rejects v19.9.9 (one below the minimum major)', () => {
    assert.equal(isNodeVersionSupported('v19.9.9'), false);
  });
  it('accepts v21.0.0 (above the minimum)', () => {
    assert.equal(isNodeVersionSupported('v21.0.0'), true);
  });
  it('rejects an unparseable version string (fail-closed)', () => {
    assert.equal(isNodeVersionSupported('not-a-version'), false);
  });
  it('rejects an empty string', () => {
    assert.equal(isNodeVersionSupported(''), false);
  });
});

describe('detectRuntimes — CHARIOT::§17.2::2', () => {
  it('reports null for every runtime when none are on PATH', () => {
    const deps: RuntimeDetectionDeps = {
      commandExistsFn: () => false,
      spawnFn: () => ({ status: 0, stdout: 'should not be reached' }),
    };
    assert.deepEqual(detectRuntimes(deps), { python: null, go: null, rust: null });
  });

  it('reports the version line when a binary exists and exits 0', () => {
    const deps: RuntimeDetectionDeps = {
      commandExistsFn: (cmd) => cmd === 'python3' || cmd === 'go' || cmd === 'rustc',
      spawnFn: (bin) => {
        if (bin === 'python3') return { status: 0, stdout: 'Python 3.12.1\n' };
        if (bin === 'go') return { status: 0, stdout: 'go version go1.22.0 darwin/arm64\n' };
        if (bin === 'rustc') return { status: 0, stdout: 'rustc 1.78.0\n' };
        return { status: 1, stdout: '' };
      },
    };
    assert.deepEqual(detectRuntimes(deps), {
      python: 'Python 3.12.1',
      go: 'go version go1.22.0 darwin/arm64',
      rust: 'rustc 1.78.0',
    });
  });

  it('falls back to python2-style `python` only when python3 is absent', () => {
    const deps: RuntimeDetectionDeps = {
      commandExistsFn: (cmd) => cmd === 'python',
      spawnFn: () => ({ status: 0, stdout: 'Python 2.7.18\n' }),
    };
    assert.equal(detectRuntimes(deps).python, 'Python 2.7.18');
  });

  it('treats a nonzero exit as absent, not a thrown error', () => {
    const deps: RuntimeDetectionDeps = {
      commandExistsFn: () => true,
      spawnFn: () => ({ status: 1, stdout: '' }),
    };
    assert.doesNotThrow(() => detectRuntimes(deps));
    assert.deepEqual(detectRuntimes(deps), { python: null, go: null, rust: null });
  });

  it('never throws when spawnFn itself throws', () => {
    const deps: RuntimeDetectionDeps = {
      commandExistsFn: () => true,
      spawnFn: () => {
        throw new Error('ENOENT');
      },
    };
    assert.doesNotThrow(() => detectRuntimes(deps));
    assert.deepEqual(detectRuntimes(deps), { python: null, go: null, rust: null });
  });
});

describe('detectGpu — CHARIOT::§17.2::3 (rulings item 92)', () => {
  it('detects NVIDIA via nvidia-smi on linux', () => {
    const deps: GpuDetectionDeps = {
      platform: 'linux',
      commandExistsFn: (cmd) => cmd === 'nvidia-smi',
      spawnFn: () => ({ status: 0, stdout: 'NVIDIA GeForce RTX 4090, 24564\n' }),
    };
    const result = detectGpu(deps);
    assert.deepEqual(result.gpu, {
      vendor: 'nvidia',
      name: 'NVIDIA GeForce RTX 4090',
      vramBytes: 24564 * 1024 * 1024,
      unifiedMemory: false,
    });
    assert.equal(result.reason, null);
  });

  it('detects Apple Silicon via sysctl on darwin when nvidia-smi is absent', () => {
    const deps: GpuDetectionDeps = {
      platform: 'darwin',
      commandExistsFn: (cmd) => cmd === 'sysctl',
      spawnFn: () => ({ status: 0, stdout: 'Apple M3 Max\n' }),
    };
    const result = detectGpu(deps);
    assert.deepEqual(result.gpu, {
      vendor: 'apple-silicon',
      name: 'Apple M3 Max',
      vramBytes: null,
      unifiedMemory: true,
    });
    assert.equal(result.reason, null);
  });

  it('does not misidentify an Intel Mac as Apple Silicon', () => {
    const deps: GpuDetectionDeps = {
      platform: 'darwin',
      commandExistsFn: (cmd) => cmd === 'sysctl',
      spawnFn: () => ({ status: 0, stdout: 'Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz\n' }),
    };
    const result = detectGpu(deps);
    assert.equal(result.gpu, null);
    assert.equal(result.reason, 'none-detected');
  });

  it('returns none-detected on linux with no nvidia-smi', () => {
    const deps: GpuDetectionDeps = {
      platform: 'linux',
      commandExistsFn: () => false,
      spawnFn: () => ({ status: 0, stdout: '' }),
    };
    const result = detectGpu(deps);
    assert.equal(result.gpu, null);
    assert.equal(result.reason, 'none-detected');
  });

  it('returns unsupported-platform on win32', () => {
    const deps: GpuDetectionDeps = {
      platform: 'win32',
      commandExistsFn: () => true,
      spawnFn: () => ({ status: 0, stdout: 'NVIDIA GeForce RTX 4090, 24564\n' }),
    };
    const result = detectGpu(deps);
    assert.equal(result.gpu, null);
    assert.equal(result.reason, 'unsupported-platform');
  });

  it('never throws when the probe binary throws (e.g. spawn failure)', () => {
    const deps: GpuDetectionDeps = {
      platform: 'linux',
      commandExistsFn: () => true,
      spawnFn: () => {
        throw new Error('spawn EACCES');
      },
    };
    assert.doesNotThrow(() => detectGpu(deps));
    assert.deepEqual(detectGpu(deps), { gpu: null, reason: 'none-detected' });
  });

  it('prefers NVIDIA over Apple Silicon when (hypothetically) both probes succeed', () => {
    const deps: GpuDetectionDeps = {
      platform: 'darwin',
      commandExistsFn: () => true,
      spawnFn: (bin) =>
        bin === 'nvidia-smi'
          ? { status: 0, stdout: 'NVIDIA T4, 16384\n' }
          : { status: 0, stdout: 'Apple M3\n' },
    };
    assert.equal(detectGpu(deps).gpu?.vendor, 'nvidia');
  });
});

describe('detectHardware — CHARIOT::§17.2::3', () => {
  it('reports cpu/ram from injected os shims and folds in the gpu result', () => {
    const deps: HardwareDetectionDeps = {
      cpus: () => Array(8).fill({ model: 'Apple M3 Max', speed: 0, times: {} as never }),
      totalmem: () => 64 * 1024 * 1024 * 1024,
      gpuDeps: {
        platform: 'darwin',
        commandExistsFn: (cmd) => cmd === 'sysctl',
        spawnFn: () => ({ status: 0, stdout: 'Apple M3 Max\n' }),
      },
    };
    const hw = detectHardware(deps);
    assert.equal(hw.cpuCores, 8);
    assert.equal(hw.cpuModel, 'Apple M3 Max');
    assert.equal(hw.ramTotalBytes, 64 * 1024 * 1024 * 1024);
    assert.equal(hw.gpu?.vendor, 'apple-silicon');
    assert.equal(hw.gpuAbsentReason, null);
  });

  it('never throws when os.cpus()/totalmem() throw', () => {
    const deps: HardwareDetectionDeps = {
      cpus: () => {
        throw new Error('boom');
      },
      totalmem: () => {
        throw new Error('boom');
      },
      gpuDeps: { platform: 'linux', commandExistsFn: () => false, spawnFn: () => ({ status: 0, stdout: '' }) },
    };
    assert.doesNotThrow(() => detectHardware(deps));
    const hw = detectHardware(deps);
    assert.equal(hw.cpuCores, 0);
    assert.equal(hw.ramTotalBytes, 0);
    assert.equal(hw.gpu, null);
    assert.equal(hw.gpuAbsentReason, 'none-detected');
  });
});
