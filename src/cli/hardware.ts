/**
 * @epicai/chariot — System hardware/runtime detection for the setup wizard.
 * CHARIOT-SPEC.md:1406 (§17.2 step 1): "Node ≥20, Python/Go/Rust runtimes,
 * hardware (CPU, RAM, GPU), existing local SLM backends on standard ports."
 * CHARIOT::§17.2::1 (Node >=20 detect+validate), ::2 (Python/Go/Rust
 * detection), ::3 (CPU/RAM/GPU detection).
 *
 * Every exported detector is a pure(-ish) function taking injectable
 * dependencies so callers can drive it without a real subprocess/OS call —
 * the wizard itself calls the zero-arg convenience wrappers at the bottom.
 * No detector ever throws: a missing tool/unsupported platform degrades to
 * `null`/`false`, matching the existing LOCAL_BACKENDS probe's fail-open
 * pattern (src/cli/mcp-clients.ts:299-338).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { spawnSync } from 'node:child_process';
import * as os from 'node:os';
import { commandExists } from './paths.js';

// ─── Node version validation (CHARIOT::§17.2::1) ───────────────────────────

/**
 * `process.version` is `vMAJOR.MINOR.PATCH`. Returns false on any string
 * that doesn't parse as that shape (fail-closed: an unparseable version
 * string is never treated as supported).
 */
export function isNodeVersionSupported(versionString: string, minMajor = 20): boolean {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(versionString);
  if (!m) return false;
  const major = Number(m[1]);
  if (!Number.isFinite(major)) return false;
  return major >= minMajor;
}

// ─── Runtime detection (CHARIOT::§17.2::2) ─────────────────────────────────

export interface RuntimeVersions {
  python: string | null;
  go: string | null;
  rust: string | null;
}

/** Injectable so tests never spawn a real process. */
export interface RuntimeDetectionDeps {
  commandExistsFn: (cmd: string) => boolean;
  spawnFn: (bin: string, argv: string[]) => { status: number | null; stdout: string };
}

const defaultDeps: RuntimeDetectionDeps = {
  commandExistsFn: commandExists,
  spawnFn: (bin, argv) => {
    const r = spawnSync(bin, argv, { timeout: 3000, encoding: 'utf-8' });
    return { status: r.status, stdout: (r.stdout ?? '').toString() };
  },
};

function probeVersion(
  bin: string,
  argv: string[],
  deps: RuntimeDetectionDeps,
): string | null {
  if (!deps.commandExistsFn(bin)) return null;
  try {
    const r = deps.spawnFn(bin, argv);
    if (r.status !== 0) return null;
    const line = r.stdout.trim().split('\n')[0] ?? '';
    return line.length > 0 ? line : null;
  } catch {
    return null;
  }
}

/**
 * Detects Python, Go, and Rust in a single pass. `python3` is tried before
 * the bare `python` alias (Python 2 shells still ship `python` on some
 * hosts; `python3` is the unambiguous signal).
 */
export function detectRuntimes(deps: RuntimeDetectionDeps = defaultDeps): RuntimeVersions {
  const python =
    probeVersion('python3', ['--version'], deps) ?? probeVersion('python', ['--version'], deps);
  const go = probeVersion('go', ['version'], deps);
  const rust = probeVersion('rustc', ['--version'], deps);
  return { python, go, rust };
}

// ─── Hardware detection (CHARIOT::§17.2::3) ────────────────────────────────

/**
 * MASTER ruling (rulings item 92, 2026-09-04): minimum GPU set is NVIDIA
 * via `nvidia-smi` and Apple Silicon via `sysctl machdep.cpu.brand_string`;
 * otherwise `gpu: null` with a `reason` distinguishing "genuinely absent"
 * from "this platform isn't covered by a detector yet". Windows is
 * `unsupported-platform`. Never throws.
 */
export type GpuAbsentReason = 'none-detected' | 'unsupported-platform';

export interface GpuInfo {
  vendor: 'nvidia' | 'apple-silicon';
  name: string;
  /** VRAM in bytes; null when the probe can't report it (Apple Silicon uses unified memory — see `unifiedMemory`). */
  vramBytes: number | null;
  /** True for Apple Silicon, where GPU and CPU share system RAM. */
  unifiedMemory: boolean;
}

export type GpuDetectionResult =
  | { gpu: GpuInfo; reason: null }
  | { gpu: null; reason: GpuAbsentReason };

export interface GpuDetectionDeps {
  platform: NodeJS.Platform;
  commandExistsFn: (cmd: string) => boolean;
  spawnFn: (bin: string, argv: string[]) => { status: number | null; stdout: string };
}

const defaultGpuDeps: GpuDetectionDeps = {
  platform: process.platform,
  commandExistsFn: commandExists,
  spawnFn: defaultDeps.spawnFn,
};

function detectNvidia(deps: GpuDetectionDeps): GpuInfo | null {
  if (!deps.commandExistsFn('nvidia-smi')) return null;
  try {
    const r = deps.spawnFn('nvidia-smi', [
      '--query-gpu=name,memory.total',
      '--format=csv,noheader,nounits',
    ]);
    if (r.status !== 0) return null;
    const line = r.stdout.trim().split('\n')[0] ?? '';
    if (!line) return null;
    const [name, memMiB] = line.split(',').map((s) => s.trim());
    if (!name) return null;
    const mib = Number(memMiB);
    return {
      vendor: 'nvidia',
      name,
      vramBytes: Number.isFinite(mib) ? mib * 1024 * 1024 : null,
      unifiedMemory: false,
    };
  } catch {
    return null;
  }
}

function detectAppleSilicon(deps: GpuDetectionDeps): GpuInfo | null {
  if (deps.platform !== 'darwin') return null;
  if (!deps.commandExistsFn('sysctl')) return null;
  try {
    const r = deps.spawnFn('sysctl', ['-n', 'machdep.cpu.brand_string']);
    if (r.status !== 0) return null;
    const brand = r.stdout.trim();
    if (!/^Apple\s+M\d/i.test(brand)) return null;
    return { vendor: 'apple-silicon', name: brand, vramBytes: null, unifiedMemory: true };
  } catch {
    return null;
  }
}

/**
 * WHEN the host exposes neither an NVIDIA GPU (`nvidia-smi`) nor Apple
 * Silicon (`sysctl machdep.cpu.brand_string` matching `Apple M*`), returns
 * `gpu: null` with `reason: 'none-detected'` on a platform this module
 * covers (darwin/linux), or `reason: 'unsupported-platform'` on any other
 * platform (win32 included, per ruling). Never throws.
 */
export function detectGpu(deps: GpuDetectionDeps = defaultGpuDeps): GpuDetectionResult {
  try {
    if (deps.platform !== 'darwin' && deps.platform !== 'linux') {
      return { gpu: null, reason: 'unsupported-platform' };
    }
    const nvidia = detectNvidia(deps);
    if (nvidia) return { gpu: nvidia, reason: null };
    const apple = detectAppleSilicon(deps);
    if (apple) return { gpu: apple, reason: null };
    return { gpu: null, reason: 'none-detected' };
  } catch {
    return { gpu: null, reason: 'none-detected' };
  }
}

export interface HardwareInfo {
  cpuModel: string;
  cpuCores: number;
  ramTotalBytes: number;
  gpu: GpuInfo | null;
  gpuAbsentReason: GpuAbsentReason | null;
}

export interface HardwareDetectionDeps {
  cpus: () => os.CpuInfo[];
  totalmem: () => number;
  gpuDeps: GpuDetectionDeps;
}

const defaultHardwareDeps: HardwareDetectionDeps = {
  cpus: () => os.cpus(),
  totalmem: () => os.totalmem(),
  gpuDeps: defaultGpuDeps,
};

/** CHARIOT::§17.2::3 — CPU, RAM, GPU in one detection pass. Never throws. */
export function detectHardware(deps: HardwareDetectionDeps = defaultHardwareDeps): HardwareInfo {
  let cpuModel = 'unknown';
  let cpuCores = 0;
  try {
    const cpus = deps.cpus();
    cpuCores = cpus.length;
    cpuModel = cpus[0]?.model ?? 'unknown';
  } catch {
    // leave defaults — never throw out of a detector
  }
  let ramTotalBytes = 0;
  try {
    ramTotalBytes = deps.totalmem();
  } catch {
    // leave 0
  }
  const gpuResult = detectGpu(deps.gpuDeps);
  return {
    cpuModel,
    cpuCores,
    ramTotalBytes,
    gpu: gpuResult.gpu,
    gpuAbsentReason: gpuResult.reason,
  };
}
