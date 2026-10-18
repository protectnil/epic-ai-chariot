/**
 * @epicai/chariot — local-model size/backend recommendation for the setup
 * wizard. CHARIOT-SPEC.md:1407 (§17.2 step 2): "recommend a model based on
 * hardware." CHARIOT::§17.2::5.
 *
 * MASTER ruling (rulings item 92, 2026-09-04): Chariot hosts no model of
 * its own (CHARIOT-SPEC.md:56 — "Chariot is not an LLM. Chariot does not
 * host a model, does not train a model, does not fine-tune a model.");
 * the recommendation therefore names ONLY a BACKEND
 * from the §8.10 Inference Gateway's discovered-backend set
 * (llama.cpp / vLLM / mlx-lm — Ollama excluded from *recommendation*,
 * though it remains a valid "I have one running" detection target per
 * CHARIOT::§17.2::4/::6) and a coarse size class (`<=3B` | `7-13B`)
 * derived from RAM/GPU. Never a vendor/model name.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { HardwareInfo } from './hardware.js';

export type RecommendedBackend = 'llama.cpp' | 'vllm' | 'mlx-lm';
export type SizeClass = '<=3B' | '7-13B';

export interface ModelRecommendation {
  backend: RecommendedBackend;
  sizeClass: SizeClass;
  reason: string;
}

const GIB = 1024 * 1024 * 1024;
const MIN_RAM_FOR_CPU_LOCAL_BYTES = 16 * GIB;
const HIGH_RAM_THRESHOLD_BYTES = 32 * GIB;
const HIGH_VRAM_THRESHOLD_BYTES = 12 * GIB;

/**
 * Returns `null` when the detected hardware doesn't clear the minimum bar
 * for a usable local backend (no GPU and < 16 GiB RAM) — the wizard should
 * treat `null` as "no local recommendation; offer cloud/skip instead",
 * never as a silent default to the smallest size class.
 */
export function recommendModel(hardware: HardwareInfo): ModelRecommendation | null {
  const gpu = hardware.gpu;

  if (gpu?.vendor === 'apple-silicon') {
    const sizeClass: SizeClass =
      hardware.ramTotalBytes >= HIGH_RAM_THRESHOLD_BYTES ? '7-13B' : '<=3B';
    return {
      backend: 'mlx-lm',
      sizeClass,
      reason:
        sizeClass === '7-13B'
          ? `Apple Silicon (${gpu.name}) with ${Math.round(hardware.ramTotalBytes / GIB)} GiB unified memory supports a 7-13B model via mlx-lm.`
          : `Apple Silicon (${gpu.name}) with ${Math.round(hardware.ramTotalBytes / GIB)} GiB unified memory — mlx-lm recommended at <=3B for headroom.`,
    };
  }

  if (gpu?.vendor === 'nvidia') {
    const vramKnown = gpu.vramBytes !== null;
    const sizeClass: SizeClass =
      vramKnown && gpu.vramBytes! >= HIGH_VRAM_THRESHOLD_BYTES ? '7-13B' : '<=3B';
    return {
      backend: 'vllm',
      sizeClass,
      reason: vramKnown
        ? `NVIDIA ${gpu.name} with ${Math.round(gpu.vramBytes! / GIB)} GiB VRAM — vLLM recommended at ${sizeClass}.`
        : `NVIDIA ${gpu.name} detected (VRAM unreported) — vLLM recommended at <=3B, conservative default.`,
    };
  }

  // No GPU: CPU-only local inference via llama.cpp, gated on RAM.
  if (hardware.ramTotalBytes < MIN_RAM_FOR_CPU_LOCAL_BYTES) {
    return null;
  }
  return {
    backend: 'llama.cpp',
    sizeClass: '<=3B',
    reason: `No GPU detected; ${Math.round(hardware.ramTotalBytes / GIB)} GiB RAM supports CPU inference via llama.cpp at <=3B.`,
  };
}
