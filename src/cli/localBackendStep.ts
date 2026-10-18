/**
 * @epicai/chariot — local AI backend step decision logic for the setup
 * wizard. CHARIOT-SPEC.md:1407 (§17.2 step 2): "offer auto-download, 'I
 * have one running', or 'skip'." CHARIOT::§17.2::6.
 *
 * This module is the pure DECISION layer only: given what was detected
 * (CHARIOT::§17.2::4) and the recommendation (CHARIOT::§17.2::5), and the
 * operator's choice among the three options, it returns an `Action`
 * descriptor. The `@clack/prompts` UI in setup.ts is a thin wrapper that
 * presents the 3-option `p.select()` and executes the returned Action —
 * it contains no decision logic of its own, so this module is fully
 * testable without a TTY.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { ModelRecommendation, RecommendedBackend } from './modelRecommendation.js';

export type LocalBackendChoice = 'auto-download' | 'have-one-running' | 'skip';

export interface DetectedLocalBackend {
  backend: string;
  port: number;
}

export interface DownloadCommand {
  bin: string;
  argv: string[];
  /** Set when the backend has no known install command on this platform — the wizard must print manual instructions instead of spawning. */
  manualInstructionsOnly?: boolean;
}

/**
 * Best-effort install command per recommended backend. `mlx-lm` and
 * `vllm` install via pip (both are Python packages); `llama.cpp` installs
 * via Homebrew on darwin and has no single cross-platform package manager
 * command, so non-darwin hosts get manual instructions.
 */
export function installCommandFor(
  backend: RecommendedBackend,
  platform: NodeJS.Platform,
): DownloadCommand {
  switch (backend) {
    case 'mlx-lm':
      return { bin: 'pip3', argv: ['install', 'mlx-lm'] };
    case 'vllm':
      return { bin: 'pip3', argv: ['install', 'vllm'] };
    case 'llama.cpp':
      return platform === 'darwin'
        ? { bin: 'brew', argv: ['install', 'llama.cpp'] }
        : { bin: '', argv: [], manualInstructionsOnly: true };
  }
}

export type LocalBackendAction =
  | { kind: 'download'; backend: RecommendedBackend; sizeClass: ModelRecommendation['sizeClass']; command: DownloadCommand }
  | { kind: 'download-unavailable'; reason: string }
  | { kind: 'use-detected'; backend: string; port: number }
  | { kind: 'prompt-custom-url' }
  | { kind: 'skip' };

/**
 * CHARIOT::§17.2::6 — "offer the operator exactly three options ...
 * auto-download, 'I have one running', and skip." This function is the
 * single place that decides what each of the three choices DOES; the UI
 * layer never branches on `choice` itself.
 */
export function planLocalBackendStep(
  detected: DetectedLocalBackend | null,
  choice: LocalBackendChoice,
  recommendation: ModelRecommendation | null,
  platform: NodeJS.Platform,
): LocalBackendAction {
  switch (choice) {
    case 'auto-download':
      if (!recommendation) {
        return {
          kind: 'download-unavailable',
          reason: 'No local backend recommendation for this hardware (insufficient RAM/no GPU).',
        };
      }
      return {
        kind: 'download',
        backend: recommendation.backend,
        sizeClass: recommendation.sizeClass,
        command: installCommandFor(recommendation.backend, platform),
      };
    case 'have-one-running':
      return detected
        ? { kind: 'use-detected', backend: detected.backend, port: detected.port }
        : { kind: 'prompt-custom-url' };
    case 'skip':
      return { kind: 'skip' };
  }
}
