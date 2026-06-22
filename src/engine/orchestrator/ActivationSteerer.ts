/**
 * @epicai/chariot — Activation Steering for Tool Selection
 *
 * arxiv 2605.07990 "Tool Calling is Linearly Readable and Steerable in
 * Language Models": activation steering applied to a precomputed
 * category vector at layer L lifts tool-selection accuracy materially
 * (Gemma 3 4B base: 2% → 69%, ~56-point lift). Local-SLM only.
 *
 * This class hosts the per-category vectors and applies them additively
 * to a hidden state with a configurable weight. The actual model-side
 * injection (vLLM custom-forward) is out of scope; this is the wiring
 * + the no-op fallback contract so callers can compose with whatever
 * SLM provider lands the deeper hook.
 *
 * =====================================================================
 * READ THIS BEFORE ASSUMING THIS CODE DOES ANYTHING IN CURRENT BUILDS
 * =====================================================================
 * This class is DORMANT in current Chariot builds. Three halves are missing from
 * the deployed product:
 *
 *   1. NO STEERING-VECTORS FILE IS SHIPPED. The class constructor
 *      takes a `vectors: SteeringVector[]` argument, but the chariot
 *      npm package ships no `steering-vectors.bin` or equivalent.
 *      The orchestrator's `deps.activationSteerer` slot is undefined
 *      in every shipped configuration; `apply()` is never invoked.
 *
 *   2. NO MODEL-SIDE INJECTION HOOK EXISTS. Even if a vectors file
 *      shipped and `apply()` returned a steered hidden-state vector,
 *      mainline vLLM has no public API to inject a mutated hidden
 *      state mid-forward-pass. The spec (§3.3) calls this a vLLM
 *      custom-forward extension; that extension does not exist in
 *      vLLM today. Without it, `apply()`'s output cannot reach the
 *      model's next forward pass — the math is computed and
 *      discarded.
 *
 *   3. NO RUNTIME PATH ACTIVATES IT EVEN IF (1) + (2) LANDED.
 *      Chariot's customer deployment is dominantly cloud LLMs
 *      (Anthropic / OpenAI / DigitalOcean), which expose no
 *      mid-forward-pass hooks of any kind. Activation steering
 *      requires the customer to be self-hosting a local SLM with
 *      a vLLM build carrying the custom-forward extension.
 *
 * Net effect today: zero runtime behavior change vs. a build without
 * this class. The code is wired so that the day vectors + a
 * vLLM-extension call site both arrive, steering activates with no
 * further chariot-side code change.
 *
 * MARKETING / README CONSTRAINT: this feature MUST NOT be described as
 * live to customers in current marketing surfaces. Activation requires
 * the three missing artifacts named above. Verified at commit time:
 * README.md and DEVELOPER_GUIDE.md contain zero references to
 * activation steering or steering vectors — the dormant state is
 * honored by the shipped docs.
 * =====================================================================
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createLogger } from '../logger.js';

const log = createLogger('orchestrator.activation-steering');
let warnedUnsupported = false;

export interface SteeringVector {
  modelName: string;
  layer: number;
  category: string;
  vector: number[];
}

function keyOf(modelName: string, layer: number, category: string): string {
  return `${modelName}:${layer}:${category}`;
}

export class ActivationSteerer {
  private readonly byKey: Map<string, ReadonlyArray<number>>;

  constructor(vectors: SteeringVector[]) {
    this.byKey = new Map();
    for (const v of vectors) {
      if (!v || typeof v.modelName !== 'string' || !Number.isFinite(v.layer) || typeof v.category !== 'string' || !Array.isArray(v.vector)) continue;
      this.byKey.set(keyOf(v.modelName, v.layer, v.category), v.vector);
    }
  }

  /** Visible for tests. */
  size(): number { return this.byKey.size; }

  isSupported(modelName: string, layer: number, category: string): boolean {
    return this.byKey.has(keyOf(modelName, layer, category));
  }

  /**
   * Apply the (modelName, layer, category) steering vector additively to
   * hiddenState at the given weight: `out[i] = hidden[i] + weight*vec[i]`.
   * Missing key OR length mismatch → returns hiddenState unchanged with
   * a warn-once 'steering_unsupported'. Callers that need to know whether
   * a modification happened should check `isSupported()` first OR compare
   * the returned reference (unchanged → identity).
   */
  apply(hiddenState: number[], modelName: string, layer: number, category: string, weight: number): number[] {
    const k = keyOf(modelName, layer, category);
    const vec = this.byKey.get(k);
    if (!vec) {
      if (!warnedUnsupported) {
        warnedUnsupported = true;
        log.warn('activation_steering_unsupported.no_vector', { modelName, layer, category });
      }
      return hiddenState;
    }
    if (vec.length !== hiddenState.length) {
      if (!warnedUnsupported) {
        warnedUnsupported = true;
        log.warn('activation_steering_unsupported.length_mismatch', { modelName, layer, category, vectorLength: vec.length, hiddenStateLength: hiddenState.length });
      }
      return hiddenState;
    }
    const out = new Array<number>(hiddenState.length);
    for (let i = 0; i < hiddenState.length; i++) out[i] = hiddenState[i] + weight * vec[i];
    return out;
  }
}

// Visible for tests — reset the warn-once latch.
export function __resetSteeringWarnOnce(): void { warnedUnsupported = false; }
