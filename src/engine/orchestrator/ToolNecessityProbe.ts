/**
 * @epicai/chariot — Tool-Necessity Probe
 *
 * PROBE&PREFILL (arxiv 2605.09252): tool-call necessity is linearly
 * readable from an LLM's hidden state at the last input token. This
 * probe applies a precomputed logistic-regression classifier (weights
 * w, bias b, threshold τ) to decide whether the orchestrator should
 * route the query through retrieval/federation or skip the tool path
 * entirely.
 *
 * LOCAL-SLM ONLY: cloud LLMs don't expose hidden states; Ollama's
 * /api/chat also doesn't. `decide(undefined)` returns 'unsupported'
 * with a warn-once and the orchestrator falls through to today's
 * behavior.
 *
 * =====================================================================
 * READ THIS BEFORE ASSUMING THIS CODE DOES ANYTHING IN CURRENT BUILDS
 * =====================================================================
 * This class is DORMANT in current Chariot builds. Two halves are missing from
 * the deployed product:
 *
 *   1. NO PROBE WEIGHTS FILE IS SHIPPED. The class constructor takes
 *      a `weights: number[]` argument, but the chariot npm package
 *      does not ship a probe-weights `.bin`, and no construction site
 *      passes weights to a default-constructed ToolNecessityProbe.
 *      The orchestrator's `deps.toolNecessityProbe` slot is therefore
 *      undefined in every shipped configuration today; the probe call
 *      path in the orchestrator loop (Orchestrator.execute) is never reached.
 *
 *   2. NO RUNTIME PATH ACTIVATES IT EVEN IF WEIGHTS WERE SHIPPED.
 *      Chariot's customer deployment is dominantly cloud LLMs
 *      (Anthropic / OpenAI / DigitalOcean), which do not return
 *      `hiddenStates` on their LLM responses. Ollama is also
 *      unsupported per spec §3.3. The probe only fires for customers
 *      self-hosting a local SLM that exposes hidden states (vLLM with
 *      `--return-hidden-states`, llama.cpp `/embeddings`, transformers
 *      `output_hidden_states=True`).
 *
 * Net effect today: zero runtime behavior change vs. a build without
 * this class. The code is wired so that the day weights + a local-SLM
 * call site both arrive, the probe activates with no further code
 * change. Until then, treat any reference to PROBE&PREFILL in this
 * module as documentation of intent, not an active feature.
 *
 * MARKETING / README CONSTRAINT: this feature MUST NOT be described as
 * live to customers in current marketing surfaces. Activation requires
 * the two missing artifacts named above plus customer-side runtime
 * configuration. Verified at commit time: README.md and
 * DEVELOPER_GUIDE.md contain zero references to PROBE&PREFILL,
 * tool-necessity gating, or WHEN2TOOL — the dormant state is honored
 * by the shipped docs.
 * =====================================================================
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

let warnedUnsupported = false;

export type ProbeDecision = 'tool-needed' | 'no-tool' | 'unsupported';

export class ToolNecessityProbe {
  private readonly weights: ReadonlyArray<number>;
  private readonly bias: number;
  private readonly threshold: number;

  constructor(weights: number[], bias: number, threshold = 0.5) {
    if (!Array.isArray(weights) || weights.length === 0) {
      throw new Error('ToolNecessityProbe: weights must be a non-empty number[]');
    }
    if (!Number.isFinite(bias)) {
      throw new Error('ToolNecessityProbe: bias must be finite');
    }
    if (!(threshold >= 0 && threshold <= 1)) {
      throw new Error('ToolNecessityProbe: threshold must be in [0, 1]');
    }
    this.weights = weights;
    this.bias = bias;
    this.threshold = threshold;
  }

  /** Visible for tests / observability. */
  getThreshold(): number { return this.threshold; }

  /**
   * Score `hiddenStates` (dot product + bias, sigmoid) and return the
   * decision. Returns 'unsupported' (with a warn-once) when hiddenStates
   * is undefined or length mismatches the trained weight vector.
   */
  decide(hiddenStates: number[] | Float32Array | undefined): { decision: ProbeDecision; probability?: number } {
    if (hiddenStates === undefined) {
      if (!warnedUnsupported) {
        warnedUnsupported = true;
        console.warn('[chariot] PROBE&PREFILL probe_unsupported: hidden states unavailable on this LLM path (cloud-LLM or Ollama). decide() will no-op.');
      }
      return { decision: 'unsupported' };
    }
    const xs: ArrayLike<number> = hiddenStates;
    if (xs.length !== this.weights.length) {
      if (!warnedUnsupported) {
        warnedUnsupported = true;
        console.warn(`[chariot] PROBE&PREFILL probe_unsupported: hiddenStates length ${xs.length} does not match trained weight length ${this.weights.length}.`);
      }
      return { decision: 'unsupported' };
    }
    let dot = this.bias;
    for (let i = 0; i < this.weights.length; i++) dot += this.weights[i] * xs[i];
    const p = 1 / (1 + Math.exp(-dot));
    return { decision: p < this.threshold ? 'no-tool' : 'tool-needed', probability: p };
  }
}

// Visible for tests — reset the warn-once latch.
export function __resetProbeWarnOnce(): void { warnedUnsupported = false; }
