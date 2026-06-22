/**
 * @epicai/chariot — Linear-Probe Observability Hook
 *
 * Surfaces top-N tool-selection probabilities from a local-SLM
 * hidden state BEFORE federation.callTool is dispatched.  Read-only
 * observability — does NOT alter selection behavior.
 *
 * Reference: Wu et al. arXiv 2605.07990 (UCL / Holistic AI / Imperial 2026)
 *   "Tool Calling is Linearly Readable and Steerable in Language Models"
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/**
 * A single tool prediction returned by the probe.
 */
export interface ProbeEntry {
  tool: string;
  confidence: number;
}

/**
 * Optional observability hook wired into OrchestratorDeps.
 *
 * Implementations are supplied by operators who run the local-SLM path and
 * have access to the model's hidden-state buffer.  On the cloud-LLM
 * production path (where the calling LLM is the customer's and hidden states
 * are unavailable), this interface is simply not wired — no 'selection-probe'
 * StreamEvent is emitted, and zero overhead is incurred.
 */
export interface LinearProbeReadout {
  /**
   * Read tool-selection probabilities from a hidden-state buffer.
   *
   * @param hiddenState  Float32Array or number[] captured from the local SLM
   *                     at the final input-token position (pre-generation).
   * @param toolNames    Candidate tool names presented to the SLM.  The probe
   *                     implementation should restrict its output to names in
   *                     this list; unrecognised names are permitted but will
   *                     not match any active tool.
   * @returns            Predictions sorted descending by confidence.  An empty
   *                     array means "no probe signal for this iteration" — the
   *                     Orchestrator will skip emission silently.
   */
  read(hiddenState: Float32Array | number[], toolNames: string[]): ProbeEntry[];
}

/**
 * No-op default — used when no readout is wired into OrchestratorDeps.
 * Always returns an empty array so the Orchestrator emits no events.
 */
export class NoOpLinearProbeReadout implements LinearProbeReadout {
  read(_hiddenState: Float32Array | number[], _toolNames: string[]): ProbeEntry[] {
    return [];
  }
}
