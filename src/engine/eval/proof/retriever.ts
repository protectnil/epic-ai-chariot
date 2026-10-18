/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: baseline retriever adapter
 *
 * `BM25ToolPreFilterRetriever` wraps the SHIPPED `ToolPreFilter` (BM25 + IDF +
 * brand pins/hoist + term-class boosts) behind the pluggable `Retriever`
 * interface. It drives the real `select()` with the production defaults
 * (`DEFAULT_MAX_PER_SERVER`), so the benchmark measures exactly the shortlist
 * the orchestrator LLM is offered today. ToolPreFilter is imported read-only
 * and is NOT modified.
 *
 * The P4 hybrid retriever (dense+SPLADE+BM25 → RRF → cross-encoder rerank)
 * implements the same `Retriever` interface and drops in here with no harness
 * change.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { Tool } from '../../types/index.js';
import {
  ToolPreFilter,
  DEFAULT_MAX_PER_SERVER,
} from '../../federation/ToolPreFilter.js';
import { toolIdOf } from './catalog.js';
import type { Retriever, RetrieverInfo, RetrievedTool } from './types.js';

export interface BM25RetrieverOptions {
  /**
   * Per-server diversity cap passed to `select()`. Defaults to the production
   * `DEFAULT_MAX_PER_SERVER` (3) so the headline number reflects the real
   * shortlist. Set to `Infinity` for a diagnostic "no diversity cap" run that
   * isolates raw lexical recall from the diversity policy.
   */
  maxPerServer?: number;
  /** Override the reported version/provenance string. */
  version?: string;
}

export class BM25ToolPreFilterRetriever implements Retriever {
  readonly info: RetrieverInfo;
  private readonly filter = new ToolPreFilter();
  private readonly maxPerServer: number;

  constructor(opts: BM25RetrieverOptions = {}) {
    this.maxPerServer = opts.maxPerServer ?? DEFAULT_MAX_PER_SERVER;
    const capLabel = Number.isFinite(this.maxPerServer)
      ? `maxPerServer=${this.maxPerServer}`
      : 'maxPerServer=∞';
    this.info = {
      id: Number.isFinite(this.maxPerServer)
        ? 'bm25-toolprefilter'
        : 'bm25-toolprefilter-nocap',
      label: `Chariot BM25 ToolPreFilter (4.0.0 baseline, ${capLabel})`,
      version: opts.version ?? `ToolPreFilter/bm25 ${capLabel}`,
      kind: 'baseline',
      runnable: true,
      // ToolPreFilter.select() returns Tool[] with no scores and is read-only
      // (not modified here), so no per-candidate confidence is available; the
      // calibration report is recorded `unavailable` for this baseline.
      providesConfidence: false,
    };
  }

  index(tools: Tool[]): void {
    this.filter.index(tools);
  }

  async retrieve(query: string, k: number): Promise<RetrievedTool[]> {
    const selected = await this.filter.select(query, {
      maxTools: k,
      maxPerServer: this.maxPerServer,
    });
    return selected.map((t) => ({
      // `toolIdOf` returns `t.name`, which is already `${server}:${method}` — the
      // exact id the orchestrator LLM would be offered. Keeping it identical to
      // the catalog/gold id space is what makes recall computable.
      id: toolIdOf(t),
      server: t.server,
      name: t.name,
    }));
  }

  get size(): number {
    return this.filter.size;
  }
}
