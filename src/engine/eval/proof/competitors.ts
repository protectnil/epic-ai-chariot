/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: named-competitor scaffold (§6.5)
 *
 * The North-Star "provable against named competitors" axis (§1.4) requires a
 * harness that runs a third-party tool-retrieval baseline on the EXACT same gold
 * set as the Chariot retriever. The plug point is the shared `Retriever`
 * interface: any competitor that implements `index()` + `retrieve()` is measured
 * identically by run-proof.ts — no harness change.
 *
 * Until a competitor is actually wired and locally runnable, it is registered as
 * a NON-RUNNABLE STUB (`info.runnable = false`) with an honest pending reason.
 * The runner records such entries as `status:'pending'` and NEVER calls
 * `retrieve()` on them, so no competitor number is ever fabricated (§1.4: a
 * "best in class" claim is made only on a reproduced result). The eval host here
 * is air-gapped (offline; no external API keys), so all currently-named
 * competitors are pending pending vendoring of a license-clean, offline-runnable
 * baseline.
 *
 * To make a competitor RUNNABLE: implement `Retriever` (see `BM25ToolPreFilterRetriever`
 * for the reference), set `info.runnable = true`, and register it below in place
 * of the stub. The runner will then measure it on the gold set automatically.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { Tool } from '../../types/index.js';
import type { Retriever, RetrieverInfo, RetrievedTool } from './types.js';
import { AgentCoreGatewayRetriever, readAgentCoreConfig, AGENTCORE_ENV } from './agentcore-retriever.js';

/** A competitor registration: the retriever plus, for stubs, why it is pending. */
export interface CompetitorRegistration {
  retriever: Retriever;
  /** Required for non-runnable stubs; ignored for runnable retrievers. */
  pendingReason?: string;
}

/**
 * A placeholder competitor that cannot be measured yet. `index()` records the
 * catalog size (so the scaffold is exercised) but `retrieve()` throws — the
 * runner must detect `info.runnable === false` and record the entry as pending
 * without ever calling it.
 */
export class StubCompetitorRetriever implements Retriever {
  readonly info: RetrieverInfo;
  private indexed = 0;

  constructor(spec: { id: string; label: string; version: string }) {
    this.info = {
      id: spec.id,
      label: spec.label,
      version: spec.version,
      kind: 'competitor',
      runnable: false,
      providesConfidence: false,
    };
  }

  index(tools: Tool[]): void {
    this.indexed = tools.length;
  }

  async retrieve(): Promise<RetrievedTool[]> {
    throw new Error(
      `competitor '${this.info.id}' is a non-runnable stub (pending integration); ` +
        'the runner must record it as pending and must not call retrieve()',
    );
  }

  get size(): number {
    return this.indexed;
  }
}

/**
 * The named competitors the proof artifact tracks. Each is a stub today with an
 * honest pending reason; none emit fabricated numbers. Swap a stub for a real
 * `Retriever` implementation (runnable:true) to measure it on the gold set.
 */
export function listCompetitors(): CompetitorRegistration[] {
  return [
    {
      retriever: new StubCompetitorRetriever({
        id: 'langchain-openai-tool-retriever',
        label: 'LangChain tool retriever (OpenAI text-embedding-3 + FAISS)',
        version: 'stub/pending-vendor',
      }),
      pendingReason:
        'Requires an OpenAI embeddings API call per tool/query; the eval host is air-gapped (no outbound network, no API key). Pending a vendored offline embedding model + index before it can run on the shared gold set.',
    },
    {
      retriever: new StubCompetitorRetriever({
        id: 'mcp-gateway-keyword-router',
        label: 'Generic MCP gateway keyword router (named third-party gateway)',
        version: 'stub/pending-vendor',
      }),
      pendingReason:
        'No license-clean, locally runnable build of the third-party gateway is vendored in this repo. Pending a vendored offline binary/adapter implementing the Retriever interface.',
    },
    {
      retriever: new StubCompetitorRetriever({
        id: 'toolbench-bm25-baseline',
        label: 'OSS ToolBench-style BM25 tool-retrieval baseline',
        version: 'stub/pending-vendor',
      }),
      pendingReason:
        'License-clean OSS baseline not yet vendored into the repo. Pending vendoring + a Retriever adapter so it can index the same 19k-tool catalog offline.',
    },
    // AWS-native coopetition target (§23 Bedrock AgentCore Gateway as an MCP
    // target; §4.5 named-competitor benchmark). Unlike the stubs above, this
    // is a REAL Retriever implementation (agentcore-retriever.ts) that
    // becomes runnable the moment the operator supplies a live Gateway
    // endpoint + bearer token — no code change, no harness change. Until
    // then it reports itself pending with the exact missing env var names
    // (never a silent skip, never a fabricated number).
    agentCoreCompetitorRegistration(),
  ];
}

function agentCoreCompetitorRegistration(): CompetitorRegistration {
  const retriever = new AgentCoreGatewayRetriever();
  if (retriever.info.runnable) {
    return { retriever };
  }
  const { missing } = readAgentCoreConfig();
  return {
    retriever,
    pendingReason:
      `Amazon Bedrock AgentCore Gateway target is not configured: missing ${missing.join(', ')}. ` +
      `This is a Phase 7 OPERATOR input (AWS account + AgentCore Gateway creation with semantic search ` +
      `enabled + Chariot registered as an MCP target, per CHARIOT-SPEC §23). Set ${AGENTCORE_ENV.GATEWAY_URL} ` +
      `and ${AGENTCORE_ENV.BEARER_TOKEN} (and optionally ${AGENTCORE_ENV.PROTOCOL_VERSION}) to measure this ` +
      'competitor on the shared gold set.',
  };
}
