/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: Amazon Bedrock AgentCore
 * Gateway competitor target (CHARIOT-SPEC §4.5, §1.4 North Star; §23
 * AWS-native coopetition — Chariot registered as an MCP target on AgentCore
 * Gateway).
 *
 * The North-Star "provable against named competitors" axis (§1.4) requires a
 * harness that runs a third-party tool-retrieval baseline on the EXACT same
 * gold set as the Chariot retriever (§4.5 node CHARIOT::§4.5::7/8: "The
 * routing eval benchmark SHALL report Recall@8 [and] precision against named
 * competitor MCP gateways on a shared query suite"). This module is that
 * target for AgentCore Gateway's built-in semantic-search tool
 * (`x_amz_bedrock_agentcore_search`), which returns the tools in a gateway
 * relevant to a natural-language query — the same shape of result Chariot's
 * Tier-1 `ToolPreFilter.select()` returns.
 *
 * Request/response shape is per AWS documentation (verbatim, quoted in the
 * SCOPE record for this work): the gateway accepts a standard MCP
 * `tools/call` POST naming the built-in tool `x_amz_bedrock_agentcore_search`
 * with a single `query` argument —
 *   https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-using-mcp-semantic-search.html
 * — and returns "a list of tools that are relevant to the query" as a
 * standard MCP `CallToolResult` (a `content` array; AWS's doc page does not
 * publish a further-typed schema for the embedded tool list beyond the MCP
 * `Tool` shape (`name`, optional `description`, `inputSchema`), so this
 * adapter parses defensively — see `parseSearchResult` — and NEVER invents a
 * field AWS has not documented).
 *
 * This is an OPERATOR-configured target, not a Chariot component under test:
 * standing up the Gateway, enabling semantic search, and registering Chariot
 * (or any target) as an MCP target is a Phase 7 operator act (AWS account +
 * AgentCore Gateway creation) per the row's OPERATOR half. This module is the
 * BUILDER's half — the harness — and reads the operator-supplied endpoint and
 * credential from the environment, never invents them.
 *
 * FAIL-EXPLICIT CONTRACT (never silent): when `CHARIOT_AGENTCORE_GATEWAY_URL`
 * or `CHARIOT_AGENTCORE_BEARER_TOKEN` is unset, `info.runnable` is `false`
 * and `retrieve()` THROWS a typed, actionable error naming the missing
 * env var — mirroring `verified-catalog-e2e-w14.mjs`'s header env-var-check
 * pattern and `StubCompetitorRetriever`'s "never call retrieve() on a
 * non-runnable stub" contract in `competitors.ts`. The harness (`run-proof.ts`
 * `runCompetitors`) already enforces the "never call retrieve on a
 * non-runnable entry" half of this; this class enforces the other half — a
 * MISCONFIGURED-BUT-ATTEMPTED call (e.g. a future caller that bypasses the
 * runnable gate) fails loudly instead of returning an empty/fabricated result.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { Tool } from '../../types/index.js';
import type { Retriever, RetrieverInfo, RetrievedTool } from './types.js';

/** Env vars the operator supplies once the Gateway + target registration exist. */
export const AGENTCORE_ENV = {
  GATEWAY_URL: 'CHARIOT_AGENTCORE_GATEWAY_URL',
  BEARER_TOKEN: 'CHARIOT_AGENTCORE_BEARER_TOKEN',
  PROTOCOL_VERSION: 'CHARIOT_AGENTCORE_MCP_PROTOCOL_VERSION',
} as const;

const DEFAULT_MCP_PROTOCOL_VERSION = '2025-11-25';
const SEARCH_TOOL_NAME = 'x_amz_bedrock_agentcore_search';

export class AgentCoreNotConfiguredError extends Error {
  constructor(missing: string[]) {
    super(
      `AgentCore Gateway competitor target is not configured: missing env var(s) ${missing.join(', ')}. ` +
        'Set CHARIOT_AGENTCORE_GATEWAY_URL (the Gateway MCP endpoint from CreateGateway) and ' +
        'CHARIOT_AGENTCORE_BEARER_TOKEN (the inbound-auth bearer token) to run this competitor target. ' +
        'This is a required operator input (Phase 7: AWS account + AgentCore Gateway creation + Chariot ' +
        'MCP-target registration) — the harness never fabricates or skips this competitor silently.',
    );
    this.name = 'AgentCoreNotConfiguredError';
  }
}

export class AgentCoreGatewayError extends Error {
  constructor(message: string, readonly status?: number, readonly body?: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'AgentCoreGatewayError';
  }
}

/** Reads the required config from the environment; returns the missing-var list when incomplete. */
export function readAgentCoreConfig(): { gatewayUrl?: string; bearerToken?: string; missing: string[] } {
  const gatewayUrl = process.env[AGENTCORE_ENV.GATEWAY_URL];
  const bearerToken = process.env[AGENTCORE_ENV.BEARER_TOKEN];
  const missing: string[] = [];
  if (!gatewayUrl) missing.push(AGENTCORE_ENV.GATEWAY_URL);
  if (!bearerToken) missing.push(AGENTCORE_ENV.BEARER_TOKEN);
  return { gatewayUrl, bearerToken, missing };
}

/**
 * One MCP tool descriptor as AWS's doc page documents it is returned inside
 * the search result (name is the only field the doc page guarantees; the
 * gateway's tool-naming convention qualifies cross-target names as
 * `${targetName}___${toolName}` — the triple-underscore separator AWS's own
 * gateway-forwarding documentation uses for forwarded tool names).
 */
interface AgentCoreToolDescriptor {
  name: string;
  description?: string;
  [key: string]: unknown;
}

/**
 * Parse the MCP `CallToolResult` content into an ordered tool list. AWS's doc
 * page states the response "returns a list of tools relevant to the query" as
 * a standard MCP tool-call result but does not publish a further-typed schema
 * for the embedded list, so this function accepts the two shapes an MCP
 * `CallToolResult` can carry the data in:
 *   (a) `structuredContent` (or a `content` item's parsed JSON) that is
 *       itself an array of tool descriptors, or an object with a `tools`
 *       array field;
 *   (b) a `content` array whose text items each carry the JSON-serialized
 *       form of (a).
 * Anything else is a parse failure — NEVER silently coerced to an empty list
 * (an empty list would read as "Chariot beats AgentCore on every query",
 * fabricating the exact claim §1.4 forbids without a reproduced number).
 */
export function parseSearchResult(body: unknown): AgentCoreToolDescriptor[] {
  const asToolArray = (v: unknown): AgentCoreToolDescriptor[] | null => {
    if (Array.isArray(v) && v.every((t) => t && typeof t === 'object' && typeof (t as { name?: unknown }).name === 'string')) {
      return v as AgentCoreToolDescriptor[];
    }
    if (v && typeof v === 'object' && Array.isArray((v as { tools?: unknown }).tools)) {
      return asToolArray((v as { tools: unknown }).tools);
    }
    return null;
  };

  if (!body || typeof body !== 'object') {
    throw new AgentCoreGatewayError('AgentCore Gateway response body is not a JSON object; cannot parse tool list.');
  }
  const result = (body as { result?: unknown; error?: unknown }).result;
  if ((body as { error?: unknown }).error) {
    throw new AgentCoreGatewayError(
      `AgentCore Gateway returned a JSON-RPC error: ${JSON.stringify((body as { error: unknown }).error)}`,
    );
  }
  if (!result || typeof result !== 'object') {
    throw new AgentCoreGatewayError('AgentCore Gateway response has no `result` field; cannot parse tool list.');
  }

  const structured = (result as { structuredContent?: unknown }).structuredContent;
  const direct = asToolArray(structured);
  if (direct) return direct;

  const content = (result as { content?: unknown }).content;
  if (Array.isArray(content)) {
    for (const item of content) {
      if (item && typeof item === 'object' && (item as { type?: unknown }).type === 'text' && typeof (item as { text?: unknown }).text === 'string') {
        try {
          const parsed = JSON.parse((item as { text: string }).text);
          const fromText = asToolArray(parsed);
          if (fromText) return fromText;
        } catch {
          // fall through to the next content item; a non-JSON text block is
          // not itself an error — the tool list may live in another item.
        }
      }
    }
  }
  throw new AgentCoreGatewayError(
    'AgentCore Gateway response carried no recognizable tool list (checked result.structuredContent and result.content[].text as JSON); ' +
      'refusing to report an empty/fabricated candidate set.',
  );
}

/** Split an AgentCore-qualified tool name (`${target}___${tool}`) into server/name. */
export function splitAgentCoreToolId(qualifiedName: string): { server: string; name: string; id: string } {
  const sep = '___';
  const idx = qualifiedName.indexOf(sep);
  if (idx === -1) {
    return { server: qualifiedName, name: qualifiedName, id: qualifiedName };
  }
  const server = qualifiedName.slice(0, idx);
  const name = qualifiedName.slice(idx + sep.length);
  return { server, name, id: `${server}:${name}` };
}

export interface AgentCoreRetrieverOptions {
  /** Override the fetch implementation (tests only). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Override the reported version/provenance string. */
  version?: string;
}

/**
 * Competitor `Retriever` adapter for an Amazon Bedrock AgentCore Gateway with
 * semantic search enabled and Chariot (or the compared target set) registered
 * as an MCP target. `info.runnable` reflects LIVE env configuration read at
 * construction time, so `listCompetitors()` (competitors.ts) re-evaluates it
 * fresh on every `run-proof.ts` invocation — no stale "configured" state
 * across a long-lived process.
 */
export class AgentCoreGatewayRetriever implements Retriever {
  readonly info: RetrieverInfo;
  private readonly fetchImpl: typeof fetch;
  private readonly gatewayUrl?: string;
  private readonly bearerToken?: string;
  private readonly protocolVersion: string;
  private readonly missingEnv: string[];
  private indexed = 0;

  constructor(opts: AgentCoreRetrieverOptions = {}) {
    const { gatewayUrl, bearerToken, missing } = readAgentCoreConfig();
    this.gatewayUrl = gatewayUrl;
    this.bearerToken = bearerToken;
    this.missingEnv = missing;
    this.protocolVersion = process.env[AGENTCORE_ENV.PROTOCOL_VERSION] ?? DEFAULT_MCP_PROTOCOL_VERSION;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.info = {
      id: 'aws-bedrock-agentcore-gateway',
      label: 'Amazon Bedrock AgentCore Gateway (x_amz_bedrock_agentcore_search)',
      version: opts.version ?? `agentcore-gateway/mcp-${this.protocolVersion}`,
      kind: 'competitor',
      runnable: missing.length === 0,
      // The Gateway's search response is a bare tool list per AWS's
      // documented shape (name/description/inputSchema) with no numeric
      // relevance score field documented — never fabricate one.
      providesConfidence: false,
    };
  }

  index(tools: Tool[]): void {
    // The Gateway indexes its OWN registered MCP targets server-side (Phase 7
    // operator act — target registration, not a client-side index call). This
    // records the LOCAL catalog size for artifact parity with other
    // retrievers' `size` getter; it does not push tools TO the Gateway.
    this.indexed = tools.length;
  }

  async retrieve(query: string, k: number): Promise<RetrievedTool[]> {
    if (!this.info.runnable || !this.gatewayUrl || !this.bearerToken) {
      throw new AgentCoreNotConfiguredError(this.missingEnv);
    }
    const endpoint = this.gatewayUrl.endsWith('/mcp') ? this.gatewayUrl : `${this.gatewayUrl.replace(/\/$/, '')}/mcp`;
    const payload = {
      jsonrpc: '2.0',
      id: `chariot-proof-${Date.now()}`,
      method: 'tools/call',
      params: {
        name: SEARCH_TOOL_NAME,
        arguments: { query },
      },
    };
    let res: Response;
    try {
      res = await this.fetchImpl(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Authorization: `Bearer ${this.bearerToken}`,
          'MCP-Protocol-Version': this.protocolVersion,
        },
        body: JSON.stringify(payload),
      });
    } catch (err) {
      // Network-level failure (DNS, TLS, connection refused/reset, timeout):
      // fetch() rejects natively here rather than resolving with a Response.
      // Rethrow as AgentCoreGatewayError (never let a native rejection
      // propagate unwrapped) so every failure mode of this method is one of
      // the two typed errors this class documents, per its fail-explicit
      // contract — never a silently-swallowed empty result either way.
      throw new AgentCoreGatewayError(
        `AgentCore Gateway request failed before receiving a response: ${(err as Error).message}`,
        undefined,
        undefined,
        { cause: err },
      );
    }
    const text = await res.text();
    if (!res.ok) {
      throw new AgentCoreGatewayError(
        `AgentCore Gateway request failed: HTTP ${res.status} ${res.statusText}`,
        res.status,
        text,
      );
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch (err) {
      throw new AgentCoreGatewayError(
        `AgentCore Gateway response is not valid JSON: ${(err as Error).message}`,
        res.status,
        text,
      );
    }
    const tools = parseSearchResult(body);
    return tools.slice(0, k).map((t) => {
      const { server, name, id } = splitAgentCoreToolId(t.name);
      return { id, server, name };
    });
  }

  get size(): number {
    return this.indexed;
  }
}
