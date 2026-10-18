# Chariot vs. Amazon Bedrock AgentCore Gateway — retrieval benchmark method

**Governing clause:** `CHARIOT-SPEC.md` §4.5 "Routing eval" (the §1.4 North-Star
proof artifact) and §23 (AWS-native coopetition: Bedrock AgentCore Gateway as
an MCP target). Graph nodes: `CHARIOT::§4.5::5`–`::11`.

This document is the published method half of release-plan row 1.46
("Retrieval benchmark vs AgentCore's Search API"). It describes how the
harness measures Chariot's Tier-1 retrieval and an Amazon Bedrock AgentCore
Gateway's built-in semantic-search tool on the identical query set, so a
"best in class" claim is made only on a reproduced number (§1.4), never
asserted without one.

## 1. What is measured

The existing routing proof-artifact harness at `src/engine/eval/proof/`
(`run-proof.ts`) already implements the §4.5 proof artifact for the Chariot
baseline: it scores a curated, versioned gold set of natural-language queries
against a `Retriever` implementation and reports, per the pluggable
`Retriever` interface (`types.ts`):

| Metric | Where computed | Spec anchor |
|---|---|---|
| Recall@k (macro + micro) | `metrics.ts` `recallAtK` | §4.5::7 |
| Precision@k | `metrics.ts` `precisionAtK` | §4.5::8 |
| Hit-rate@k (`anyHitAtK`) + one-sided 95% Wilson LCB | `metrics.ts` `hitRateWilsonLcb95` (re-exports `GateMetrics.wilsonLowerBound`) | §4.5 release-gate pattern applied to the benchmark |
| MRR@k | `metrics.ts` `reciprocalRank` / `AggregateMetrics.meanReciprocalRank` | requested by row 1.46 |
| NDCG@k (binary relevance, log2 discount) | `metrics.ts` `ndcgAtK` / `AggregateMetrics.meanNdcgAtK` | requested by row 1.46 (added in this change) |
| Determinism (sha-equal candidate set over N runs) | `determinism.ts` | §4.5::9 |
| Tier-1 selection latency p50/p99 | `run-proof.ts` `measureLatency` | §4.5::10 |

All formulas are the standard IR definitions; see the docstrings in
`metrics.ts` for the exact formula each function implements, and
`metrics.test.ts` for known-answer-vector proofs of each (perfect ordering,
worst ordering, empty/boundary-k, ties, duplicate ids).

## 2. The competitor plug point

`src/engine/eval/proof/types.ts`'s `Retriever` interface is the one seam the
harness targets: any implementation of `index(tools)` + `retrieve(query, k)`
is scored identically on the same gold set, with no harness change. This
change adds `AgentCoreGatewayRetriever`
(`src/engine/eval/proof/agentcore-retriever.ts`) as a `kind: 'competitor'`
registration in `listCompetitors()` (`competitors.ts`), alongside the existing
named-competitor stubs.

### 2.1 Request/response contract (verbatim from AWS documentation)

Per
<https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-using-mcp-semantic-search.html>
(fetched 2026-09-05), a gateway with semantic search enabled exposes a
built-in tool `x_amz_bedrock_agentcore_search`, invoked as a standard MCP
`tools/call`:

```
POST /mcp HTTP/1.1
Host: ${GatewayEndpoint}
Accept: application/json, text/event-stream
Content-Type: application/json
Authorization: ${Authorization header}
MCP-Protocol-Version: ${McpProtocolVersion}

{
  "jsonrpc": "2.0",
  "id": "${RequestName}",
  "method": "tools/call",
  "params": {
    "name": "x_amz_bedrock_agentcore_search",
    "arguments": { "query": "${Query}" }
  }
}
```

The cited AWS page states only that the response "returns a list of tools
that are relevant to the query" and shows the result being consumed as a
generic `response.json()` / tool-call result in its code samples — it does
NOT publish a field-level schema for the embedded tool list.

Rather than guess a shape AWS does not document, `agentcore-retriever.ts`'s
`parseSearchResult()` reads the field names the base MCP specification
defines for any `tools/call` result (`CallToolResult`): a `content` array of
content blocks (a `text`-typed block carries `text: string`), and, since MCP
protocol revision 2025-06-18, an optional `structuredContent` field carrying
the tool's structured JSON output directly. Neither of these is an
AgentCore-specific or search-tool-specific contract — they are the generic
MCP result envelope every `tools/call` response uses, and this adapter reads
them **defensively**: it accepts a tool array under `structuredContent`
(bare, or nested one level under a `tools` key) OR a JSON-parseable tool
array inside a `content[]` text block, and throws `AgentCoreGatewayError`
— never silently returning an empty list — when neither shape is present.
An empty candidate set from a parse failure would read as "Chariot beats
AgentCore on every query," which is exactly the fabricated claim §1.4
forbids. Because the search tool's OWN output schema is undocumented by
AWS, this dual-shape parse is the adapter's defensive best effort against
the generic MCP envelope, not a claim that AWS specifies either carrier for
this tool.

Tool names returned by a multi-target gateway are qualified as
`${targetName}___${toolName}` (the gateway's own tool-forwarding naming
convention); `splitAgentCoreToolId()` splits this into the `${server}:${name}`
id space the gold set and Chariot catalog already use, so recall/precision
are computed over a common id space.

## 3. Fail-explicit contract (never a silent skip, never a fabricated number)

`AgentCoreGatewayRetriever` reads two required inputs from the environment,
evaluated fresh on every `run-proof.ts` invocation:

| Env var | Meaning |
|---|---|
| `CHARIOT_AGENTCORE_GATEWAY_URL` | The Gateway's MCP endpoint, from the `CreateGateway` API response |
| `CHARIOT_AGENTCORE_BEARER_TOKEN` | The inbound-auth bearer token for that gateway |
| `CHARIOT_AGENTCORE_MCP_PROTOCOL_VERSION` (optional) | MCP protocol version header; defaults to `2025-11-25` |

- **Unconfigured** (either var absent): `info.runnable = false`.
  `listCompetitors()` records the entry as `status: 'pending'` with a
  `pendingReason` naming the exact missing var(s) and the required operator
  act (see §4). `run-proof.ts`'s `runCompetitors()` never calls `retrieve()`
  on a non-runnable entry — the existing harness contract, unchanged.
- **Configured but the call fails** (network error, non-2xx, unparseable
  body, JSON-RPC error envelope, or an unrecognized response shape):
  `retrieve()` throws `AgentCoreGatewayError` — it is never swallowed into an
  empty/zero result. A caller that bypassed the `runnable` gate (there is
  none in the shipped harness, but the class does not rely on that for
  safety) still cannot silently produce a fabricated number.

This mirrors the fail-explicit pattern already used for infrastructure
preconditions elsewhere in this repo (e.g. `test/verified-catalog-e2e-w14.mjs`'s
header env-var check) and the existing `StubCompetitorRetriever` contract in
`competitors.ts` ("the runner must detect `info.runnable === false` and
record the entry as pending without ever calling it").

## 4. What the operator must supply (Phase 7 — AWS account + Gateway)

The harness above is runnable today against Chariot (the baseline retriever)
and will run against AgentCore Gateway the moment these operator inputs
exist — **no code change, no harness change**:

1. An AWS account with Bedrock AgentCore access in a region that supports
   semantic search (per the AWS doc: `us-east-1`, `us-east-2`, `us-west-2`,
   and 15 other regions listed on the cited doc page).
2. `CreateGateway` with semantic search enabled, and Chariot (or the target
   set being compared) registered as an MCP target on that gateway, per
   CHARIOT-SPEC §23's AWS-native coopetition posture.
3. An inbound-auth bearer token for the gateway (from the configured
   identity provider).
4. Set, on the machine running `run-proof.ts`:
   ```
   CHARIOT_AGENTCORE_GATEWAY_URL=https://<gateway-id>.gateway.bedrock-agentcore.<region>.amazonaws.com
   CHARIOT_AGENTCORE_BEARER_TOKEN=<token>
   ```
5. Run `node dist/engine/eval/proof/run-proof.js`. The emitted
   `routing-proof.v1.json` / `.md` will carry a `status: 'measured'` row for
   `aws-bedrock-agentcore-gateway` with real Recall@k / precision@k /
   hit-rate (+ Wilson LCB) / NDCG / MRR numbers, scored on the identical gold
   set as the Chariot baseline in the same run.

Until then, the artifact's competitor table reports this target as
`pending`, quoting the missing env var names — never a placeholder number.

## 5. Re-running the harness

```
npm run build   # compiles src/ → dist/ (queued; see the repo's single-compile-at-a-time budget)
node dist/engine/eval/proof/run-proof.js
```

Env overrides (unchanged, documented in `run-proof.ts`'s header):
`CHARIOT_PROOF_DETERMINISM_RUNS`, `CHARIOT_PROOF_LATENCY_ITERS`,
`CHARIOT_PROOF_OUT_DIR`, `CHARIOT_GOLD_SET_PATH`,
`CHARIOT_ADAPTER_CATALOG_PATH`.

## 6. Provenance

- AWS AgentCore Gateway semantic-search request/response shape:
  <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-using-mcp-semantic-search.html>
  (fetched via the AWS documentation MCP tool, 2026-09-05; quoted verbatim
  above, not paraphrased from memory).
- CHARIOT-SPEC §4.5 (`CHARIOT-SPEC.md:323`–`:337`) and §23 (AgentCore
  mention at `CHARIOT-SPEC.md:2180`).
- Wilson lower-confidence-bound formula: re-exported from the already-tested
  `src/engine/eval/GateMetrics.ts` `wilsonLowerBound` (one implementation,
  not duplicated).
