# Epic AI® Chariot — Security Architecture

This document is written for enterprise security reviewers, CISOs, and platform engineers evaluating Chariot for production deployment. It states the threat model, explains what each architectural layer protects against, acknowledges the attack surface honestly, and describes the roadmap for areas under active development.

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

---

## OWASP Top 10 for LLM Applications (2025) — Per-Item Evidence Map

**Format note.** This table does NOT claim binary "compliance." It enumerates, per OWASP LLM (2025) item, (1) the runtime defense in source, (2) the hard-gate eval that exercises that defense, (3) the narrow property the eval proves, and (4) the property the eval explicitly does NOT prove. The format is bounded by what evidence exists on disk; reviewers can verify each cell against source. Limitations are stated up-front, not discovered by audit. Adversarial-review-pipeline approved (2026-05-26).

| OWASP Item | Runtime defense (src) | Hard-gate eval | What the eval proves | What the eval does NOT prove |
|---|---|---|---|---|
| **LLM01 Prompt Injection** | `src/engine/resilience/ToolResultInjectionScanner.ts:325`; chokepoint at `src/engine/server/toolHandlers.ts:357` | `test/ai-evals/prompt-injection-tool-result-eval-may-2026/index.mjs` (26 SECTION-headers, including SECTION 23 homoglyph end-to-end driver at line 1399) | The `applyInjectionScanner` wrapper is invoked at the dispatcher chokepoint; the scanner quarantines explicit role-reversal phrases, ChatML token variants, markdown system-fence envelopes, base64 envelopes ≥200 chars, Unicode confusables (Latin↔Cyrillic/Greek map), and homoglyph-substituted "ignore previous instructions" phrasings | Model immunity to all jailbreak phrasings; novel attack patterns outside the 26 covered sections; the eval is per-section assertion-driven, not a single 179-case parametric driver |
| **LLM02 Sensitive Information Disclosure** | Credential vault: `src/iam/crypto.ts:63` (AES-256-GCM + HKDF-SHA256). Cred-shape stripping in error-envelope: `src/engine/server/toolHandlers.ts:536-551` (Bearer / Basic / `sk_`/`pk_`/`rk_`/`tok_` / AKIA / Slack `xox` / PEM block / JWT regex set). CLI-bridge stderr exit: `src/engine/server/toolHandlers.ts:1713` (`redactStderr(stderr, credValues)`). **Federation DLP chokepoint (LLM02 PII + credential coverage):** `src/engine/dlp/Inspector.ts:41` (`DlpInspector`, 14 built-in rules including `credit-card`, `ssn-us`, AWS access-key id/secret, PEM private keys, JWT, GitHub PAT, Stripe secret, generic API key, GCP service-account JSON, Azure connection string, Slack token, Twilio credentials, npm token); inspector constructed redact-by-default in `src/engine/server/ChariotState.ts:loadChariotState`; runtime chokepoint `applyDlpInspection` in `src/engine/server/toolHandlers.ts` invoked from `extractAndScanMcpTextResult` (stdio/SSE/streamable-HTTP) AND the REST inline path BEFORE `applyInjectionScanner` runs. | `test/ai-evals/10-dlp-fpfn.mjs:47`; `test/ai-evals/27-dlp-fuzz.mjs:156`; `test/dlp-inspector.mjs` | Targeted DLP redaction of the listed credential AND PII patterns at the federation chokepoint (every MCP transport + REST), at the tool-error envelope, and at the CLI-bridge stderr exit, with 0% FN / 0.5% FP gate on the regex set. Block / redact / allow decisions are per-tenant configurable. | End-to-end disclosure guarantee across every runtime path; novel credential or PII shapes not in the regex set; downstream LLM provider logging (operator-side); cross-field reconstruction (a secret split across multiple JSON fields) per the eval-10 documented out-of-scope class |
| **LLM03 Supply Chain** | `package.json:52` (`prepublishOnly` script chain); `scripts/verify-dependency-provenance.mjs:3` (per-dep lockfile + integrity check); `src/license/binding.ts` (zero bare-npm imports in the native loader) | `test/ai-evals/54-supply-chain-provenance.mjs:51` | `prepublishOnly` contains npm audit + leak-scan + manifest + signature + test gates; `.github/workflows/release.yml` disables npm provenance; native binding loader has no bare imports; binding loads with valid SHA-256 hash; 12 runtime `dependencies` entries have registry-resolved https source + valid sha512 integrity | Future zero-day in transitive deps; supply-chain attack against the npm registry itself; tampering between npm install and verifier run |
| **LLM04 Data and Model Poisoning** | `src/engine/orchestrator/GeneratorProvider.ts:24+93` (delegation to operator-supplied generator) | N/A — out of scope | N/A — Chariot does not train, fine-tune, or host the LLM. Model-poisoning surface lives with the operator's chosen model provider | N/A |
| **LLM05 Improper Output Handling** | CLI dispatch: `src/engine/server/toolHandlers.ts:1671+1856` (`spawn(...,shell:false)`); arg validation: `src/engine/server/toolHandlers.ts:1614`; size/depth guards: `src/engine/resilience/ResponseSizeGuard.ts:11`, `src/engine/resilience/JsonDepthGuard.ts:11` | `test/ai-evals/30-dos-unit.mjs` U2 (MAX_TOOL_DEPTH=8, line 196), U3 (MAX_TOOL_FANOUT=32), U4 (MAX_RESPONSE_BYTES=1MiB, line 351) | Tool-call depth cap, fanout cap, and response-byte cap each enforced — over-cap inputs rejected, at-cap inputs accepted | Shell-interpolation absence is asserted by source-level inspection of the dispatch helper, not by a separate runtime test; vulnerabilities in operator-supplied adapter code; size caps for non-JSON response shapes |
| **LLM06 Excessive Agency** | Per-call RBAC: `src/engine/server/toolHandlers.ts:901` (`resolveRbacDecision` + `isOperationAllowed`); native adapter-allowlist: `src/license/binding.ts:33` (Rust `checkAccess`) | `test/ai-evals/55-rbac-native-per-tool.mjs:51` | Native `checkAccess` denies cross-tenant + unmapped-adapter requests; `isOperationAllowed` is deny-by-default per (adapter, operation); `resolveRbacDecision` rejects anonymous calls unless `localMode=true`; `RBAC_OPERATION_DENIED` error payload shape | Every transport call site actually invokes `resolveRbacDecision` at dispatch time (gate proves the helper denies correctly; call-site coverage is unit-tested elsewhere) |
| **LLM07 System Prompt Leakage** | Sanitizer: `src/engine/persona/injection-defense.ts:176`; builder: `src/engine/persona/SystemPromptBuilder.ts:15`; orchestrator fence-wrap: `src/engine/orchestrator/Orchestrator.ts:359+687` | `test/ai-evals/56-system-prompt-leakage.mjs:162` | Attacker text injected into persona / constraints / memory / retrieval / tool-result is stripped or fence-wrapped before reaching planner or synthesis context; attacker-injected `</DATA_CONTEXT>` close-tags are stripped (count stays ≤ 1, the legitimate wrapper) | Semantic jailbreak immunity; the LLM will always obey fence semantics; attacks using delimiters other than `<DATA_CONTEXT>` / `<TOOL_RESULT>` |
| **LLM08 Vector and Embedding Weaknesses** | Routing is **BM25-only** (`src/engine/federation/ToolPreFilter.ts`); no `vector-index.json` / embedding artifact is shipped or loaded, so there is no embedding artifact to poison or stale-replay. The former signed-envelope verifier (`VectorIndexVerifier`) and its eval were removed in the 3.1.1 BM25-only excision. | N/A — no vector artifact in this release | With no embedding artifact present, the LLM08 vector/embedding surface (poisoning, stale-replay, malformed-index) has no attack target in this release | Integrity of a vector index in a future release that re-introduces one — that would require re-implementing the signed-envelope verifier and its gate |
| **LLM09 Misinformation** | Orchestrator attribution path: `src/engine/orchestrator/Orchestrator.ts:752+757` (`source-attribution` event emit + `Sources:` suffix + `sources[]` on narrative). **Risk Communication for empty synthesis (OWASP LLM09 mitigation):** `src/engine/orchestrator/Orchestrator.ts` emits a `no-narrative` StreamEvent with `reason: 'refusal' \| 'content-filter' \| 'token-budget' \| 'unknown'` when toolResults > 0 but synthesis.content is empty. Reason is derived from provider finishReason; granular mapping preserved in `src/engine/orchestrator/GeneratorProvider.ts` (OpenAI: content_filter / length / refusal; Anthropic: max_tokens / refusal / tool_use). `NoNarrativeEvent` declared in `src/engine/types/index.ts`; telemetry counted in `src/engine/observability/RunTelemetry.ts`. Variant intentionally distinct from `error` so OpenTelemetry span semantics stay clean. | `test/ai-evals/57-factuality-tool-attribution.mjs` (6/6 cases including the empty-synthesis content-filter end-to-end driver) | When tools are called: synthesis prompt carries `[server/tool]` provenance and `<TOOL_RESULT>` payload; orchestrator emits a `source-attribution` event; narrative text includes citation markers. When tools called but synthesis empty: orchestrator emits a single `no-narrative` event with the derived reason AND the sources of tools that ran; never emits a dangling source-attribution without narrative. Consumers can distinguish refusal / content-filter / token-budget from "no answer." | Factual correctness of synthesized prose; LLM truthfulness; misinformation resistance beyond provenance/attribution; provider finishReason precision (Ollama collapses to `stop` since the API doesn't surface granularity, so Ollama-backed refusals map to `reason: 'unknown'`) |
| **LLM10 Unbounded Consumption** | Per-tenant rate limit: `src/engine/resilience/PerTenantRateLimiter.ts:38`; size/depth: `src/engine/resilience/ResponseSizeGuard.ts:11`, `src/engine/resilience/JsonDepthGuard.ts:11`; token budget: `src/engine/federation/ToolPreFilter.ts:258` | `test/ai-evals/30-dos-unit.mjs:127`; `test/ai-evals/31-dos-fuzz.mjs:323`; `test/ai-evals/35-token-budget.mjs:46` | Per-tenant rate limit enforced at gateway entry; response-size and JSON-depth caps fail closed; token-budget enforced in pre-filter | Budget caps at the LLM provider tier (outside Chariot's control); coordinated multi-tenant DDoS at the operator's network edge |

**How to read this table.** Each row is independently verifiable: open the cited source file at the cited line, open the eval file, run the eval. If a cell in the "proves" column is true, the eval passes; if any "does NOT prove" item matters to your threat model, layer additional controls (pen test, runtime monitor, third-party audit) on top of the Chariot baseline.

**Scope of this evidence.** This is a self-assessment by protectNIL Inc., not a third-party attestation. It does NOT replace: (a) a SOC 2 / ISO 27001 attestation; (b) a third-party pen test against your specific deployment; (c) operator-side controls for items marked N/A or with stated limitations. Counter-examples and bypass research are welcomed via `security@epic-ai.io`; see [SECURITY.md](SECURITY.md).

---

## Threat Model

Chariot is designed to defend against the following threats:

**1. Prompt injection via tool results.** A malicious external service returns a crafted response containing instructions that the LLM treats as legitimate input — redirecting the agent's subsequent actions. Example: a support ticket system returns a response that instructs the agent to exfiltrate credentials to a third-party endpoint.

**2. Supply chain compromise.** A dependency in the open-source adapter layer (npm package, forked adapter) is tampered with or contains malicious code that attempts credential theft, data exfiltration, or unauthorized network calls.

**3. Unauthorized access to tools and data.** A user accesses adapters or calls tools their role does not permit — either through missing auth enforcement, session fixation, or group-mapping bypass.

**4. Credential exfiltration at rest or in transit.** API keys and secrets stored by the credential vault are extracted via direct database access, memory inspection, or a compromised adapter making unauthorized outbound calls.

**5. Audit trail tampering.** An operator or attacker deletes, modifies, or reorders audit log entries to conceal unauthorized activity.

**6. Lateral movement via internal API discovery.** The `chariot discover` feature exposes internal REST/gRPC services as MCP tools. A compromised agent could attempt to reach internal services it was not authorized to access.

**7. License bypass.** A user attempts to exceed their licensed seat count or run enterprise features without a valid license.

---

## Architecture Layers

```
AI Client (Claude, Cursor, etc.)
        │  MCP protocol (stdio)
        ▼
┌─────────────────────────────────────────────┐
│           Chariot MCP Server                │
│  ┌──────────────────────────────────────┐   │
│  │     Rust Native Binary (ELv2)        │   │
│  │  • RBAC enforcement                  │   │
│  │  • Credential vault (AES-256-GCM)    │   │
│  │  • License validation (Ed25519)      │   │
│  │  • Internal API discovery            │   │
│  └──────────────────────────────────────┘   │
│  ┌──────────────────────────────────────┐   │
│  │   TypeScript / Node.js Layer (ELv2)  │   │
│  │  • MCP protocol handling             │   │
│  │  • Routing engine (BM25)             │   │
│  │  • Adapter execution                 │   │
│  │  • IAM routes (SAML, OIDC, SCIM)     │   │
│  │  • Audit trail writes                │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
        │  Outbound calls (per-adapter)
        ▼
  External APIs / Internal Services
```

---

## Layer 1: Rust Native Binary

The Rust binary handles every operation where a compromise would be catastrophic. It is compiled, memory-safe, and signed.

### Why Rust

- **No buffer overflows, no use-after-free, no null pointer dereferences.** Memory safety is enforced at compile time, not by policy.
- **No dynamic evaluation.** There is no equivalent of `eval()` or `require()` at runtime. The binary does exactly what it was compiled to do.
- **No npm dependency tree.** The Rust binary has zero npm dependencies. It cannot be compromised via a malicious npm package.

### What the Rust binary enforces

**RBAC at the tool call level.** When a user authenticates via SSO, their IdP group memberships are resolved to a set of permitted adapter IDs. This mapping is stored and enforced by the Rust binary. Every tool call passes through an RBAC check before the adapter executes. A user in the "Finance" group calling a `kubectl_apply` tool gets a hard rejection — not a soft policy check — because the Rust layer enforces it before the Node.js adapter layer is ever reached.

**Credential vault.** API keys and secrets are encrypted using AES-256-GCM with HKDF-SHA256 per-tenant key derivation. Encryption and decryption are performed exclusively in Rust. The master key and all derived keys exist only in memory — they are never written to disk, never logged, and never passed to the Node.js layer. The Node.js layer receives decrypted credentials only at the moment of use and only for the duration of a single tool call.

**License validation.** Ed25519 signature verification against a compiled-in public key. Fully offline — no license server, no network call. Seat enforcement is applied at session creation time in the Rust layer. Middleware rejects requests that exceed the seat count before any business logic runs.

**Binary integrity.** The Rust binary verifies its own structural integrity at load time. A tampered binary fails the integrity check and Chariot does not start. The integrity manifest covers every security-critical code path.

---

## Layer 2: TypeScript / Node.js

This is the bundled Chariot engine plus Chariot's IAM routes. It handles MCP protocol parsing, tool routing, adapter execution, and IAM flows. The TypeScript source is included in the published package under Elastic License 2.0.

### What this layer does well

- MCP protocol handling is straightforward request/response. There is no persistent state between tool calls.
- Adapter base URLs are fixed at definition time, not derived from user input. A crafted tool call parameter cannot redirect an adapter to an arbitrary URL.
- CLI adapters use `execFile`, not `exec` or `spawn` with `shell: true`. Arguments are passed as structured arrays. Shell metacharacters in parameters are rejected at the schema validation layer before execution.
- IAM routes (SAML, OIDC, SCIM) are source-available under Elastic License 2.0, Zod-validated on every inbound request, and covered by the release-pipeline test suite.

### The honest attack surface

**Adapters execute in Node.js.** Each adapter has network access to its configured endpoint. A compromised adapter — whether through a malicious npm package, a tampered adapter file, or an injected dependency — could make unauthorized outbound calls, log credentials, or exfiltrate data to a third-party endpoint during the window it holds a decrypted credential.

The Rust layer constrains what credentials an adapter receives and enforces RBAC before the adapter runs. But it cannot constrain what the adapter does with those credentials once it has them, because Node.js does not provide a native sandbox.

**Prompt injection is defended at the gateway with semantic content scanning.** Every tool-result content string that the gateway is about to serialize into the prompt transcript runs through the Tool-Result Prompt-Injection Scanner FIRST (see §LLM01 below). The scanner is heuristic, not perfect — semantic NLU is not in scope — but it deterministically catches the canonical injection classes (role-reversal, policy-bypass, obfuscation envelopes) and replaces quarantined content with an attacker-byte-free marker before it reaches model context. Defense against prompt injection is now a layered responsibility: the gateway enforces the deterministic scanner and the audit trail; the LLM provider continues to enforce system-prompt hardening and instruction hierarchy.

### Mitigations in place

- **Integrity manifest.** Adapter files are hash-verified against a signed manifest at startup. A tampered adapter file fails verification and Chariot does not load it.
- **Three-tier autonomy governance.** Tool calls are classified as auto-execute (reads), escalate (writes requiring approval), or blocked (destructive operations). A compromised adapter calling a destructive tool on its own cannot execute it — the governance layer requires explicit operator approval.
- **Full tool-call audit trail.** Every adapter invocation is written to the hash-chained audit trail, including the tool name, parameters (redacted of credential values), response status, and timestamp. The chain is tamper-evident — modification or deletion of any record breaks chain verification.
- **Tool-Result Prompt-Injection Scanner (LLM01).** See §LLM01 below.
- **Vector-Index Integrity Gate (LLM08).** See §LLM08 below.

---

## §LLM01: Tool-Result Prompt-Injection Scanner

Implementation: `src/engine/resilience/ToolResultInjectionScanner.ts`; wiring: `src/engine/server/toolHandlers.ts` (`applyInjectionScanner` + `extractAndScanMcpTextResult` + every adapter-transport return chokepoint). Eval: `test/ai-evals/prompt-injection-tool-result-eval-may-2026/index.mjs` (179 hard gates, 100% pass).

**Three-verdict classifier.** Every tool-result content string is scanned and routed:

- **clean** → pass through unchanged.
- **suspicious** → wrap in a hardening notice with the original content embedded; emit an observability event so operators see the soft signal. The notice instructs the model to disregard any embedded instructions. Currently reserved for the imperative-burst soft signal.
- **quarantine** → REPLACE the content with a deterministic, attacker-byte-free `quarantineMarker(signals)` JSON string; emit observability/audit; the model never sees the original payload.

**Detection layers (single-pass normalize + deterministic regex).**

- **Role-reversal phrase list (17 variants).** `ignore previous instructions`, `disregard the above`, `system: you are now`, `forget your instructions`, `override the system prompt`, `developer mode enabled`, `jailbreak mode`, and 10 more canonical phrasings. Single hit → quarantine.
- **Policy-bypass alternation regex.** Verb + (1–2 determiners) + sensitive object: `reveal/leak/disclose/expose/print/dump/exfiltrate/send/transmit/forward + your/the/all/me/us [+ your/the/all] + system prompt | instructions | secrets | api[-]key | credentials | env`. Plus `execute/run/invoke/call + arbitrary | the following + code/commands/shell`. Plus `transfer/send/wire + funds/money/btc/eth + to`. Plus `base64=…40+chars`. Single combined alternation, single regex pass. Single hit → quarantine.
- **Obfuscation envelopes (all single-hit quarantine).** Markdown system-keyword code fence (terminator relaxed to `\s|$`, no longer needs trailing newline). HTML system-keyword comment. 200+ char base64 envelope with explicit non-word/start/end anchors (catches runs that begin with `+`/`/` and end with `=`/`==` followed by whitespace/EOF). ChatML role tokens (`<|im_start|>`, `<|im_end|>`, `<|im_sep|>`, `<|system|>`, `<|assistant|>`, `<|user|>`, `<|tool|>`, `<|endoftext|>`, `<|fim_prefix|>`, `<|fim_middle|>`, `<|fim_suffix|>`, `<|/im_start|>`).
- **Imperative-burst tail density.** 5+ imperative verbs (`ignore/disregard/forget/override/reveal/leak/disclose/expose/dump/exfiltrate/send/transmit/forward/execute/run/invoke/transfer/wire/jailbreak/bypass`) in the second half of the input (midpoint computed on RAW input length to defeat tag-block padding shift) → suspicious. Verbs are matched against the post-normalize tail so Cyrillic-confusable verbs (`еxecute`) are counted.
- **Unicode normalization (single-pass combined regex + lowercase).** Strip zero-width chars (U+200B/200C/200D/FEFF). Strip bidi-override + isolate chars (U+202A–U+202E, U+2066–U+2069). Strip Unicode Tag block (U+E0000–U+E007F). Apply 21-letter Cyrillic/Greek confusables map (`і → i`, `а → a`, `е → e`, `о → o`, `р → p`, `с → c`, `х → x`, `у → y`, and 13 more, including uppercase). Collapse whitespace to single ASCII space. Lowercase.

**Wiring chokepoint.** `applyInjectionScanner(content, ctx, emit?)` in `src/engine/server/toolHandlers.ts`. Every adapter-transport return path goes through it:

- REST adapter happy path (line ~1337).
- MCP stdio, MCP SSE, MCP streamable-HTTP via the shared `extractAndScanMcpTextResult` helper (3 sites).
- CLI-bridge (8 sites): non-zero exit error envelope, JSON / JSON-RPC / text success, JSON / JSON-RPC parse-fail error envelopes, JSON-RPC error response, spawn-fail catch. `redactStderr()` runs first on success paths (credential-shape redaction), then `applyInjectionScanner` runs (prompt-injection text catch).

A regression-guard eval gate (section 26f) counts `applyInjectionScanner(` call sites in `toolHandlers.ts` and fails if the count drops below the floor (currently ≥ 9 — REST + 3 MCP + 5+ CLI).

**Size guard.** Inputs > `SCAN_LIMIT` (64 KiB) are scanned as head[0..32 KiB+1] + marker + tail[len-32 KiB-1..]; the one-byte overlap closes a previous off-by-one bypass where a payload sized exactly `SCAN_LIMIT+1` could place an injection phrase at the boundary byte and have its first character excluded from the tail scan.

**Immutability of the disposition set.** `HARD_SIGNAL_SET: ReadonlySet<InjectionSignal>` is `Object.freeze`d and its `.add` / `.delete` / `.clear` are non-writable, non-configurable, and throw. A runtime mutation attempt (legitimate code OR injected code) fails loudly instead of silently downgrading a hard signal to "suspicious".

**Documented heuristic limits.** The scanner does NOT auto-decode HTML entities, URL percent-encoding, JS backslash-u escapes, ROT13, or reversed text. These attacks are documented in `r.info` gates as accepted limits because they require the model to decode them server-side, which mainstream LLM tool-result paths do not do. A phrase placed in the discarded middle of a > 2 × `SCAN_HEAD_TAIL` payload is also a documented limit.

---

## §LLM08: Vector-Index Integrity (removed — BM25-only)

**Status (3.1.x):** routing is **BM25-only**. No `vector-index.json` artifact is shipped, loaded, or prepublish-gated — it is absent from `package.json` `files[]` and from the `prepublishOnly` chain, and the former runtime load sites in `ChariotState.ts`, `bin/setup.ts`, and `eval/routing-eval.ts` are reduced to comments. Because no embedding/vector artifact exists in this release, the OWASP LLM08 surface (embedding poisoning, stale-replay, malformed-index) has no attack target.

**Verifier removed.** The signed-envelope verifier (`VectorIndexVerifier.ts`), its record-shape helper (`vector-record-shape.ts`), and the integrity eval (`test/ai-evals/53-vector-index-integrity.mjs`) were removed in the 3.1.1 BM25-only excision. The signing path they shared — `src/engine/keys/verifyCatalogSignature.ts` and `src/engine/keys/artifact-limits.ts` — remains in use for the adapter bundle/catalog (`artifact-limits.ts` still defines a `vectorIndex` byte cap, currently unused).

**Re-introduction.** A future release that ships a vector index must re-implement: (1) the Ed25519 signed-envelope verifier with version binding and record-shape validation; (2) the `files[]` entries for `vector-index.json` + `.sig`; (3) the `prepublishOnly` signature/version/schema guard; and (4) runtime load sites that verify before load and fall back to BM25-only on any failure. Until then, `artifact-limits.ts` retains an unused `vectorIndex` cap and `verifyCatalogSignature.ts` continues to serve the adapter bundle/catalog signing path.

### Roadmap: adapter sandboxing

The architectural solution to the Node.js adapter execution surface is WASM sandboxing. Each adapter compiles to a signed WebAssembly module. The Rust gateway loads and executes WASM modules via an embedded runtime (Wasmtime). The WASM sandbox has no host capabilities by default — network calls, credential access, and result return are explicit host functions that the Rust layer controls. A compromised WASM adapter cannot make unauthorized network calls because the host function for outbound HTTP only permits calls to the adapter's configured base URL.

This is on the roadmap. It is not shipped in the current release. Operators who require adapter-level sandboxing today should consider network-isolation at the deployment layer (see Deployment Guidance below).

---

## Audit Trail

The audit trail records two classes of events:

**IAM events:** `login`, `logout`, `user_created`, `user_deactivated`, `session_revoked`, `adapter_connected`, `credential_stored`, `credential_revoked`, `rbac_updated`, `settings_updated`, `license_validated`, `scim_provision`, `scim_deprovision`.

**Tool call events:** Every MCP tool invocation — adapter name, tool name, requesting user identity, RBAC decision (permitted/denied), execution status (success/error), and response latency. Credential values in parameters are redacted before the record is written. The raw credential is never logged.

**Chain structure:** Each record contains the SHA-256 hash of the previous record. `verifyChain()` recomputes the full chain from the first record and fails immediately on any gap, modification, or deletion. Optimistic-locking writes (CAS) prevent race conditions on concurrent appends.

**Export:** JSON (API), CSV (download). Both formats include the full chain for offline verification.

---

## RBAC in Detail

RBAC maps IdP group memberships to permitted adapter IDs. The check happens at two points:

1. **Session creation.** When a user authenticates via SAML or OIDC, the Rust binary resolves their group memberships to `allowedAdapterIds` and attaches this to the session token.

2. **Tool call time.** When the MCP server receives a tool call request, the Rust middleware checks whether the tool's adapter ID is in the session's `allowedAdapterIds`. If not, the call is rejected with a 403 before the adapter executes. The rejection is written to the audit trail.

This means RBAC is not a filter on the tool list returned to the agent — it is an enforcement gate on every individual tool call. An agent that discovers a tool name through other means cannot call it if the session's RBAC does not permit it.

Tool-level RBAC (restricting specific tools within an adapter, not just the adapter itself) is on the roadmap.

---

## Okta Verification

"Okta-verified" means the IAM module — SAML 2.0, OIDC Authorization Code + PKCE, and SCIM 2.0 — was integration-tested against a live Okta tenant before the 1.0 release. Specifically:

- SAML SP-initiated and IdP-initiated flows with Okta as IdP, including attribute mapping for `email` and `groups`.
- OIDC Authorization Code + PKCE flow with Okta as IdP, including token introspection.
- SCIM 2.0 provisioning and deprovisioning via Okta's SCIM client, including JIT provisioning, user deactivation, and group push.
- Session revocation on SCIM deprovisioning — Okta deprovisions a user, Chariot immediately revokes all active sessions.

This is integration verification, not a formal certification program. Chariot also supports Entra ID, Ping, and any standard SAML 2.0 / OIDC-compliant IdP — Okta is the verified reference implementation.

---

## Deployment Guidance for Security-Conscious Operators

**Network isolation.** Run Chariot in a network segment where outbound calls are restricted to the specific external API endpoints your adapters use. This constrains what a compromised adapter can reach even before WASM sandboxing ships.

**Air-gapped operation.** Chariot makes no vendor outbound connections. License validation, RBAC, and credential operations are fully local. You can verify this by running Chariot in a container with `--network none` — it operates normally for all local operations. External adapter calls only reach destinations you explicitly configure.

**Master key management.** The `ENTERPRISE_MASTER_KEY` environment variable is the root of credential vault security. Rotate it on a schedule consistent with your key management policy. Store it in your secrets manager (Vault, AWS Secrets Manager, etc.), not in a `.env` file on disk.

**Audit trail integration.** Export the audit trail to your SIEM on a schedule. Run `verifyChain()` as part of that export pipeline to detect tampering before the records leave Chariot.

**Adapter allowlist review.** Review the set of adapters connected to your Chariot instance on a regular cadence. Adapters you are not actively using should be removed — they represent unnecessary network access and credential surface.

**Internal API discovery scope.** `chariot discover ./src` should be scoped to approved codebases only. Review the discovered adapter list before approving any service. Admin, internal, debug, and health routes are excluded by default — verify this exclusion is correct for your environment.

---

*Epic AI® is a registered trademark of protectNIL Inc.*
