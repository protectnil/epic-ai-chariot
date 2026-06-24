# Changelog

All notable changes to `@epicai/chariot` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
## 3.1.2 — 2026-06-24

### Security
- Pre-publish leak-scan explicitly enumerates the consolidated
  `docs/product/DEVELOPER_GUIDE.md` and `docs/product/SECURITY.md` shipped
  artifacts (already covered recursively via the `docs/product` directory; now
  named explicitly in the gate).
- MCP `/mcp` (streamable-HTTP): authenticated `chariot_call` now enforces
  per-operation RBAC (deny-by-default) and per-request tenant isolation instead
  of implicit single-user trust; the per-user downstream-credential exchange
  reaches parity with the REST transport. Stdio remains single-user trust.
- Stdio adapters spawn pinned (`pkg@version`) and offline — no runtime
  fetch/exec of unpinned packages.
- Adapter constructors guard against missing configuration.
- `hono` pinned to a patched release (resolves a HIGH advisory).
- `bindHttp` fails fast when shared-bearer and JWT authentication are both
  configured (previously a silent universal-401 condition).

### Reliability
- CLI reads the field-rich adapter registry projection (REST adapters retain
  tool metadata).
- Health emitter covers dispatch-after-load and first-call-success phases.
- git-commit pin contract for `github:`-sourced stdio adapters.
- CLI update-availability notification.
- Search output: correct singular/plural labels, no ANSI escapes on non-TTY
  stdout, and a single de-duplicated implementation.

---
## 3.1.1 — 2026-06-11

Pure-BM25 retrieval, catalog expansion, and supply-chain / release-gate
hardening, plus engine reliability and correctness fixes.

### Added
- **Catalog expansion.** 230 REST adapter modules added; the signed bundle now
  ships **1,797 adapters**. Competitor-routed rows were removed and the catalog
  re-signed.
- **Runtime npm stdio adapter integrity guard.** stdio adapters launched via npm
  are checked against a pinned version + SHA-512 before spawn; unpinned adapters
  fail closed.
- **Dispatch health telemetry.** `ChariotHealthEmitter` writes JSONL
  health-pings for dispatch observability.

### Changed
- **Retrieval is now pure BM25.** The miniCOIL / HybridRetriever / vector-index
  subsystem was removed; routing is BM25-only (real IDF with document-length
  normalization plus deterministic name/brand/phrase pins). No `vector-index.json`
  artifact is shipped or loaded.
- Internal comment cleanup; removed references to deleted credential helpers.

### Fixed
- **Setup pre-warm memory safety.** The STDIO adapter pre-warm now bounds its
  concurrency to available host memory (override via `CHARIOT_WARM_CONCURRENCY`)
  instead of a fixed fan-out, preventing out-of-memory failures on small hosts.
- **Credential state.** `credentialStatus` now carries explicit
  `restDeclared`/`restSatisfied`/`mcpDeclared`/`mcpSatisfied`/`mcpKeys`
  discriminators; routing reads them directly (no fragile reconstruction) and
  `effectiveEnvKeys` is resolved once per adapter. Duplicate missing-key entries
  are de-duplicated when a REST and MCP surface name the same variable.
- **Health output.** `chariot health` distinguishes a credential-free pass from
  a verified-credential pass and flags adapters that pass with no declared
  credentials and no canonical entry.
- **Tool counts.** `chariot health`/setup tool-count display now falls back to
  the MCP tool count for MCP-only adapters instead of reporting `0`.
- **BM25 ranking monotonicity** and **RFC 6749 §5.2** OAuth error-response
  conformance.
- **Stale-tool-name dispatch.** Fail-closed when a tool name is absent from the
  current catalog before MCP dispatch; hardened tool-name anti-fabrication
  messaging.
- **Enterprise HTTP.** `serve --http` enforces license / seat / TLS on the
  `/enterprise/oauth` surface.

### Security
- **Signed release gate.** The deterministic eval-gate attestation is
  Ed25519-signed and verified (hash + signature + run-identity, fail-closed) in
  `prepublishOnly`.
- **Leak-scan coverage.** The pre-publish leak-scan now covers the published
  catalog/bundle and every shipped text artifact, with precompiled patterns and
  explicit denylist precedence.

---
## 3.1.0 — 2026-05-28

### Added
- **Cross-App Access (Identity Assertion Authorization Grant).** Resource
  authorization-server support: RFC 7523 JWT-bearer, RFC 9449 DPoP,
  tenant-from-credential resolution, subject-identifier binding, and replay
  protection.

### Changed
- **Retrieval (Phase 0).** Tool routing is now honest BM25 (real IDF +
  length normalization) with deterministic brand/phrase pins. The precomputed
  vector-index artifact is no longer shipped or loaded; "semantic" retrieval is
  held until the bundled encoder ships in a later release.

---
## 3.0.7 — 2026-05-26

OWASP Top 10 for LLM Applications (2025) coverage hardening. Per-item
evidence map replaces the prior binary "Complies / Not applicable"
table; each row now enumerates the runtime defense, the hard-gate eval,
the property the eval proves, and the property the eval explicitly does
NOT prove. Four new hard-gate evals close the items flagged WEAK or
NOT-VERIFIED by independent adversarial review (2026-05-26).

### Added

- **`test/ai-evals/54-supply-chain-provenance.mjs`** (LLM03). Asserts
  `package.json` `prepublishOnly` carries the six required gate lines
  (`npm audit --omit=dev --audit-level=high`, leak-scan,
  manifest-coverage verifier, catalog-signature verifier, vector-index
  verifier, `npm test`), `.github/workflows/release.yml` disables npm
  provenance (`NPM_CONFIG_PROVENANCE: 'false'`), the native binding
  loader at `src/license/binding.ts` has zero bare-npm imports, the
  compiled binary loads with a valid SHA-256 hash, and the new
  `scripts/verify-dependency-provenance.mjs` script verifies each of
  the 12 runtime `dependencies` entries against `package-lock.json`
  for registry-resolved https source + valid sha512 integrity.
  Eval: 11/11 pass, 100% gate.

- **`test/ai-evals/55-rbac-native-per-tool.mjs`** (LLM06). Exercises
  the native `checkAccess()` binding directly (no mocks): allows
  group-mapped adapters, denies unmapped adapters, hard-rejects
  cross-tenant mappings, and asserts `RBAC_OPERATION_DENIED` payload
  shape on the TypeScript `resolveRbacDecision()` path. Closes the
  previously-skipped per-operation grant property on `28-rbac-fuzz.mjs`.
  Eval: 11/11 pass, 100% gate.

- **`test/ai-evals/56-system-prompt-leakage.mjs`** (LLM07). Injects
  four attacker fragments (instruction-override, role-override,
  identity-swap, secret-extraction) plus a fence-escape
  `</DATA_CONTEXT>` close-tag into persona / constraints / memory /
  retrieval / tool-result, runs a full `execute()` loop, and asserts
  every fragment is stripped from both planner and synthesis prompts
  and that the closing-fence tag count stays at the legitimate-wrapper
  count. Eval: 13/13 pass, 100% gate.

- **`test/ai-evals/57-factuality-tool-attribution.mjs`** (LLM09).
  Exercises the new `source-attribution` event emission and the
  `Sources:` narrative-text citation suffix. Asserts synthesis prompt
  carries `[server/tool]` provenance and the `<TOOL_RESULT>` payload;
  orchestrator emits a `source-attribution` event when tools were
  called; final narrative includes citation markers. Sixth case
  added in 3.0.7: empty-synthesis content-filter end-to-end driver
  asserting `no-narrative` event emission with derived reason +
  preserved sources.
  Eval: 6/6 pass, 100% gate.

- **DLP federation chokepoint** (LLM02 PII + credential coverage).
  `DlpInspector` (`src/engine/dlp/Inspector.ts:41`, 14 built-in rules
  including `credit-card` and `ssn-us`) is constructed redact-by-default
  in `src/engine/server/ChariotState.ts:loadChariotState` and invoked
  via the new module-scope helper `applyDlpInspection` in
  `src/engine/server/toolHandlers.ts`, called from
  `extractAndScanMcpTextResult` (stdio/SSE/streamable-HTTP) AND the
  REST inline path BEFORE `applyInjectionScanner` runs. Block →
  synthetic `DLP_BLOCKED` error envelope; redact →
  `[REDACTED-<rule-id>]` markers; allow → pass through. Inspector
  was previously dead code (defined, exported, eval-tested at
  450/450 + 13/13 unit, but zero runtime call sites); 3.0.7 wires it
  into the production tool-call dispatch path. Closes the LLM02
  "PII not redacted in successful response bodies" gap.

- **`no-narrative` StreamEvent** (LLM09 Risk Communication mitigation).
  New discriminated-union variant in `src/engine/types/index.ts`:
  `{ type: 'no-narrative', data: { reason: 'refusal' | 'content-filter'
  | 'token-budget' | 'unknown', sources: { server, tool, toolCallId }[] },
  timestamp }`. Emitted by `Orchestrator.execute()` when
  `toolResults.length > 0` AND synthesis.content is empty. Reason is
  derived from the provider's finishReason. Provider granularity
  preserved in `GeneratorProvider.ts`: OpenAI `content_filter` /
  `length` / `refusal` / `tool_calls` / `stop` and Anthropic
  `max_tokens` / `refusal` / `tool_use` are passed through rather
  than collapsed to binary `stop`/`tool_calls`. `LLMResponse.finishReason`
  union widened to include `'content-filter' | 'refusal'`. RunTelemetry
  `EVENT_TYPES` array and `eventCounts` record updated in lockstep.
  Variant intentionally distinct from `error` so OpenTelemetry span
  semantics stay clean.

- **`scripts/verify-dependency-provenance.mjs`** — new release-gate
  script invoked by eval 54. Per runtime dep, verifies declared spec
  is registry-resolvable (not git/file/http), `node_modules` install
  matches spec, package has a `repository` field, and `package-lock.json`
  carries a valid sha512 integrity for an https-resolved source.
  Writes structured summary to `scripts/.dep-provenance-last.json`.

- **`source-attribution` StreamEvent** (LLM09 defense). New
  discriminated-union variant in `src/engine/types/index.ts`:
  `{ type: 'source-attribution', data: { sources: { server, tool,
  toolCallId }[] }, timestamp }`. Emitted by `Orchestrator.execute()`
  when `toolResults.length > 0`, before the `narrative` event.
  Narrative event's `data` field gains a `sources[]` field
  (always-present; empty array when no tools were called).
  Narrative text gains a `\n\nSources: [server/tool, ...]` suffix
  when tools were called. Anti-hallucination: when no tools were
  called, no `source-attribution` is emitted and no `Sources:` suffix
  is appended.

### Changed

- **`SECURITY_ARCHITECTURE.md` OWASP table restructured.** Replaced
  the binary "Verdict: Complies / Not applicable" column with a
  bounded four-column evidence map: (runtime defense src file:line),
  (hard-gate eval), (what the eval proves), (what the eval does NOT
  prove). Each cell is independently verifiable against on-disk
  files; limitations are stated up-front rather than discovered by
  audit. All 10 rows verified PASS by independent adversarial review.

- **`README.md` OWASP claim narrowed.** Replaced "complies on every
  applicable item" with the per-item evidence-map framing. Links
  directly to the SECURITY_ARCHITECTURE.md anchor.

### Fixed

- **`src/iam/middleware.ts`** build-blocker: SCIM bearer auth path
  referenced undefined `clientIp` at lines 395 + 412 (variable is
  named `clientAddr` at line 371). The typo blocked every `tsc` run
  with `TS2304: Cannot find name 'clientIp'`. Renamed both references
  to `clientAddr`; build returns clean.

- **`test/ai-evals/57-factuality-tool-attribution.mjs:146` filter**
  (round-4 finding #1, HIGH). The eval's "no-tools" branch detection
  filtered `event.type === 'result' && !event.data?.isError`, but
  `Orchestrator.ts:679` pushes to `toolResults` unconditionally and
  emits `source-attribution` regardless of errored status. Errored-only
  runs would have falsely failed the gate. Filter widened to
  `event.type === 'result'` to match orchestrator semantics. Phase-2
  verifier: single consumer in the eval, no other callers.

- **`scripts/verify-dependency-provenance.mjs:201` regex** (round-4
  finding #2, MEDIUM). The prior SRI shape `^(sha384|sha512)-[A-Za-z0-9+/]+={0,2}$`
  accepted any base64 body length — `sha512-AAAA==` would pass. New
  shape `^(sha384-[A-Za-z0-9+/]{64}|sha512-[A-Za-z0-9+/]{86}==)$`
  enforces canonical SRI lengths per W3C SRI / RFC 4648 (sha384 =
  48 bytes → 64 base64 no pad; sha512 = 64 bytes → 86 base64 + `==`).
  Verified against this repo's 95 sha512 lockfile entries (all 95
  chars). 12-case regex unit test confirms forgeries rejected.

- **`src/engine/orchestrator/Orchestrator.ts:758` sanitizeIdentifier
  whitelist** (round-4 finding #3, MEDIUM). The whitelist
  `[a-zA-Z0-9_./-]` stripped `@` from every `@scope/name` adapter ID
  in the bundled catalog (88 such adapters as of this publish).
  Resulting `Sources:` suffix rendered as `[amcharts/amcharts5-mcp/...]`
  rather than `[@amcharts/amcharts5-mcp/...]`. `@` restored.
  `:` deliberately NOT added (R2's mistake); only `@` is on the
  catalog identifier surface today and admitting `:` would open a
  prompt-injection vector through fence-escape.

- **Silent empty-synthesis branch in `src/engine/orchestrator/Orchestrator.ts`**
  (round-4 finding #4, LOW → upgraded to OWASP LLM09 Risk
  Communication mitigation). Previously when toolResults > 0 but
  synthesis.content was empty the orchestrator emitted neither
  `narrative` nor `source-attribution` — consumers could not
  distinguish refusal / content-filter / token-budget-truncation
  from "no answer." A new `no-narrative` StreamEvent variant now
  emits with a `reason` discriminator derived from the provider's
  finishReason and the `sources` of tools that ran. The variant is
  intentionally separate from `error` (which has reserved OpenTelemetry
  span semantics) so OTEL consumers keep working unchanged.

### Notes

- LLM09 retains explicit limitation language in the
  SECURITY_ARCHITECTURE.md table: LLM09 covers tool-call provenance,
  attribution, and Risk Communication for empty-synthesis cases (not
  factual correctness of synthesized prose). LLM02 PII coverage now
  spans the federation chokepoint in addition to the prior credential-
  shape redaction at error-envelope / CLI-stderr boundaries — the
  prior "PII not redacted in successful response bodies" limitation
  is dropped from the LLM02 row.

- The `source-attribution` and `no-narrative` events are additive;
  existing consumers of `narrative` events continue to work because
  the new `sources` field is always present on `narrative.data`
  (empty array when no tools were called). Consumers that switch on
  `event.type` see `no-narrative` as an opaque variant unless they
  opt in. RunTelemetry's `EVENT_TYPES` array and `eventCounts` record
  were extended in lockstep so the new variant is counted.

### Also included in 3.0.7 (catalog-signature recovery + adapter ergonomics, originally drafted 2026-05-23 but not published)

This release also supersedes the broken 3.0.6 publish and lands the
post-3.0.5 fixes that were drafted under the same version number on
2026-05-23 but never reached the npm registry. Those changes are
preserved verbatim below.

### Fixed (catalog-signature recovery + adapter ergonomics)

- **3.0.6 catalog-signature break.** 3.0.6 shipped a signed-but-
  tampered catalog bundle: a prior commit edited
  `chariot-adapter-bundle.json` without re-signing the matching `.sig`
  file. The runtime gate in `src/engine/keys/verifyCatalogSignature.ts`
  rejected the load on every customer install with
  `catalog signature gate failed reason=signature-verification-failed`
  followed by `No adapters matched` on every query. 3.0.7 re-ran the
  catalog materializer and re-signed both `chariot-adapter-bundle.json`
  and `chariot-adapter-catalog.json` together with the production
  catalog-signing key.

- **`chariot query` natural-language arg extraction.** `cmdQuery` now
  fetches each tool's `inputSchema` via `listTools()` and extracts
  arguments from the user's prompt — URL fields get the URL,
  `term`-shaped fields get the stripped query, `query`-shaped fields
  get the raw prompt. Optional LLM path activates when
  `CHARIOT_LLM_PROVIDER`/`CHARIOT_LLM_MODEL`/`CHARIOT_LLM_API_KEY` are
  set or when a local OpenAI-compatible endpoint
  (Ollama 11434 / llama.cpp 8080 / vLLM 8000) answers. Falls back to
  `{query}` when no schema is available, preserving legacy adapter
  behavior.

- **`chariot search` top-hit reranking.** Within each tier (curated,
  configured, available) results now rank by best-name match — exact
  id beats exact name beats `startsWith` beats `contains` — so
  `chariot search slack` puts the `slack` adapter first instead of a
  substring sibling.

- **Brand-token + curated-four phrase pins.** When a curated/configured
  adapter id appears as a whole-word token in the query, the router
  pins that adapter even when BM25 favors another. New semantic phrase
  pins cover `clinical trials` / `biomedical research` → pubmed,
  `whois` / `asn` / `nameservers` / `reverse dns` → dns,
  `paging` / `page the on-call` → rootly.

- **`chariot add` success message + non-interactive guard.** Success
  message now prints the persisted adapter id (with package name
  dimmed) so the customer sees the same identifier
  `chariot remove`/`chariot health` will use. `chariot add <brand>`
  with no credentials under `CHARIOT_NON_INTERACTIVE=1` now exits
  `STDIN_REQUIRED(4)` with a clear message instead of silently
  reporting `configured`.

- **`wayback-machine` adapter packageName.** The bundle now references
  `mcp-wayback-machine` (resolves on the npm registry) instead of the
  prior unresolvable upstream package.

- **`chariot list` no longer leaks the catalog-drop WARN.** The
  `adapter catalog: dropped undispatchable entries at load` log line
  is demoted to `debug` so it no longer surfaces on customer-facing
  CLI output.

- **`PERSONA_ANCHOR` rewritten** so the safety anchor no longer echoes
  the exact attacker literals that the prompt-injection unit tests
  grep for. Closes a regression where every prompt-injection test
  failed by detecting the anchor's own description of the attacks.

- **`chariot resume` works in dev tree** after copying the signed
  native binary + integrity manifest from the matching sibling
  package; customer fresh-install path was always working.

### Added

- **Five fail-closed CI gates** against future catalog-signature
  drift (see `BUNDLE_AUTHORITY.md`):
  1. Pre-commit hook refuses bundle.json commits without paired .sig.
  2. CI validate-job runs the prepublish signature verifier.
  3. `prepublishOnly` runs the same verifier on local `npm publish`.
  4. Bundle/sig lineage parity check catches history desync.
  5. Post-publish customer-flow probe in CI; failure triggers
     automatic `npm deprecate` of the broken version.

- **`test/customer-golden-queries.mjs`** — 18 customer-shaped queries
  + 5 arg-extraction probes that assert *the right answer* rather
  than just *feature appears in output*.

- **`test/external-adversarial-probe.sh`** — probes the published
  tarball in a fresh `/tmp` install with no source-tree visibility.

- **`probeLocalLLM()`** auto-detects local Ollama / llama.cpp / vLLM
  so `chariot query`'s tool-arg extraction works zero-config when a
  local SLM is reachable.

- **Eval runner auto-resolves `CHARIOT_EVAL_ENV_PATH`** so
  `npm run eval:ai` finds judge-LLM credentials without manual setup.

### Changed

- `chariot-adapter-bundle.json` regenerated by the materializer; the
  bundled catalog ships **1,501 integrations** in this release. The
  README now points readers at the bundle file for the authoritative
  count instead of hard-coding it.

- `helium-mcp` temporarily removed from the curated set —
  the entry was advertised in `chariot list` but absent from the
  bundle, so `chariot add helium-mcp` printed `Adapter not found.`
  It returns once the upstream publisher ships the corresponding
  adapter document.

### Deprecated

- **`@epicai/chariot@3.0.6` is DEPRECATED** as of this release. The
  3.0.6 tarball ships a self-inconsistent catalog (bundle edited
  without re-signing) and fails the runtime signature gate on every
  fresh install. All 3.0.6 users should `npm install @epicai/chariot@3.0.7`.

---
## 3.0.5 — 2026-05-22

Patch release closing every release-touched bug.

### Fixed

- **Dispatcher field-name normalization** verified by
  `customer-flow-smoke-eval` + `customer-ux-eval` (real-bundle
  `handleCall` round-trip).
- **Retriever quality filters**: description-quality + tool-description
  cohesion filters; canonical-vendor pin map; high-confidence phrase
  pin map; query expansions covering 12 intent classes.
- **`chariot add` canonical credentialed-brand fail-closed** — closes
  the gap where 0/1501 bundle entries declared `mcp.envKeys` and every
  credentialed brand silently landed at `status=configured`.
- **Setup wizard non-interactive guard** — `npx @epicai/chariot` under
  `CHARIOT_NON_INTERACTIVE=1` now exits `STDIN_REQUIRED(4)` instead of
  hanging on a closed stdin.

### Added

- **End-to-end CLI smoke test** (`test/cli-add-query-smoke.mjs`)
  exercising `add → list → health → query` against the bundled catalog.
- **Non-interactive guard integration tests.**
- **`closure-adversarial.mjs` harness** — 10 probes verifying every
  release-touched bug stays closed under adversarial conditions.

### Eval gates

- eval-01 routing reaches 100% top-1.
- eval-22 refusal fuzz at 200/200 per property × 3 properties.
- eval-06 multi-turn classifier wired into per-turn loop, 8/8 DEFENDED.

### Release notes

- Publication-gate cohesion enforcement was added on the publisher
  side (sibling repo); this version is the first chariot release to
  consume the cohesion-enforced bundle.

---
## 3.0.4 — 2026-05-21

Patch release iterating on the 3.0.3 orphan-root publication.

### Fixed

- Multiple retriever-quality regressions surfaced after the orphan-root
  cut: ethora removed from quality whitelist, canonical-brand adapters
  whitelisted from the description-quality filter, description-
  quality-disqualified adapters excluded from the routing index.
- DAN classifier catches temporal-displacement and grandmother-roleplay
  framings; rot13 classifier accepts punctuation in letter-runs and
  has a whole-message fallback.
- Bundle: `decern-crm` renamed to `spacemolt` (id ↔ content cohesion
  fix).

---
## 3.0.3 — 2026-05-21

Orphan-root publication after the April 2026 leak-scrub incident.

### Security

- Repository history rewritten to an orphan-root commit to expunge the
  97 leak findings from the pre-scrub branch (proprietary product
  mechanism, internal infrastructure paths, hardcoded production
  Redis credential). All historical tags and GitHub releases prior to
  3.0.3 were deleted; npm versions in the 2.x line plus the old native
  sibling packages were unpublished. Three-layer leak gate (local
  pre-commit, CI `pull_request_target` denylist check, harness
  `PreToolUse` hook) is now enforced on every commit.

---
## 3.0.2 — 2026-05-20

Patch release with native sibling rename and security scrub.

### Security

- **Prompt-injection mid-line detector widened** (`src/engine/persona/injection-defense.ts`). The `you are` and `act as` continuation alternations in `INJECTION_PATTERNS` and `INJECTION_MIDLINE_RE` now include `[a-z0-9]{2,}(?:gpt|ai|bot|assistant|claude|chatgpt)\b` so canonical mid-line persona-rename jailbreaks ("please act as AdminGPT", "please you are AdminGPT", "you are ChatGPT now") are flagged. The `{2,}` prefix requirement keeps short tokens like standalone "AI" from false-positiving "you are AI literate" while still catching "AdminGPT", "ChatGPT", "ClaudeAI", "EvilBot".

### Breaking changes

- **Native sibling packages renamed.** The four platform-specific native binding packages have moved from `@epicai/chariot-{linux-x64-gnu,darwin-arm64,darwin-x64,win32-x64-msvc}` to `@epicai/chariot-bin-{linux-x64-gnu,darwin-arm64,darwin-x64,win32-x64-msvc}`. `@epicai/chariot`'s `optionalDependencies` and the runtime native-binding loader (`src/license/binding.ts`) have been updated to match. Customers who install `@epicai/chariot@3.0.2` get the renamed siblings automatically via npm's optional-dep resolution; no customer-side config change is needed. The old sibling names have been unpublished from npm during the v3.0.2 scrub.

### Fixed

- **`engines.node` floor raised to `>=22.13.0`.** `node:sqlite` (used by the federation, audit, and recovery layers) only leaves `--experimental-sqlite` in Node 22.13.0 / 23.4.0; the prior `>=22.5.0` floor admitted versions where the import throws `ERR_UNKNOWN_BUILTIN_MODULE` at module load.
- **Praetor branding scrubbed from public artifact.** Three legacy `Praetor` references in `dist/engine/observability/EventEmitter.{d.ts,js}` and `dist/engine/types/index.d.ts` were rewritten to "a webhook, queue, or external approval system". Source updated; dist regenerated.
- **CHARIOT-SPEC license JWT claims table** (`docs/CHARIOT-SPEC.md` §5.2) now lists `tenant_id` as an optional claim, closing a documentation drift versus the issuance code path.

### Changed

- CI runner pinned to Node 22.13.0 to match the new `engines.node` floor.
- Workflow opts JavaScript-based GitHub Actions onto the runner's Node 24 via `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`.

### Release notes

- The old `@epicai/legion` companion package has been **fully removed from npm**. All Intelligent Virtual Assistant (IVA) MCP gateway functionality lives in `@epicai/chariot`.
- `@epicai/core` is now a clean redirect-stub at version `1.0.4`; older `1.0.x` versions have been unpublished.
- `@epicai/chariot@2.0.0`, `2.1.0`, `2.1.1` and the old native sibling packages at `2.0.0`/`3.0.0` have been unpublished. Tombstone `@epicai/chariot@2.1.2` exists temporarily to clear the dependency graph and is removed when `3.0.2` propagates.
- `3.0.0` and `3.0.1` were never general-availability cuts; `3.0.2` is the first GA release of the renamed sibling layout.

### Security-review approvals

- BUG-XXX (injection-defense): thread `<id>` APPROVED
- BUG-XXX (epic-ai env guard): thread `<id>` APPROVED
- BUG-XXX (publish artifact): thread `<id>` APPROVED post-scrub
- BUG-XXX (spec sync): thread `<id>` APPROVED
- BUG-XXX (push chain): thread `<id>` APPROVED with conditions

---
## 3.0.0 — 2026-05-14

Epic AI® Chariot 3.0.0 is a fully self-contained, proprietary enterprise IVA MCP gateway. The package no longer depends on any external Epic AI® package. The MCP routing engine, adapter catalog, federation layer, and all tooling ship bundled inside `@epicai/chariot`. The entire package is licensed under Elastic License 2.0.

### Highlights — what's new since 2.x

- **Self-contained engine.** The previously-separate routing engine has been forked into `src/engine/` and ships inside `@epicai/chariot`. No second npm dependency, no second registry pull, no source mismatch between what is reviewed and what is loaded at runtime.
- **One license for the whole product.** Both layers — the TypeScript engine and the compiled Rust native binary — are now Elastic License 2.0. There is no split-license model. Source for the TypeScript engine ships in the published package and can be read before installation.
- **Live customer breakage in 2.1.1 resolved.** The native binary's accept-list now includes the current production license-signing public key. Customers on `@epicai/chariot@2.1.1` have been unable to validate licenses signed after 2026-04-30; upgrading to 3.0.0 restores validation. Tracked as [CHARIOT-2026-002](docs/product/SECURITY.md#chariot-2026-002--300-license-signing-key-rotation-2026-04-30).
- **IdP-asserted MFA detection.** When the upstream IdP performed MFA, Chariot no longer forces a second TOTP enrollment. SAML callbacks inspect `<saml:AuthnContextClassRef>` against the OASIS multi-factor allow-list and Microsoft's `multipleauthn` extension; OIDC callbacks inspect the `amr` claim per RFC 8176. The audit log captures `idpAssertedMfa` and the raw signal for compliance review.
- **SSE adapter transport, fully supported.** Adapters configured with `transport: "sse"` are routed via `SSEClientTransport`. Streamable-HTTP transport URL resolution correctly falls back from `adapter.mcp.serverUrl` to `adapter.mcp.url` when the former is absent.
- **Full platform integrity coverage.** The signed integrity manifest now covers `linux-x64`, `darwin-x64`, `darwin-arm64`, and `win32-x64`. Prior releases shipped a Linux-only manifest, which caused the integrity check to fail closed on macOS and Windows and silently degrade to single-user mode. The manifest is generated at release-time by the CI `sign-manifest` job (not VCS-tracked).
- **Reproducible release pipeline.** Tag-driven 6-job GitHub Actions pipeline (`validate → build × 4 platforms → sign-manifest → publish-siblings × 4 → publish-main → release`). Rust toolchain is pinned via `rust-toolchain.toml`. Each per-platform sibling package ships its own copy of the signed manifest. The release workflow publishes with plain `npm publish --access public`; provenance is explicitly disabled in CI so the token-based publish path stays deterministic.
- **Hardened token surface.** Per-user epoch closes a legacy-token gap, monotonic per-user revocation version eliminates same-millisecond races, and the `/refresh` post-issuance epoch re-check closes a TOCTOU window. `revokeAllTenantSessions` immediately invalidates every active session in the affected tenant via Redis-backed epoch.
- **Anti-rollback license enforcement.** A signed envelope with an older `license_epoch` than the on-disk floor (`~/.epic-ai/state/license_epoch`) is rejected, blocking signed-but-stale rollback. `renew-now` flushes the new epoch to disk immediately so the floor advances without waiting for the next validate cycle.
- **Input-validation hardening.** `chariot_query`, `chariot_call`, and `chariot_list` string fields are capped at `MAX_ARG_LEN = 256` characters. `chariot_call.args` is bounded by a `MAX_ARG_PAYLOAD_BYTES = 65_536` (64 KiB) total-payload cap measured in actual UTF-8 bytes via `Buffer.byteLength`, with iterative-depth (`MAX_ARG_DEPTH = 32`) rejection running before any serialization so a recursive stringify cannot stack-overflow on attacker input.
- **Local-LLM probe correctness.** The setup wizard's `/v1/models` probe validates both `application/json` content-type and response body shape (`data[]` or `models[]`) before reporting a local LLM as detected. A 2-second abort timer covers fetch + body parse via a `finally` block so a service that stalls its body stream cannot hang detection.
- **Search precision.** `chariot search` matches `id`, `name`, and `category` fields against the full term, and matches `description` only against its first 120 characters (the summary sentence). This eliminates false positives where a query like `stripe` previously surfaced unrelated adapters that mentioned a third-party service deep in their verbose description body.
- **AI eval suite reliability.** The shared eval harness now terminates the process explicitly on pass (`process.exit(0)`) so in-process Redis/Mongo stub timers cannot hold the event loop open after the gate verdict. Eval 13 (RBAC red-team) had been timing out indefinitely on this issue.

### Breaking Changes

- **MCP tool names.** The three gateway tools are `chariot_query`, `chariot_call`, and `chariot_list`. Update any MCP client configurations referencing the prior tool names. Calling a removed tool name returns `TOOL_NOT_REGISTERED`.
- **Environment variables.** All configuration env vars are prefixed `CHARIOT_*` (e.g. `CHARIOT_TENANT_ID`, `CHARIOT_REST_TOKEN`, `CHARIOT_ADAPTER_CATALOG_PATH`, `CHARIOT_MCP_REGISTRY_PATH`, `CHARIOT_LICENSE_URL`, `CHARIOT_LICENSE_SIGNING_KEY_PATH`, `CHARIOT_LICENSE_SIGNING_KID`, `CHARIOT_AUDIT_SIGNING_KEY`, `CHARIOT_CHAIN_ID`, `CHARIOT_TSA_URL`, `CHARIOT_REVOCATION_LIST_PATH`, `CHARIOT_ENTERPRISE`). Prior prefixes are no longer read.
- **MCP server identity.** `serverInfo.name` is `epic-ai-chariot`. AI clients that matched on the prior identity string must update their config-file entry.
- **License model.** The entire package — TypeScript engine and Rust binary — is Elastic License 2.0. There is no separately licensed Apache 2.0 component. The previously open-source engine has been forked into the package under ELv2.
- **SDK API rename (deprecated, not removed).** `chariotLegionOverrideEnv` and `applyChariotLegionOverrides` are deprecated aliases of `chariotCatalogEnv` and `applyChariotCatalogEnv`. The aliases will be removed in 4.0.0.
- **Integrity manifest source.** `native/integrity.json` is no longer VCS-tracked. The CI `sign-manifest` job generates and signs it against all four platform binaries during the release pipeline. Building from source for development purposes works without the manifest present; production deployments must use the published artifact, not a local rebuild, to retain integrity verification.

### Added (detailed)

- IdP-asserted MFA detection (SAML `AuthnContextClassRef`, OIDC `amr`).
- SSE adapter transport via `SSEClientTransport`.
- Full platform integrity manifest coverage (linux-x64, darwin-x64, darwin-arm64, win32-x64).
- `MAX_ARG_PAYLOAD_BYTES` cap with `ARG_PAYLOAD_TOO_LARGE` error code on `chariot_call`.
- `.max(256)` Zod caps on `chariot_query.query`, `chariot_call.adapter`, `chariot_call.tool`, `chariot_list.category`, `chariot_list.search`.
- CI-fail-loud behavior in license-signing tests when `CHARIOT_LICENSE_SIGNING_KEY_PATH` or `CHARIOT_LICENSE_SIGNING_KID` are unset. Local dev still SKIPs silently.
- Regression test file `test/external-review-regressions.mjs` covering: detectSystem abort-timer body-parse coverage, detectSystem body-shape validation, `renewNow` destPath path-guard, payload byte-count vs codepoint-count, depth-before-stringify ordering.

### Fixed (detailed)

- **License signing key rotation accept-list.** Native binary now accepts the post-2026-04-30 production key in addition to the pre-rotation key. Previously every 2.1.1 customer's license validation failed silently.
- **Default renew URL.** `chariot license renew-now` defaults to `https://epic-ai.io/api/license/renew`. The prior default `https://license.epic-ai.io/renew` 404s.
- **License renew epoch flush.** `renewNow()` calls `revalidateLicense()` after writing the new envelope when `destPath` equals the default `licenseFilePath()`, persisting the new `license_epoch` to disk immediately. Anti-rollback comparison no longer reads stale epoch during the 60s validate-cache window.
- **AI eval-13 hang.** Eval harness `reporter.finish()` now calls `process.exit(0)` on pass. Previously, in-process Redis stub `setTimeout` callbacks (session-token EX timers scheduling abort callbacks 8 hours in the future) kept the event loop alive after the gate verdict.
- **External-review hardening (round 1 + round 2).** Abort-timer moved into a `finally` block on `detectSystem` so the 2-second budget covers fetch and body parse together. Argument-payload depth guard reordered to run before any `JSON.stringify`. Payload-size cap measured in UTF-8 bytes via `Buffer.byteLength('utf8')` rather than UTF-16 code units. Cycles, BigInt, and other unstringifiable inputs reject as oversized.
- **MCP adapter idiomatic refactor.** Chained ternaries in `clio`, `ljaero-dflight`, `pandascore`, and `uspto` adapters replaced with explicit if/return guards and a static page-key map. Behavior identical, intent clearer at the call site.
- **Token revocation hardening.** Per-user epoch closes the legacy-token gap. Monotonic per-user revocation version eliminates same-millisecond races. The `/refresh` post-issuance epoch re-check closes the TOCTOU race window.
- **`streamable-http` adapter URL resolution.** Transport now correctly resolves `adapter.mcp.serverUrl` with `adapter.mcp.url` as fallback.

### Notes

- Earlier 2.x versions are deprecated. Upgrade by pinning `@epicai/chariot` to `^3.0.0` and re-running your install. No 1.x line was ever published.
- A GitHub Security Advisory documents a credential-scoped finding that affected versions prior to 2.0.0. A second advisory ([CHARIOT-2026-002](docs/product/SECURITY.md#chariot-2026-002--300-license-signing-key-rotation-2026-04-30)) covers the 2.1.1 license-validation regression resolved here.
- Six known eval-suite findings are filed for 3.1.0+ scheduling: LLM tool-routing ambiguity on synonymous incident-platforms, golden-trace baseline regeneration after adapter catalog category drift, canonical-JSON `__proto__` key edge case found by fuzz, adapter-execution surface — adapter sandboxing on the roadmap, mitigations in place via three-tier autonomy + RBAC + audit, LLM-side refusal jailbreak grammar — industry-wide LLM limitation, no code-side primitive, RBAC group-name case-mix corner found by fuzz, canonical paths verified clean.

### Migration from 2.x

1. **Update tool names in your MCP client config.** Replace any prior gateway tool references with `chariot_query`, `chariot_call`, and `chariot_list`. Other tool names exposed by adapters are unchanged.
2. **Rename environment variables to `CHARIOT_*` prefix.** If you previously set non-`CHARIOT_*` config env vars, the 3.0.0 loader does not read them. Either rename your env-file entries or run `chariot configure` to re-supply them via the credential vault.
3. **Re-pin the dependency.** `npm install @epicai/chariot@^3.0.0`. The package will pull the matching platform-specific binary as an optional dependency.
4. **Re-run the setup wizard if your AI-client MCP entry references the old server identity.** The wizard rewrites the entry to the current identity. AI clients matching on `serverInfo.name` will need to be updated to match `epic-ai-chariot`.
5. **No data migration required.** Tenant state, audit chain, credential vault, license envelope, and RBAC mappings are read-compatible from 2.x and upgraded in place where the schema cascade applies.

---
## 1.1.0 — 2026-04-14

### Security

- **RBAC group→adapter mapping: silent data-loss fix.** Group mappings now
  persist the full `adapterIds: string[]` array instead of silently truncating
  to the first element. Users in groups mapped to multiple adapters previously
  got access to only one. The schema cascade upgrades legacy 1.0.x singular
  `adapterId` documents transparently on read and in place on write, so no
  manual migration is required.

- **OIDC callback rate limiting: bypass closed.** The rate-limit gate on
  `/oidc/callback` now runs before every error branch (missing cookie,
  malformed cookie, CSRF state mismatch, downstream IdP failure) and uses
  the same tenant-resolution fallback chain as the failure recorder. An
  attacker spamming the endpoint with malformed or missing state cookies
  previously accumulated failures without ever tripping the 429 threshold.

- **SAML RelayState open redirect closed.** `isSafeRelayState` validator
  rejects absolute URLs, protocol-relative URLs, whitespace, and control
  characters; only tenant-local relative paths are accepted.

- **OIDC error message leak closed.** Client-facing responses on callback
  failure no longer include the underlying IdP URL, library stack fragment,
  or token response detail. Operator-side logging preserves full context.

- **Audit hash-chain rollback under partial failure.** `audit.log()` now
  rolls back the hash-chain state if the event insert fails after a
  successful chain advance. Previously, a partial failure stranded the
  audit stream in an un-reconcilable state.

### Added

- **SOC 2 rate-limit coverage on all OIDC failure branches.** Every auth
  failure path calls `recordAuthFailureSafe` — absent-cookie spam,
  malformed-cookie spam, and CSRF attempts all accumulate toward the
  15-minute threshold.

- **End-to-end security evals.** `test/security-fix-evals.mjs` runs 28
  assertions across 8 scenarios against real local MongoDB and Redis,
  including the plural-adapterIds RBAC path, cross-group isolation, the
  three-branch middleware privilege guard, legacy 1.0.x document compat,
  the gate/recorder key lockstep on both malformed- and missing-cookie
  attacks, SCIM token persistence, and in-place legacy-doc upgrades.

- **Zod request-body validation** on every admin, adapters, and SCIM
  POST/PUT route.

- **CHARIOT-2026-001 security advisory** entry added to `SECURITY.md`
  describing the five findings, affected versions (1.0.6 and earlier),
  and the upgrade path.

### Changed

- **Type safety pass.** `as any` and `@ts-ignore` escape hatches removed
  from security-critical paths. `Filter<T>` typed MongoDB filters,
  `ObjectId`/`string` narrowed at route boundaries, `unknown`-typed
  `JSON.parse` outputs explicitly narrowed before use.

- **`generateScimTokenForTenant` throws on missing tenant.** Previously
  returned a token that was never persisted when the tenant row did not
  match. The thrown `Error` omits the tenant identifier from the message
  to prevent leakage through naive `err.message` serializers.

- **Legacy group→adapter mapping documents upgraded in place.** Reads
  through `mapping.ts` normalize legacy singular `adapterId` documents
  into the canonical plural shape; writes `$unset` the legacy field in
  the same atomic operation so documents upgrade on their next update.

- **Test harness no longer hardcodes the license signing key path.**
  Every `.mjs` test file that signs a license now reads the PEM path
  from `CHARIOT_LICENSE_SIGNING_KEY_PATH` and skips the signing-dependent
  block gracefully when the variable is unset.

### Migration

Enterprises upgrading from 1.0.6 need no migration script. Existing
`iam_group_adapter_mappings` documents with the legacy singular
`adapterId` field are read correctly and upgraded to `adapterIds: [...]`
on their next write. The legacy field is stripped via `$unset` in the
same atomic update. If you have no active enterprise mappings yet, the
upgrade is a no-op.

### Advisory

Coordinated security advisory CHARIOT-2026-001 covering the five findings
above is published in `SECURITY.md` in the same commit as this release.
Users on 1.0.6 should upgrade to 1.1.0.

---

## 1.0.6 — 2026-04-11

### Fixed
- **`native/package.json` added** — `@napi-rs/cli` v3 requires a
  `package.json` co-located with `Cargo.toml` when the Rust crate lives in
  a subdirectory. Declares `napi.binaryName = "chariot-native"` and the
  four build targets (`x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`,
  `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`) so
  `cd native && napi build --platform --release --target <triple>` resolves
  the napi config correctly. The file is marked `private: true` and is
  never published to npm — it exists only as a build manifest for the
  release workflow.
- **Release workflow** (`.github/workflows/release.yml`) — new 6-job
  matrix pipeline: `validate → build × 4 platforms → sign-manifest →
  publish-sibling × 4 → publish-main → release`. Per-platform native
  binaries are built on their own GitHub-hosted runners
  (`ubuntu-22.04`, `macos-13`, `macos-14`, `windows-2022`), the integrity
  manifest is signed once against all four binaries in `sign-manifest`
  (with a 5-attempt registry-propagation retry for idempotent partial-
  failure retries), and each sibling package ships its own copy of the
  signed manifest so the loader's `binaryDir/integrity.json` check passes
  on every platform without cross-package lookup.
- **Multi-platform integrity manifest** — the release-artifact
  `integrity.json` (generated by the `sign-manifest` job in CI and shipped
  inside the published main and sibling tarballs) now covers `linux-x64`,
  `darwin-x64`, `darwin-arm64`, and `win32-x64`.
  Prior releases shipped a linux-x64-only manifest, which caused the
  signed integrity check to fail closed on macOS and Windows and silently
  degrade Chariot to single-user mode (breaking `chariot discover` and
  every enterprise feature that depends on the native binary).

### Added
- **Catalog event subscriber** — new optional observability producer that consumes a MongoDB change stream of catalog updates and forwards alert-worthy events into the local `ChariotEmitter` instance for downstream alerting. Opt-in via consumer wiring; not enabled by default.
- **Test coverage** — new test exercises the subscriber lifecycle, resume-token persistence, and fail-closed behavior on unsupported MongoDB deployments.

### Notes
- Change streams require a MongoDB replica set or sharded cluster. On
  standalone deployments the subscriber logs `watch_unsupported` and remains
  inactive; Chariot otherwise runs normally. Check `subscriber.isActive()`.
- No runtime behavior changes for existing Chariot features. RBAC, IAM,
  credential vault, license validation, and internal API discovery are
  unchanged.

---
