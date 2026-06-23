# Epic AI® Chariot — Integrator-Facing Specification

**Document:** `CHARIOT-SPEC.md` (public, integrator-facing subset)
**Status:** CURRENT — maintained in sync with private spec
**Date:** 2026-05-11
**Audience:** Customers integrating with Chariot, third-party adapter authors, security reviewers.
**Classification:** PUBLIC — source-available under Elastic License 2.0 (TypeScript engine and compiled Rust binary).
**Trademark notice:** "Epic AI®" is a registered trademark of protectNIL Inc. (U.S. Reg. No. 7,748,019). Chariot is the **Intelligent Virtual Assistant (IVA) MCP gateway** referenced in the trademark filing.

> **Comprehensive internal spec:** A complete implementation-level specification (threat models, internal code paths, procurement evidence map, operational runbook) is maintained privately by protectNIL Inc. This public document is the integrator-facing subset. Internal claims in this document are sourced from the private spec; integrators should treat this document as authoritative for the interface contract.

---

## 1. Overview

Epic AI® Chariot is a self-hosted **Intelligent Virtual Assistant (IVA) MCP gateway**. Delivered as the npm package `@epicai/chariot`, launched with `npx @epicai/chariot`. A single Chariot installation stands between enterprise AI clients (Claude Desktop, Cursor, ChatGPT Enterprise, Codex CLI, custom LLM applications) and an enterprise's own data systems.

Chariot federates a curated set of MCP-capable adapters, governs which adapters each user may invoke, vaults the credentials those adapters need, signs and verifies the adapter catalog, and hash-chains every action into an export-ready audit trail.

**Key properties:**

- **Zero outbound by default.** In air-gapped mode, no data leaves the customer's network. In connected mode, the only outbound destination is `https://epic-ai.io/api/license/renew` (license renewal every 6 hours). No telemetry, no analytics, no inference proxying through Epic AI® infrastructure.
- **Self-hosted.** No Chariot-hosted control plane. Customer query data, audit records, and credential vault contents never leave the customer's network perimeter.
- **Invisible at runtime.** Customers interact with Chariot through their existing AI client. There is no Chariot-branded UI other than the CLI.

---

## 2. Architecture (High-Level)

### 2.1 Two cooperating layers

A Chariot installation has two cooperating layers:

- **TypeScript engine** (Node.js): orchestrator, federation manager, retrieval, tiered-autonomy governance, IAM, observability, and CLI.
- **Compiled Rust binary** (NAPI native module): Ed25519 license validator, AES-256-GCM credential vault with HKDF-SHA256 per-tenant key derivation, RBAC enforcement primitives, OpenAPI/Express internal-API discovery scanners, and integrity manifest verifier.

Both layers ship in a single npm install. The Rust binary ships as four optional-dep sibling packages (`@epicai/chariot-bin-linux-x64-gnu`, `@epicai/chariot-bin-darwin-arm64`, `@epicai/chariot-bin-darwin-x64`, `@epicai/chariot-bin-win32-x64-msvc`); npm selects the correct platform binary.

### 2.2 Deployment topologies

| Topology | Outbound | License renewal | Telemetry |
|---|---|---|---|
| Public-LLM connected | LLM provider + `epic-ai.io/api/license/renew` | Automatic, every 6 hours | None outbound to Epic AI® |
| Hybrid (on-prem LLM, connected license) | `epic-ai.io/api/license/renew` only | Automatic, every 6 hours | None |
| Air-gapped | None | Manual signed-file transfer | None |

### 2.3 Process model

Chariot runs as a single Node.js process. A second optional process — the Inference Gateway (`chariot-gateway`) — handles multi-backend or multi-replica LLM routing. The Inference Gateway speaks the OpenAI Chat Completions API surface and proxies to llama.cpp, vLLM, mlx-lm, Ollama, or any OpenAI-compatible HTTP endpoint.

---

## 3. MCP Transports Supported

Chariot supports the following MCP transport modes for connecting to upstream adapters:

| Transport | Status | Notes |
|---|---|---|
| `stdio` | Supported | Spawns the adapter as a child process; speaks MCP over stdin/stdout. Default for most npm/pip/binary adapters. |
| `streamable-http` | Supported | HTTP-based streaming MCP. Used for HTTP-native adapters. |
| `sse` | Not supported | The `transport: 'sse'` parameter is accepted in the tool surface but errors out at federation dispatch. SSE transport is not implemented at the federation adapter layer. Do not configure adapters with `transport: 'sse'`. |

The inbound MCP surface (between the AI client and Chariot) supports SSE for streaming responses via `SSEWriter`; this is distinct from the federation-layer transport above.

---

## 4. Bundle Envelope Schema

The materialized adapter bundle (`chariot-adapter-bundle.json`) is the authoritative catalog artifact. It is signed with Ed25519 by the upstream catalog publisher on every materialize cycle. Chariot verifies the signature at load and refuses to serve a catalog whose signature fails (empty effective catalog on failure).

### 4.1 Required envelope fields

The root JSON object of `chariot-adapter-bundle.json` MUST contain the following top-level fields. All four fields are covered by the Ed25519 signature; a bundle missing any field is treated as invalid.

| Field | Type | Constraint | Purpose |
|---|---|---|---|
| `catalog` | `AdapterEntry[]` | non-empty array | Ordered adapter list with full schemas, tool definitions, and metadata |
| `registry` | `RegistryEntry[]` | array (may be empty) | Supplemental registry entries for `chariot add` / `chariot health` |
| `epoch` | `number` (Unix ms integer) | MUST be strictly greater than the previously accepted epoch | Replay defense — prevents serving a stale bundle that was captured and re-submitted |
| `catalogVersion` | `number` (non-negative integer) | MUST be ≥ the previously accepted catalogVersion | Downgrade defense — prevents serving an older catalog version after a newer one has been accepted |

### 4.2 Verifier behavior

On successful signature verification, Chariot's `VerifiedCatalog` enforces both monotonic fields before advertising any adapters:

1. **Replay check (epoch):** If `bundle.epoch <= persisted_epoch`, the bundle is rejected. Emits `WARN catalog.epoch_replay_rejected`. Effective catalog becomes empty.
2. **Downgrade check (catalogVersion):** If `bundle.catalogVersion < persisted_catalogVersion`, the bundle is rejected. Emits `WARN catalog.version_downgrade_rejected`. Effective catalog becomes empty.
3. **Atomic persistence:** On acceptance, `{epoch, catalogVersion}` are persisted atomically before the catalog is advertised to any consumer.

### 4.3 VerifiedCatalog state machine

`VerifiedCatalog` exposes three states:

| State | Trigger | Effective catalog |
|---|---|---|
| `verified` | Signature valid, freshness OK, epoch/version monotonic | Full catalog |
| `stale` | Signature valid, catalog age > 7 days from `materializedAt` | Full catalog with WARN log |
| `invalid` | Signature mismatch, missing required fields, epoch/version rejected | Empty catalog |

An `invalid` or `stale` state produces an operator-observable alert via the `ChariotEmitter` event `catalog.signature_failed` or `catalog.stale_warning` respectively.

### 4.4 Publisher requirements (third-party adapter authors)

If you are publishing a bundle for use with Chariot:

- Stamp `epoch = Date.now()` (millisecond resolution) on every publish cycle. If two cycles complete within the same millisecond, use a monotonic counter increment above the first.
- Stamp `catalogVersion` as a non-negative integer that is monotonically non-decreasing across intentional catalog promotions. Never auto-decrement.
- Sign the bundle with an Ed25519 key and provide the corresponding public key to the Chariot operator via a secure out-of-band channel. The operator configures the public key via `CatalogSourceConfig.publicKeyPem`.

### 4.5 AdapterEntry schema — canonical field names

Each element of `catalog[]` is an `AdapterEntry`. The dispatcher reads canonical field names; the catalog publisher publisher historically emitted alias names. Both sets are accepted at the load boundary in `ChariotState.normalizeAdapter()`, which writes the canonical fields if only the alias is present. Downstream consumers MUST read the canonical fields.

| Canonical field | Alias accepted at load | Used by | Required when |
|---|---|---|---|
| `mcp.url` | `mcp.serverUrl` | streamable-http and sse transport dispatch (`toolHandlers.ts`, `setup.ts` query path) | `mcp.transport === 'streamable-http'` or `'sse'` |
| `mcp.command` + `mcp.args` | `mcp.packageName` (synthesized as `command='npx', args=['-y', packageName]`) | stdio transport dispatch | `mcp.transport === 'stdio'` |
| `rest.module` + `rest.className` | (no alias) | in-process REST adapter dispatch | `type === 'rest'` or REST tools present |
| `cli.binary` + `cli.toolSchemas[]` | (no alias) | CLIBridge dispatch | `type === 'cli-bridge'` |

An adapter is **dispatchable** iff at least one of the four canonical shapes resolves after normalization. Entries that fail `isDispatchable()` are dropped at `loadAllAdapters()` time with a single WARN log and never reach the routing index, the configured set, or the customer-visible `chariot list` / `chariot health` output.

The runtime test gate at `test/customer-flow-smoke-eval-may-2026/validate.mjs` asserts both the field-name reconciliation and the dispatchable-after-load invariant against the production bundle. New publishers MUST satisfy this gate; new dispatcher branches MUST extend `isDispatchable`.

---

## 5. License Validation Contract

### 5.1 License file format

The license file at `~/.epic-ai/chariot.license` is a JSON envelope:

```json
{
  "jwt": "<compact EdDSA JWT>",
  "renewal_secret": "<base64url 32 bytes>"
}
```

The JWT is signed with Ed25519 (`alg: "EdDSA"`, `typ: "JWT"`, `kid: <key fingerprint>`). Multi-key rotation is supported: a license signed by an older key continues to verify while a new key propagates.

### 5.2 JWT claims

| Claim | Type | Required by loader | Purpose |
|---|---|---|---|
| `iss` | string | yes | Must equal `"license.epic-ai.io"` |
| `sub` | string | yes | Customer company identifier |
| `exp` | number | yes | Expiry (Unix seconds) |
| `license_epoch` | number ≥ 0 | yes | Anti-rollback counter — monotonic per customer |
| `min_security_epoch` | number ≥ 0 | yes | Catalog floor |
| `seats` | number | no | Seat count; read if present |
| `tier` | string | no | One of: `chariot-trial`, `chariot-starter`, `chariot-10`, `chariot-25`, `chariot-50`, `chariot-100`, `chariot-premium` |
| `sla_tier` | string | no | `none` \| `standard` \| `premium` |
| `topology` | string | no | `public-llm` \| `hybrid` \| `air-gapped`; informational |
| `company_name` | string | no | Display only |
| `jti` | string | no | Unique per JWT; used in renewal proof |
| `tenant_id` | string | no | Runtime tenant identifier. Distinguishes runtime tenant from `sub` (licensee `company_id`) so one licensed company can dispatch from multiple isolated tenants without re-issuing the license. Single-tenant deployments default `tenant_id` to `sub`. |

There is no `aud` claim, no `features` claim, and no `renewal_secret` claim inside the JWT. The `renewal_secret` lives only in the envelope sidecar.

### 5.3 Four loader modes

| Mode | Condition | Effective behavior |
|---|---|---|
| `LICENSED` | Present, valid signature, `now < exp` | Full seats, all features |
| `GRACE` | Present, valid signature, `exp ≤ now ≤ exp + 14d` | Full seats, all features, admin alert |
| `DEGRADED` | Present, `now > exp + 14d`, OR invalid signature | 1 user, single-user features |
| `UNLICENSED` | File absent | 1 user, single-user features (free tier) |

The 14-day grace window is a fixed constant in the binary; the `grace_days` JWT claim is not consulted by the consumer.

### 5.4 Anti-rollback (replay defense)

The license `license_epoch` claim is monotonic per customer. The loader rejects any license whose `license_epoch` is less than the on-disk persisted floor (`~/.epic-ai/state/license_epoch`). The floor advances even for an expired-but-newer license, so it never retreats. This prevents an attacker who holds an older signed license from rolling back to a lower tier.

---

## 6. RBAC Model

### 6.1 Authorization is enforced in code — not by the LLM

Authorization decisions are enforced at the request boundary before any adapter dispatch. The session token's `adapterIds` claim defines the set of adapters the authenticated user is permitted to invoke. An adapter not in `adapterIds` is not dispatched regardless of what the LLM requests.

### 6.2 Per-operation grants (enterprise mode)

In enterprise mode, RBAC is configured via group → adapter mappings (`/enterprise/{tenantId}/admin/group-mappings`). IdP group membership (from SAML assertions or OIDC claims) is mapped to adapter access at session-issue time. The `adapterIds` claim in the session JWT reflects the resolved access set for that user at login time.

Per-operation grant flow:
1. User authenticates via SAML 2.0, OIDC (Authorization Code + PKCE), or local MFA.
2. IAM service resolves the user's IdP groups → adapter mappings → `adapterIds` set.
3. Session JWT is issued with the `adapterIds` claim.
4. On every `chariot_call`, the request-boundary middleware checks the `adapterIds` claim against the requested adapter. Mismatch → `403 Forbidden` before adapter dispatch.

### 6.3 Tiered autonomy — governance on high-impact actions

Every tool call is classified by `TieredAutonomy` into one of three tiers:

| Tier | Behavior | `allowed` |
|---|---|---|
| `auto` | Call proceeds immediately | `true` |
| `escalate` | Call proceeds; enqueued for post-hoc human review | `true` |
| `approve` | Call blocked; enqueued; requires human approval before dispatch | `false` |

Unmatched tools (no policy rule matches) default to `approve` — functionally equivalent to default-deny. The audit record and queue entry are written regardless of tier.

### 6.4 Trust boundary — refusal and code-level defenses

(A comprehensive internal threat-model treatment is maintained privately by protectNIL Inc.)

This subsection clarifies what Chariot enforces in code versus what is delegated to the deployed LLM's model-level training.

**What Chariot enforces in code:**

- **RBAC** — Operations not in the session token's `adapterIds` claim are rejected at the request boundary.
- **Tiered autonomy** — High-impact actions classified as `approve`-tier require explicit human approval before dispatch (enforced in code, not by the LLM).
- **Rate limiting** — Per-adapter token-bucket back-pressure is enforced regardless of the LLM's call pacing.
- **Audit chain** — Every tool dispatch and autonomy decision is hash-chained before execution, creating a tamper-evident record.
- **Content boundaries** — Tool results are wrapped in `<DATA_CONTEXT>...</DATA_CONTEXT>` markers signaling to the LLM that the enclosed content is data, not instructions. DLP egress filters (when configured) redact PII and secret patterns from adapter responses before they reach the LLM.

**What Chariot does NOT enforce in code:**

Chariot does **not** embed a code-level refusal classifier. There is no component that evaluates query intent or tool-call sequences and rejects them on harm grounds. Chariot relies on the deployed LLM's model-level refusal training for query-intent evaluation.

**Trust boundary table:**

| Layer | Chariot enforces | Chariot does not enforce | Implication |
|---|---|---|---|
| Query-intent refusal | — | Deployed LLM's refusal training | Choose an LLM appropriate for your use case |
| Authorization | RBAC at request boundary | — | Users cannot access adapters outside their `adapterIds` grant |
| Rate limits | Token-bucket per adapter | — | LLM's call pacing is not trusted; back-pressure is enforced |
| Data exfiltration | DLP filters (when configured); audit trail | — | PII/secrets can be redacted at adapter-response layer; all dispatch is auditable |

**For high-risk deployments (medical, legal, financial, safety-critical):** Operators MUST verify that the chosen LLM has appropriate refusal training for the target use case. Chariot's code-level defenses (RBAC, tiered autonomy, audit) operate independently of model choice and do not substitute for a well-trained model.

**Comprehensive threat model:** A detailed threat model covering internal code paths, procurement evidence, and operational scenarios is maintained in the private specification. Contact protectNIL support for access.

---

## 7. Catalog Signature Format

### 7.1 Signing algorithm

Ed25519 detached signature. Two artifacts are signed per publish cycle:

- `chariot-adapter-bundle.json` → `chariot-adapter-bundle.json.sig`
- `chariot-adapter-catalog.json` → `chariot-adapter-catalog.json.sig`

Verification: `crypto.verify(null, bundleBytes, publicKeyPem, signatureBytes)` using Node's built-in `crypto` module. The public key set is operator-configurable; the default embedded key is the production root (see §7.2).

### 7.2 Key disclosure

As of 3.0.0 the default embedded acceptance set contains a single production key: `chariot-catalog-prod-2026-05-07`. Bundles distributed with the npm package are signed by the matching production private key, held under the same operator-internal custody discipline as the license-signing key. The previous development key (`chariot-catalog-dev-2026-04-11`) was retired from the acceptance list when the upstream catalog publisher cut over to the production key; no dev-signed catalog remains in the release surface.

Operators who require bring-your-own-trust may override the bundled set via `CatalogSourceConfig.publicKeyPem` (single key) or by supplying an alternate `CHARIOT_CATALOG_PUBLIC_KEYS` ordered list. Contact protectNIL support for the key-distribution procedure.

### 7.3 Multi-key rotation

The verifier supports an array of public keys keyed by `kid`. A catalog signed by any key in the array verifies successfully. This enables zero-downtime key rotation: add the new key to the array, re-sign future bundles with the new key, remove the old key after all in-flight bundles have expired.

---

## 8. Audit Chain

### 8.1 Two hash chains

Chariot operates two distinct SHA-256 hash chains side-by-side. Both are tamper-evident and gap-detecting.

| Chain | Covers | Storage |
|---|---|---|
| IAM chain | Authentication events, provisioning, RBAC mapping changes, admin actions, credential vault operations | `iam_audit_events` collection (enterprise mode); JSONL file (filesystem mode) |
| Engine chain | Tool dispatch, autonomy decisions, federation events, approval-queue actions | `engine_audit_events` collection (enterprise mode); in-memory (single-user mode) |

Hash construction: `SHA-256(previousHash || canonicalizeJSON(record))`. `canonicalizeJSON` sorts keys lexicographically and strips insignificant whitespace so the same record always produces the same hash regardless of insertion-order JSON.

### 8.2 Signing key custody

The IAM chain's trust root is an Ed25519 signing key held under operator key custody.

- The signing key MUST reside in a KMS, HSM, or sealed-store (e.g., AWS KMS, HashiCorp Vault transit engine, PKCS#11 HSM). Plaintext key material MUST NOT be stored on the application host filesystem.
- Loss of the signing key = loss of historical trust. Records signed under a lost key cannot be re-signed after the fact. Key rotation is forward-only.
- Operators MUST treat the signing key with the same security rigor as production database root credentials.

### 8.3 External anchoring — RFC-3161 timestamp

Defense-in-depth against post-compromise re-stitch attacks. Configure via environment variable `CHARIOT_TSA_URL` (no default; anchoring is disabled if unset).

When enabled, Chariot periodically submits RFC-3161 timestamp requests to the configured Timestamp Authority (TSA). The TSA returns a signed timestamp token (`.tsr` file) that binds the current chain head hash to a third-party timestamp. These tokens are stored in `CHARIOT_ANCHOR_STORE_PATH` (default: `~/.epic-ai/audit/anchors/`).

**Effect:** An attacker who re-stitches the chain after key compromise cannot produce `.tsr` files predating the original anchoring events. The fabricated chain's head hashes will not match the stored `.tsr` tokens.

**Verifier API:**

```typescript
verifyAnchor(
  headHash: string,       // SHA-256 hex of the chain record at anchoring time
  anchorPath: string,     // Absolute path to the .tsr file
  tsaCertPem: string      // PEM certificate of the TSA
): Promise<AnchorVerifyResult>

// AnchorVerifyResult: { valid: boolean, anchoredAt: Date, tsaInfo: string, error?: string }
```

Any RFC-3161-compliant TSA is supported (DigiCert, Sectigo, Freetsa, or an internal TSA for air-gapped deployments).

### 8.4 Length attestation — tail-truncation defense

An attacker with write access to the audit store may delete records from the tail of the chain; the signature on earlier records remains valid. Length attestation closes this gap.

Periodically, Chariot signs and publishes a length attestation to a separate append-only store:

```json
{
  "chainId": "<string>",
  "length": "<integer — total record count>",
  "headHash": "<hex SHA-256 of the most-recently-inserted record>",
  "attestedAt": "<ISO8601 UTC>"
}
```

The attestation is signed with the IAM chain signing key. On each audit export or periodic health check, the verifier reconciles the current chain length against the most recent attested length. If `currentLength < attestedLength`, the difference indicates tail truncation — Chariot emits `CRITICAL audit.tail_truncation_detected` and halts the export.

**Verifier API:**

```typescript
verifyLengthAttestation(
  att: LengthAttestation,   // Deserialized attestation including signature
  publicKeyPem: string       // Ed25519 public key to verify the attestation signature
): Promise<AttestationVerifyResult>

// AttestationVerifyResult: { valid: boolean, attestedAt: Date, chainId: string, attestedLength: number, error?: string }
```

### 8.5 Operational cadence (recommended)

Anchor and attest cadences are operator-determined based on Recovery Point Objective (RPO):

| RPO | Recommended cadence |
|---|---|
| 1 hour | Every 500 events OR every 60 minutes, whichever comes first |
| 4 hours | Every 2,000 events OR every 4 hours |
| 24 hours | Every 10,000 events OR every 24 hours |

Environment variables:
- `CHARIOT_ANCHOR_EVENT_INTERVAL` — max events between RFC-3161 anchors
- `CHARIOT_ANCHOR_TIME_INTERVAL_MS` — max ms between anchors
- `CHARIOT_ATTEST_EVENT_INTERVAL` — max events between length attestations
- `CHARIOT_ATTEST_TIME_INTERVAL_MS` — max ms between length attestations

At least one trigger (event count or time interval) MUST be configured for each feature when enabled.

### 8.6 Export formats

The implemented export endpoint is `GET /enterprise/{tenantId}/admin/audit-logs`. Accepts `since`, `until`, `eventType`, and `actor` filters. Returns JSON with streaming response body (large windows do not buffer in memory).

CSV and syslog (RFC 5424) export formats are not implemented. Customers transform JSON client-side or feed it through a downstream forwarder.

---

## 9. Error Codes

The following error categories are emitted by Chariot's observability layer and appear in logs and audit records.

### 9.1 Catalog errors

| Event / code | Cause | Action |
|---|---|---|
| `catalog.signature_failed` | Bundle signature verification failed | Check that the bundle was signed with the key matching the embedded or configured public key. Effective catalog becomes empty until a valid bundle is loaded. |
| `catalog.epoch_replay_rejected` | Bundle `epoch` ≤ persisted epoch | The bundle is stale or is being replayed. The publisher must publish a new bundle with a strictly greater `epoch`. |
| `catalog.version_downgrade_rejected` | Bundle `catalogVersion` < persisted version | The bundle is an older version. Increment `catalogVersion` on publish or restore the current version. |
| `catalog.stale_warning` | Bundle age > 7 days from `materializedAt` | Re-publish the catalog. Effective catalog continues to be served with a warning. |

### 9.2 License errors

| Event / code | Cause | Action |
|---|---|---|
| `license.expired` | JWT `exp` passed; grace window has not started | Renew the license before expiry. |
| `license.grace_entered` | JWT `exp` passed; within 14-day grace window | Renew immediately. All features active during grace. |
| `license.degraded` | Grace window expired or signature invalid | Renew the license. Chariot falls back to single-user free-tier features. |
| `license.renew_failed` | Renewal endpoint unreachable or HMAC proof rejected | Check network access to `https://epic-ai.io/api/license/renew`. In air-gapped mode, install a new signed license file manually. |

### 9.3 Audit errors

| Event / code | Cause | Action |
|---|---|---|
| `audit.gap_detected` | Chain sequence gap (missing record) | Critical alert — notify on all channels simultaneously. Investigate audit store integrity. |
| `audit.tail_truncation_detected` | Current chain length < last attested length | Critical alert. Do not serve the export. Investigate write-access to the audit store. |

### 9.4 Authorization errors

| HTTP status | Cause |
|---|---|
| 401 | Missing or invalid Bearer token |
| 403 | Adapter not in session `adapterIds` claim, OR tenant URL mismatch |
| 429 | Auth rate limit exceeded (15-minute lockout per IP per tenant) |

---

## 10. CLI Commands

The `chariot` CLI is the entry point for `npx @epicai/chariot`. All subcommands:

| Subcommand | Purpose |
|---|---|
| `setup` (alias: `init`, also `chariot` no-arg) | Run the setup wizard (system detection, LLM selection, adapter picker, dependency install, credential configuration, connection verification, config generation). Refuses to run when stdin is not a TTY; exits `STDIN_REQUIRED` (4). |
| `add <adapter>` | Add a single adapter post-setup. In non-interactive mode, credentials must already exist in `~/.epic-ai/.env`; otherwise exits `STDIN_REQUIRED` (4). |
| `remove <adapter>` | Remove an adapter and its credentials. |
| `health` | Scan installed adapters against the live registry; report drift. Enumerates `union(CURATED_IDS, state.adapters)` so curated adapters report status on a fresh install. |
| `list [term]` | List installed adapters (no arg) or search the catalog (with term). Enumerates the same union as `health`. |
| `search <term>` | Search the full bundled catalog by id / name / description / category and print the top 20. |
| `configure` | Interactive credential-import wizard. No non-interactive alternative; exits `STDIN_REQUIRED` (4) when stdin is not a TTY. |
| `discover [path]` | Run the OpenAPI + Express scanner over a directory tree. With `--config <file>` runs non-interactively; otherwise needs a positional path or interactive input. |
| `query <text>` | Route a natural-language query through the BM25 index, pick the top adapter+tool, dispatch it, and print the result. |
| `serve [--http [port]]` | Start the MCP server (stdio default; `--http` for HTTP/SSE). |
| `license activate <file>` | Install a signed license file; validates signature and anti-rollback epoch; writes to `~/.epic-ai/chariot.license` |
| `license status` | Print current license state (mode, seats, expiry, days until grace ends) |
| `license renew-now` | Force an immediate renewal cycle outside the 6-hour interval |
| `audit anchor [--chain-id <id>]` | Anchor the current chain head to the RFC-3161 TSA at `CHARIOT_TSA_URL`. Writes the raw `.tsr` to `~/.epic-ai/audit/anchors/<chainId>-<epoch>.tsr`. Exits non-zero with `TSA_NOT_CONFIGURED` if `CHARIOT_TSA_URL` is unset. Chain ID defaults to the `CHARIOT_CHAIN_ID` env var or `default`. |
| `audit attest [--chain-id <id>]` | Sign a length attestation using the Ed25519 key in `CHARIOT_AUDIT_SIGNING_KEY`. Writes to `~/.epic-ai/audit/length-attestations/<chainId>-<epoch>.json`. |
| `audit verify-anchor <tsrPath> [--cert <pem>] [--chain-id <id>]` | Verify a `.tsr` file embeds the current chain head hash. When `--cert` is supplied the verifier fails closed (`ANCHOR_VERIFY_FAILED`) — CMS signature verification is not yet implemented. |
| `audit verify-length [--chain-id <id>]` | Compare current chain length against all stored length attestations. Exits non-zero with `CHAIN_TRUNCATION_DETECTED` if `currentLength < maxAttestedLength`. |

### 10.1a Non-interactive mode

Any of the following puts the CLI into non-interactive mode:

- The flags `--yes`, `-y`, `--non-interactive`, `--accept-defaults`
- The environment variable `CHARIOT_NON_INTERACTIVE=1`
- `process.stdin.isTTY === false` (stdin piped or redirected)

In non-interactive mode, prompts that have no safe default fail closed: the CLI prints `STDIN_REQUIRED: …` to stderr with a suggested remediation and exits with code `4`. The setup wizard, `configure`, and credential prompts inside `add` follow this rule. Commands with a meaningful non-interactive path (`discover --config <file>`) continue to work normally.

### 10.2 Adapter state machine

`state.adapters[id].status` (in `~/.epic-ai/state.json`) is a string enum:

| Status | Set by | Meaning |
|---|---|---|
| `configured` | `chariot add` when all `envKeys` are present in `~/.epic-ai/.env` (or the adapter requires no creds) | Ready to be dispatched. `chariot health` reports as healthy. |
| `credentials-pending` | `chariot add` when at least one required `envKey` is missing after prompting | Listed in `chariot list`, but `chariot health` reports `missing <key>`. Dispatch will fail-closed. |
| `unhealthy` (reserved) | future automated health probes | Reserved — not yet emitted by the OSS build. |

Curated adapters (`CURATED_IDS`) are always treated as `configured` for health-reporting purposes; they require no credentials and are dispatchable by construction.

### 10.1 MCP tool surface (AI client-facing)

The three tools registered for the AI client are:

| Tool | Args | Purpose |
|---|---|---|
| `chariot_query` | `query: string`, `detail: 'full'|'summary'`, `discover: boolean` | Natural-language search over configured adapters or (with `discover: true`) the full bundled catalog |
| `chariot_call` | `adapter: string`, `tool: string`, `args: Record<string, unknown>` | Execute a tool on a specific adapter |
| `chariot_list` | `category?: string`, `search?: string` | Browse available adapters by category or keyword |

`getTenantId` is process-configured; it is never read from tool arguments (security invariant). Administrative operations (audit queries, RBAC mapping management, force-logout, tenant settings) are accessed via the HTTP admin surface at `/enterprise/{tenantId}/admin/` — not via MCP tools.

---

## 11. Versioning Policy

Chariot has three independent version axes:

| Axis | Description | Breaking change signal |
|---|---|---|
| `package.json` version | npm package version — customer-visible via `npm view @epicai/chariot version` | MAJOR bump on breaking changes to CLI, MCP tool surface, config schema, or license format |
| `native/Cargo.toml` version | Rust binary version. The binary's NAPI ABI is the contract. | MAJOR bump when the NAPI ABI changes in a way that is incompatible with older TypeScript layers |
| `native/integrity.json` version | Cross-platform integrity manifest version | MUST match `package.json` version at publish time; mismatch is a publish blocker |

**Upgrade policy:**

- Minor and patch releases are backward-compatible with the existing license file, credential vault, and audit chain on disk.
- Major releases announce migration steps in the release notes. The anti-rollback epoch (`license_epoch`) and catalog epoch persist across upgrades; they are never reset.
- The `chariot-adapter-bundle.json` format is versioned via `catalogVersion`. Operators who supply custom bundles must increment `catalogVersion` on every structural change.

**Deprecation policy:**

- CLI subcommands removed in a MAJOR release are announced at least one MINOR release in advance with a deprecation warning.
- MCP tool names (`chariot_query`, `chariot_call`, `chariot_list`) are stable across minor releases. Additions are additive and do not break existing AI client configurations.
- License JWT claims are backward-compatible: new optional claims may be added in minor releases; required claims are never removed without a MAJOR version bump.

---

*This document is a scrubbed integrator-facing subset. Internal implementation details, operational infrastructure specifics, and procurement evidence material are in the private comprehensive spec maintained by protectNIL Inc.*
