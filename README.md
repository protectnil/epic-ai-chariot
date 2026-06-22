# Epic AI® Chariot

> ⚠️ **Major version upgrade** — Earlier 2.x versions are deprecated. Please upgrade to **3.1.1**. See [CHANGELOG.md](CHANGELOG.md) for migration details including breaking changes to tool names and environment variables.

**One Intelligent Virtual Assistant. Three deployments. Zero compromises.**

Epic AI® Chariot is an **Intelligent Virtual Assistant (IVA) MCP gateway** that connects the AI your team already uses — Claude Desktop, ChatGPT, Cursor, Codex, VS Code — to your enterprise integrations. Discovers your internal APIs. You choose which ones to connect. One MCP server. 469 tokens. SSO via SAML, OIDC, and SCIM.

**From air-gapped Enterprise download to hyperscaler SaaS — Chariot meets you where you deploy.** Available in `@epicai/chariot@3.1.1`.

```bash
npx @epicai/chariot
```

**Epic AI® Chariot publishes a per-item OWASP Top 10 for LLM Applications (2025) evidence map.** For each of the ten items, the map enumerates: (1) the runtime defense in source, (2) the hard-gate eval that exercises it, (3) the property the eval proves, and (4) the property the eval explicitly does NOT prove. Limitations are stated up-front rather than left for audit to discover. Item LLM04 (Data and Model Poisoning) is out of scope — Chariot does not train, fine-tune, or host the model. Full per-item table with file:line citations in [SECURITY_ARCHITECTURE.md §OWASP Top 10 for LLM Applications (2025)](SECURITY_ARCHITECTURE.md#owasp-top-10-for-llm-applications-2025--per-item-evidence-map). Self-asserted by protectNIL Inc.; adversarial-review-pipeline approved.

---

## Three Deployment Modes — Same Engine, Same Sovereignty

| Mode | Who runs it | Best for |
|------|-------------|----------|
| **Air-gapped Enterprise Download** | Your IT team, inside your perimeter | Regulated, air-gapped, or zero-trust environments. **No vendor SOC 2 audit sits in your data path** — Epic AI® is not a hosted-service operator for this mode. Your own compliance review still applies. |
| **Standalone SaaS** | Hosted by Epic AI® or a delivery partner | Teams that want managed operations without surrendering data sovereignty. Per-tenant credential isolation; operator-held master key never reaches Epic AI®. |
| **Hyperscaler PaaS** | Available through partner cloud channels | Enterprises already standardized on a hyperscaler — integrated IAM, billing, and observability inside the platform you already trust. Channel availability rolls out as partner agreements complete. |

The codebase is the same in every mode. The IAM surface (SAML, OIDC, SCIM 2.0, RBAC), the credential vault (AES-256-GCM with per-tenant HKDF-SHA256 key derivation), the audit chain (SHA-256, append-only, tamper-evident), and the routing engine are identical bit-for-bit across all three. Only the operator boundary changes.

---

## What Is Chariot?

Chariot is an Intelligent Virtual Assistant (IVA) MCP gateway. It understands the intent behind your natural-language requests, accesses third-party sources of information across more than 1,700 bundled integrations (1,797 in this release; the bundled catalog grows on each publish cycle — read `chariot-adapter-bundle.json` for the exact count at any time), and performs the kinds of tasks a live-person assistant would: answering email (`gmail` adapter), scheduling meetings (`google-calendar`), booking travel (`amadeus`), handling phone-and-message workflows (`twilio`, `aircall`), and reaching into industrial systems (`siemens-mindsphere`). Two-tier routing engine (BM25 keyword ranking — real IDF with document-length normalization plus deterministic name/brand/phrase pins — at zero inference cost, then LLM picks from an 8-tool shortlist). Three-tier autonomy governance (auto/escalate/approve). SHA-256 hash-chained audit trail.

One npm package. Two licenses:

- **TypeScript engine (Elastic License 2.0):** MCP server, routing engine, adapters, federation, autonomy, retrieval, persona, audit. Ships compiled (JavaScript + TypeScript type declarations); full source is available under Elastic License 2.0 in the public repository.
- **Compiled binary (Elastic License 2.0):** IAM (SSO, SCIM 2.0, RBAC, credential vault, audit trail) + Internal API Discovery (codebase scan, adapter generation). Compiled Rust via napi-rs. Signed binaries.

## Free Tier

Single user. Full functionality. Connects to your existing IdP out of the box. Inside your zero trust perimeter from minute one. Curated open-data integrations require no API key, no account, and no setup — they are catalog-ready and available to connect out of the box. Live connectivity depends on the upstream service being reachable at runtime.

## Paid Tier — Buy Seats on Your Chariot

The moment your team needs multi-user auth, buy seats. Same Chariot. Same deployment. A signed license file unlocks multi-user mode.

| Pack | Seats | Monthly | Annual (2 months free) |
|------|-------|---------|----------------------|
| **Free** | 1 | $0 | $0 |
| **10-Pack** | 10 | $300/mo | $3,000/yr |
| **25-Pack** | 25 | $600/mo | $6,000/yr |
| **50-Pack** | 50 | $1,000/mo | $10,000/yr |
| **100-Pack** | 100 | $1,800/mo | $18,000/yr |

One Chariot deployment per company. One SSO connection. One RBAC policy. One audit trail. Packs add seat capacity. Adapters are unlimited at every tier.

*Direct pricing above applies to the air-gapped Enterprise Download mode. Standalone SaaS and Hyperscaler PaaS pricing is set by the operator or partner channel and may differ — contact us or your channel partner for details.*

---

## Installation

```bash
npx @epicai/chariot
```

The setup wizard detects your AI client, writes the MCP config, and makes curated open-data integrations available — no credentials required for those adapters. You're running in under 60 seconds.

### Add Adapters

```bash
chariot search <term>        # find adapters by name or keyword
chariot add <adapter-id>     # add one and enter credentials
```

Ask your AI anything across all connected adapters — correlated answer in seconds.

### Discover Internal APIs

```bash
chariot discover ./src
```

Scans your codebase for OpenAPI specs and Express route definitions. You select which services to expose. The AI stops confusing your internal payment service with Stripe.

### Check License

```bash
chariot license
```

### All Commands

```
chariot                            Run setup wizard
chariot serve                      Start MCP server (stdio)
chariot serve --http [port]        Start MCP server (Streamable-HTTP, default port 3550)
chariot query "<question>"         Route a question to your configured adapters
chariot search <term>              Search the bundled adapter catalog
chariot discover [path]            Scan a codebase for internal APIs
chariot discover --rescan          Rescan and show changes
chariot discover --config <file>   Non-interactive discovery from a config file
chariot add <adapter-id>           Add an adapter
chariot remove <adapter-id>        Remove an adapter
chariot list [term]                List configured adapters (term filters)
chariot health                     Check adapter health
chariot configure                  Configure credentials for added adapters
chariot license                    Show license status
chariot audit verify-anchor <tsr>  Verify a .tsr timestamp file against the chain head
chariot audit verify-length        Detect chain truncation from length attestations
chariot help                       Show help
```

---

## Architecture

```
npx @epicai/chariot
    ├── src/engine/ (Elastic License 2.0)
    │   ├── MCP server + routing engine
    │   ├── Adapters (REST + MCP, updated on a rolling basis)
    │   ├── Federation, autonomy, retrieval, persona, audit
    │   └── CLI: add, remove, list, health, serve
    │
    └── Chariot native binary (Elastic License 2.0)
        ├── License validation (Ed25519)
        ├── RBAC enforcement
        ├── Credential vault (AES-256-GCM, HKDF-SHA256)
        └── Internal API Discovery
```

### Start Free, Scale When Ready

Single user. Full functionality. No license file required. When the team needs multi-user auth, buy seats — same deployment, same configuration, a signed license file unlocks multi-user mode.

---

## Trust and Security

**Don't trust us. Docker it. Kill the network. It still works.**

- **Zero egress.** Chariot makes no outbound connections. No license server. No telemetry. Verify it yourself in a network-isolated container.
- **Source-available engine.** The TypeScript engine is source-available under Elastic License 2.0 in the public repository (`github.com/protectnil/epic-ai-chariot`); the npm package ships the compiled engine and TypeScript type declarations.
- **Compiled binary.** The enterprise binary (IAM, RBAC, credential vault, discovery) is compiled Rust via napi-rs. Interface-verified at load time.
- **Credential vault.** AES-256-GCM encryption with per-tenant HKDF-SHA256 key derivation. Master key required at startup — no defaults, no fallbacks.
- **Audit trail.** SHA-256 hash-chained, append-only, tamper-evident. Optimistic-locking writes with full chain verification. Export as JSON, CSV, or syslog.
- **Fail-fast startup.** Enterprise mode validates all secrets (JWT, master key), backing services (MongoDB, Redis), and binary integrity before mounting any routes. Missing or insecure configuration is rejected with an explicit error — Chariot does not limp along in a partially configured state.
- **License enforcement.** Locally enforced via Ed25519 signature verification. Offline validation — no license server. Single-user mode is free and fully functional. Multi-user mode requires a valid license file. The transition is enforced by middleware, not by policy text.
- **Rust memory safety.** No buffer overflows. No use-after-free. No null pointer dereferences.

### Artifacts We Ship

| Artifact | Purpose |
|----------|---------|
| Interface verification | Binary structural integrity check at load time |
| Docker isolation config | Zero-trust proof — air-gapped operation verified |
| Credential vault encryption spec | At-rest data specification (AES-256-GCM + HKDF) |

---

## Enterprise IAM

Chariot's IAM module is Okta-verified and includes:

- **SSO:** SAML 2.0 SP-initiated and IdP-initiated flows. OIDC Authorization Code + PKCE.
- **SCIM 2.0:** Full RFC 7644 compliance. User and group provisioning. JIT provisioning. Deprovisioning with automatic session revocation.
- **RBAC:** Group-to-adapter mappings. Users see only the integrations their role permits.
- **Credential Vault:** Per-tenant key derivation. AES-256-GCM encryption at rest. Per-user and shared (org-wide) credentials.
- **Session Management:** JWT with Redis-backed per-session and per-tenant epoch revocation.
- **Audit Trail:** Hash-chained, tamper-evident, optimistic-locking writes. Full chain verification.

---

## Platform Support

Platform-specific binaries ship as npm optional dependencies:

| Platform | Package |
|----------|---------|
| Linux x64 | `@epicai/chariot-bin-linux-x64-gnu` |
| macOS ARM (Apple Silicon) | `@epicai/chariot-bin-darwin-arm64` |
| macOS Intel | `@epicai/chariot-bin-darwin-x64` |
| Windows x64 | `@epicai/chariot-bin-win32-x64-msvc` |

npm detects your platform and pulls the right binary automatically.

---

## License

- **Elastic License 2.0** — see [LICENSE-ELASTIC](LICENSE-ELASTIC)

---

## Links

- **Website:** [epic-ai.io](https://epic-ai.io)
- **Chariot:** [github.com/protectnil/epic-ai-chariot](https://github.com/protectnil/epic-ai-chariot)
- **Security Architecture:** [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md)
- **Security Policy:** [SECURITY.md](SECURITY.md)
- **Operator — Nondeterminism by design:** [docs/operator/nondeterminism.md](docs/operator/nondeterminism.md)
- **Security email:** security@epic-ai.io
- **Support:** support@epic-ai.io

---

*Epic AI® is a registered trademark of protectNIL Inc.*
*IVA — Intelligent Virtual Assistant*

*Intelligence that acts.*™
