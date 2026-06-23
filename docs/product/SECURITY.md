# Security Policy

Epic AI® Chariot is an Intelligent Virtual Assistant (IVA) MCP gateway distributed as software for deployment by enterprises, lab model operators, hyperscalers, and PaaS providers. **protectNIL Inc. does not operate Chariot as a hosted service** and has no plans to. The bundled TypeScript engine and proprietary native component for IAM, RBAC, credential vaulting, license enforcement, and internal API discovery are licensed to the deploying entity, which itself chooses one of three deployment modes: air-gapped inside its perimeter, hosted as SaaS by the deploying entity for its own customers, or integrated into a hyperscaler's PaaS surface. Available in `@epicai/chariot@3.1.1`.

**A note on protectNIL's role.** protectNIL Inc. is the software publisher of Chariot, not a service operator. Customer data never traverses protectNIL infrastructure in any supported deployment. Where this document refers to "the operator," that means the entity that runs the Chariot instance — never protectNIL.

If you discover a security issue, please report it privately rather than opening a public issue. Preferred reporting path:

- GitHub Security Advisory for this repository, if enabled
- Email: `security@epic-ai.io`

Please include:

- A clear description of the issue
- The affected version(s)
- The platform or deployment model involved
- Reproduction steps, if available
- Any logs, screenshots, or proof-of-concept material you are comfortable sharing privately

We aim to acknowledge valid reports within 2 business days and provide a triage update as soon as practical. Critical issues are prioritized immediately.

## OWASP Top 10 for LLM Applications (2025) — Self-Asserted Compliance

**Epic AI® Chariot complies with the OWASP Top 10 for LLM Applications (2025) on every applicable item.** Self-assessment by protectNIL Inc.; not a third-party attestation. Each "Complies" item was implemented in code, exercised by a dedicated eval suite, then independently reviewed by the project's adversarial-review pipeline before landing. The full item-by-item mapping with implementation citations and eval gates is in [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) under the "OWASP Top 10 for LLM Applications (2025) — Self-Asserted Compliance" section. Headlines:

- **LLM01 Prompt Injection** — every tool-result content string flowing to model context (REST + 3 MCP transports + 8 CLI-bridge return paths) is scanned by the Tool-Result Prompt-Injection Scanner; quarantined content is replaced by an attacker-byte-free marker. 179 hard gates.
- **LLM02 Sensitive Info Disclosure** — AES-256-GCM credential vault with per-tenant key derivation; audit redaction of credential values; CLI stdout/stderr credential-shape redaction.
- **LLM03 Supply Chain** — zero-npm-dependency Rust binary; signed adapter integrity manifest; `prepublishOnly` audit + leak-scan + manifest + catalog signature + full test suite.
- **LLM05 Improper Output Handling** — `execFile`-only subprocess; Zod schema validation; response-size and JSON-depth guards.
- **LLM06 Excessive Agency** — three-tier autonomy governance + Rust-layer RBAC enforced per tool call.
- **LLM08 Vector and Embedding Weaknesses** — routing is BM25-only; no `vector-index.json` artifact ships, so there is no embedding artifact to poison or stale-replay. The former signed-envelope verifier and its integrity eval were removed in the 3.1.1 BM25-only excision; re-introducing a vector index would require re-implementing the verifier and gate.
- **LLM10 Unbounded Consumption** — per-tenant rate limiting + size/depth guards + license seat enforcement.

LLM04 (model poisoning) and LLM07 (system prompt leakage) and LLM09 (misinformation) are not in Chariot's surface: Chariot is a tool-call gateway that does not train, hold the system prompt, or generate content.

These eval gates run in series in the release pipeline before every publish; they are not bundled in the package.

---

## Security posture

1. **Deployment-flexible — operator-controlled in every mode**
   - **Air-gapped Enterprise Download.** Run inside your perimeter. Zero outbound dependency on Epic AI®, so no Epic AI®-issued SOC 2 attestation lives in your data path. Your own compliance posture still governs the deployment.
   - **Hosted as SaaS by a customer or partner.** Same engine, hosted by an enterprise IT team, a lab model operator, or a hyperscaler partner for that party's own customers. **protectNIL Inc. is never the SaaS operator.** Same per-tenant credential isolation. Same SAML/OIDC/SCIM. Master key held by the deploying SaaS operator — never reaches Epic AI®.
   - **Hyperscaler PaaS.** Delivered through partner clouds. Integrated IAM, billing, and observability inside the partner's tenant boundary. Per-tenant credential isolation is preserved end-to-end.
   - In every mode, core enterprise behavior — license validation, RBAC, credential vault decryption, audit chain writes — is enforced locally inside the deployment, not by a vendor-managed control plane.

2. **Can be air-gapped**
   - The air-gapped download mode operates without outbound connectivity to any vendor service.
   - The enterprise binary validates licenses locally; no phone-home.
   - If you configure cloud LLMs or external adapters, those are the outbound dependencies you choose to enable.
   - SaaS and PaaS modes retain the same property at the deployment boundary: the operator chooses what egress, if any, exists from their tenant network.

3. **Strong IAM/RBAC and identity-provider integration**
   - Chariot supports SAML, OIDC, and SCIM-based identity integration.
   - Group-based access mapping, seat enforcement, and session revocation are enforced locally.
   - Multi-user access is controlled by policy, not by a hidden vendor control plane.
   - Treat IAM configuration as a security boundary: review IdP mappings, SCIM provisioning, and role assignments carefully.

4. **Minimizes leakage when a public LLM is used**
   - Discovery, routing, credentials, and policy enforcement stay under your control.
   - Only the context you choose to send to your LLM provider leaves the machine.
   - Use your provider’s privacy and training controls that match your policy.
   - Chariot is designed to reduce unnecessary exposure, not to override your provider contract.

5. **Strong observability for SecOps and DevOps**
   - Chariot emits audit trails intended for incident review and compliance evidence.
   - Session, license, and administrative actions are designed to be traceable.
   - Integrate Chariot with your SIEM, logging pipeline, and alerting systems.

6. **Supply-chain and artifact integrity**
   - The native enterprise component uses signed integrity manifests and fail-closed verification.
   - Release artifacts are intended to be verifiable before publication and load.
   - Treat package provenance, signature verification, and binary integrity as required controls before deployment.

7. **Controlled data handling**
   - Secrets remain under your control.
   - The credential vault is local and encrypted.
   - Review retention, redaction, and access rules before connecting production systems.
   - Internal API discovery should be limited to approved codebases and approved services.

8. **Incident response and vulnerability reporting**
   - Report suspected vulnerabilities privately.
   - Do not publish exploit details publicly before triage and coordination.
   - Include affected versions, deployment details, and any reproduction steps you can safely share.

9. **Version support and patch policy**
   - Security fixes are released on the current supported line first.
   - Older releases may receive backports when practical.
   - High-severity issues are prioritized over routine feature work.

## What to report

Because Chariot operates as an Intelligent Virtual Assistant (IVA) routing your natural-language intent to enterprise integrations, the relevant security surface spans identity, credentials, audit, and the routing/discovery layer. Please report any issue that could:

- Expose credentials, tokens, or vault contents
- Bypass IAM, RBAC, SCIM, or seat enforcement
- Circumvent license validation or integrity checks
- Break tamper-evident audit logging
- Allow unauthorized internal API discovery or adapter exposure
- Leak data to unapproved outbound destinations
- Undermine package or native-binary integrity

## Responsible disclosure

Please do not publish vulnerability details publicly until we have had a chance to triage and respond. If you need to coordinate a public disclosure, we will work with you on timing and scope.

## Advisories

### CHARIOT-2026-002 — 3.0.0 license-signing key rotation (2026-04-30)

**Affected:** `@epicai/chariot@2.1.1` (and any earlier 2.x line that embedded the pre-rotation public key).
**Fixed in:** `@epicai/chariot@3.0.0` (2026-05-14).
**Upgrade:** `npm install @epicai/chariot@^3.0.0`.

**Impact.** Production licenses signed after 2026-04-30 fail validation on installations running `@epicai/chariot@2.1.1`. The Rust native binary in 2.1.1 embedded only the pre-rotation Ed25519 public key in its accept-list. The license issuer at `epic-ai.io/api/license/renew` began signing with the post-rotation key on 2026-04-30. Customers on 2.1.1 receive correctly-signed, in-date license envelopes that the binary rejects as untrusted-signature. The multi-user Intelligent Virtual Assistant (IVA) surface is gated by license validation, so this defect collapsed those deployments back to single-user IVA mode even though licensed seats were on file.

**Operator-visible symptom.** `chariot license` reports the license as invalid; multi-user IVA features fall back to single-user mode despite a valid signed envelope on disk. Renewals via `chariot license renew-now` succeed at the wire layer but the renewed envelope is still rejected on next validation.

**Root cause.** Asymmetric rotation of the production signing key without a corresponding accept-list expansion on the verifier side. The native binary verifier should have included both the pre- and post-rotation public keys for the duration of the rotation window. The 2.x line shipped before the rotation completed, so the post-rotation key never made it into 2.1.1's accept-list.

**Remediation in 3.0.0.** The native binary's accept-list now includes the current production public key (`MCowBQYDK2VwAyEACBR74DxcFEvMcBO0YOxA9q5X/75uLAh3Z1CHOg2dHEc=`, kid `f8b8f6f64a6c43adec00dfff648cf93d6a8e2703122098db46e15c297f2219d0`) alongside the pre-rotation key. Both keys are honored simultaneously to support customers who hold licenses signed under either key. Future rotations will land in the accept-list before the issuer cuts over.

**No exploitation path.** This is an availability defect, not a confidentiality or integrity defect. No exploitation is possible: a malicious party cannot use this issue to forge a license, exfiltrate data, or bypass RBAC. The defect causes the customer's own valid license to be rejected. There is no attacker-side amplification.

**Credit.** Internal review traced to the binary key sync gap during the production rotation cutover.

---

### CHARIOT-2026-001 — 1.1.0

**Affected:** `@epicai/chariot@1.0.6` and earlier.
**Fixed in:** `@epicai/chariot@1.1.0` (2026-04-14).
**Upgrade:** `npm install @epicai/chariot@^1.1.0`.

This release remediates five independent security issues in the enterprise IAM surface. Users on 1.0.6 should upgrade.

- **RBAC silent data loss on group→adapter mapping (high impact on deployments that use group mappings).** Admin API persisted only the first adapter in a multi-adapter group mapping; all other adapters were silently discarded. A user in a group authorized for `['github','datadog','jira']` received access to `github` only. Fixed by cascading the mapping schema to a plural `adapterIds: string[]` array end-to-end. Legacy 1.0.x singular documents are read correctly and upgraded in place on their next write — no manual migration required.
- **OIDC callback rate-limit bypass (moderate).** The rate-limit gate on `/oidc/callback` was not reached on the missing-cookie and malformed-cookie branches, and the gate and the failure recorder keyed against different `(ip, tenant)` tuples when the state cookie was unparseable. An attacker could accumulate authentication failures against the endpoint without ever tripping the 429 threshold. Fixed by hoisting the gate ahead of every error return and using a single shared tenant-resolution fallback chain for both the gate and the recorder.
- **SAML RelayState open redirect (moderate).** The SAML callback accepted RelayState values that could be absolute URLs, protocol-relative URLs, or contain whitespace / control characters, enabling a redirect-based phishing primitive after a successful SAML assertion. Fixed by introducing `isSafeRelayState()` which accepts only tenant-local relative paths.
- **OIDC error message information leak (low).** Client-facing error responses on OIDC callback failure could include the underlying IdP URL, token-exchange stack fragments, or library-specific detail strings. Fixed by returning a generic error to the client and logging the full context only to the operator stream.
- **Audit hash-chain rollback on partial write failure (moderate).** When a chain-advance succeeded but the subsequent event insert failed, the chain state was stranded in an un-reconcilable state and subsequent appends would fail verification. Fixed by wrapping the append/insert in a nested try/catch so chain state rolls back to the last confirmed position on partial failure.

Additional hardening shipped in 1.1.0 but not scoped to a single advisory: Zod request-body validation on every admin / adapters / SCIM POST/PUT route; removal of `as any` and `@ts-ignore` escape hatches from security-critical paths; `Filter<T>` typed MongoDB filters; `generateScimTokenForTenant` throws on missing tenant instead of returning an un-persisted token; 28 end-to-end eval assertions against real local Mongo + Redis covering every fix above.

No public exploitation of these issues has been reported. Credit: internal security review by Epic AI®.

