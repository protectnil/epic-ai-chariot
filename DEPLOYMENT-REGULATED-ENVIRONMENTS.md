# Epic AI® Chariot — Deploying in Regulated Environments

This document is for operators deploying Chariot in environments with strict data residency, audit, access-control, or outbound-connection requirements — including ITAR, HIPAA, CMMC, FedRAMP, and other compliance frameworks. **Chariot is the infrastructure; the operator is the regulated party.** This document lists the operator-side configuration and process choices that the architecture supports.

protectNIL Inc. is the software publisher of Chariot, not a service operator. protectNIL is never in the customer data path and does not operate Chariot as a hosted service in any deployment mode. The operator is the entity that runs the Chariot instance — an enterprise IT team, a lab model operator, a hyperscaler partner, or a PaaS provider.

For the underlying security architecture, see [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md). For vulnerability reporting, see [SECURITY.md](SECURITY.md).

---

## Pre-Deployment Checklist

Run through these before exposing Chariot to regulated data.

### 1. Verify air-gap behavior end-to-end

Chariot's documented posture is that all license validation, RBAC, credential operations, and adapter execution work without vendor outbound. Verify in your environment, not in ours:

- [ ] Run Chariot in a container with `--network none`. Confirm all local operations (login, tool call against a local mock adapter, audit chain verification) function normally.
- [ ] In your production network segment, allowlist outbound destinations to only the specific external adapter endpoints your tenants require.

### 2. License management

Chariot license **validation** is fully offline (Ed25519 signature against a compiled-in public key). Chariot license **renewal** is the **only** customer-initiated path that, by default, contacts a protectNIL-controlled URL: `https://epic-ai.io/api/license/renew`. **The renewal payload contains license metadata only** — current license envelope identifier, renewal nonce, and an HMAC proof. **No tenant data, no user data, no credential vault contents, no audit log entries, no adapter traffic, and no MCP tool inputs or outputs are transmitted on this call.** The claim that customer data never traverses protectNIL infrastructure remains intact across this path. To remove even the metadata exposure, choose one:

- [ ] **Offline renewal:** Do not invoke `renewNow()`. Coordinate with protectNIL out-of-band to receive a refreshed license file before your term expires, and replace the file on disk.
- [ ] **Override renewal endpoint:** Set environment variable `CHARIOT_LICENSE_URL=https://your-internal-proxy/license/renew` and proxy the call through your own egress controls.

### 3. Identity provider configuration

Chariot enforces access via SAML 2.0, OIDC, or SCIM 2.0 against your existing IdP (Okta, Entra ID, Ping, Auth0, Keycloak). All access control derives from claims your IdP issues:

- [ ] Document which IdP group represents your access-attestation cohort (e.g., for ITAR: "U.S. persons cleared for export-controlled data"; for HIPAA: "workforce members with PHI access training current"). This is a string Chariot honors; your IdP enforces the membership rule.
- [ ] Configure your IdP to assert this group only after your existing personnel-screening process is complete.
- [ ] Map the group to specific adapter IDs via Chariot's admin API (`/enterprise/{tenantId}/admin/group-mappings`). Users outside the group cannot reach those adapters.
- [ ] Verify SAML attribute mapping or OIDC claim mapping includes the `groups` claim. A misconfigured mapping fails open — the user is authenticated but unauthorized for the regulated adapters.
- [ ] Test: provision a non-cleared test user, confirm they cannot reach regulated adapters at the Chariot RBAC layer.

### 4. Disable opt-in outbound paths

Three outbound paths are off by default; verify they remain off:

- [ ] `EPICAI_LOG_LOKI_URL` and `EPICAI_LOG_LOKI_TOKEN` environment variables are **not set** (or are set to your internal log aggregator only).
- [ ] Adapter catalog `source` is `bundle` (default), not `registry` — i.e., the local `chariot-adapter-bundle.json` is the catalog source.
- [ ] Kill-list watcher `url` is unset (default) — the watcher is a no-op when no URL is configured. Alternatively, configure your own internal kill-list mirror.

### 5. Adapter review and integrity

- [ ] Review the bundled adapter catalog. Disable any adapter whose destination is outside your approved-vendor list.
- [ ] Confirm the adapter integrity manifest verifies at startup (a tampered adapter file prevents Chariot from loading).
- [ ] Acknowledge the documented adapter-sandbox limitation: Node.js adapters can in principle exfiltrate decrypted credentials if compromised at the npm dependency layer. Mitigate via network isolation per item 1.

### 6. Internal API discovery scope

The `chariot discover ./src` feature exposes internal REST/gRPC endpoints as MCP tools. Regulated environments must constrain this carefully:

- [ ] Scope discovery to approved codebases only. Do not point at regulated-data-handling services unless those services themselves are framework-aware.
- [ ] Review every discovered adapter before approving it for production.
- [ ] Verify the default exclusion of admin, internal, debug, and health routes is correct for your environment.

### 7. Audit trail export

Chariot writes a hash-chained audit trail covering IAM events and every MCP tool call. The chain is tamper-evident: `verifyChain()` fails on any modification, deletion, or gap.

- [ ] Configure scheduled export of the audit trail to your SIEM (Splunk, Sentinel, Chronicle, etc.).
- [ ] Run `verifyChain()` as part of the export pipeline. Alert your security team on any verification failure.
- [ ] Confirm your SIEM retention policy meets your regulatory requirement (e.g., DDTC requires multi-year retention for ITAR-related access records; HIPAA requires six years for PHI-access logs).

### 8. Credential vault — master key management

`ENTERPRISE_MASTER_KEY` is the root of credential vault security (AES-256-GCM with HKDF-SHA256 per-tenant key derivation, performed exclusively in the Rust binary).

- [ ] Store the master key in your secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault), not in a `.env` file on disk.
- [ ] Define a rotation schedule consistent with your key-management policy. Document the rotation process.
- [ ] Restrict access to the master key to operators who have completed the same screening as item 3 cohort members.

### 9. Host-level access controls

The Chariot Node.js process holds decrypted credentials in memory for the duration of a tool call. Host-level controls protect this surface:

- [ ] Restrict shell and debugger access to the Chariot host to operators in the cohort from item 3.
- [ ] Disable core dumps for the Chariot process (`ulimit -c 0` or systemd `LimitCORE=0`).
- [ ] Configure ptrace restrictions (`/proc/sys/kernel/yama/ptrace_scope = 2` or stricter).
- [ ] If running under systemd, set `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `PrivateDevices=yes` on the unit file.

### 10. RBAC scope limitations to disclose

RBAC today is **adapter-level**, not tool-level. A user authorized for an adapter is authorized for all tools within that adapter.

- [ ] Audit each adapter's tool list. For any adapter that combines read-only and write tools, decide whether the regulated cohort should have the whole adapter or none of it.
- [ ] If finer-grained control is required, deploy separate adapter instances scoped to the specific tools each cohort needs.
- [ ] Track the tool-level RBAC roadmap item; revisit when shipped.

---

## Acceptance Test

Once configured, the following test demonstrates the deployment is internally consistent:

1. Provision two test users via SAML or OIDC:
   - User A: in the regulated-cohort group, with adapter X mapped to that group.
   - User B: not in the regulated-cohort group.
2. User A logs in, calls a tool on adapter X → success, audit row written.
3. User B logs in, attempts the same call → 403 from the Rust RBAC layer before the adapter executes, audit row written with `decision: denied`.
4. Run `verifyChain()` on the audit trail → returns `valid: true`.
5. Confirm via `ss -tnp` (or equivalent) that the Chariot process has no open outbound connections to `epic-ai.io`, `submit.epicai.co`, or any Loki endpoint while idle.

If all five steps pass, your deployment matches the documented architecture.

---

## Cross-App Access (XAA / ID-JAG) Deployment

When Chariot runs as a Cross-App Access resource server (see
[`Cross-App_Access_XAA_ID-JAG.md`](./Cross-App_Access_XAA_ID-JAG.md)), it is a
long-running HTTP service that an enterprise IdP and its clients call. Run it
under a process supervisor and give it a shared, persistent state store.

### State store — required for a restartable service

Session state, the JWT-replay (`jti`) cache, and MFA-pending records are held
in an external Redis when `REDIS_URL` is set. **Set `REDIS_URL` in any
deployment you intend to restart or run more than one instance of.** Without
it, Chariot falls back to an in-process store that is **lost on every
restart** (all sessions invalidated, replay cache reset) and is **not shared
across instances** — acceptable for local development only. `REDIS_URL` is a
standard connection string to any Redis you operate (e.g.
`redis://127.0.0.1:6379`); it is not a hosted/managed-service requirement.

### Environment contract

| Variable | Required | Purpose |
|---|---|---|
| `CHARIOT_ENTERPRISE` | yes | Enables the enterprise IAM / ID-JAG surface. |
| `MONGODB_URI` | yes | Mongo connection (IAM tenants, clients, users, audit). |
| `MONGODB_DB` | no (default `epicai`) | Database name. |
| `REDIS_URL` | yes for production | Shared, restart-surviving session / `jti` / MFA store. Omit only for local dev. |
| `ENTERPRISE_JWT_SECRET` | yes | Signing secret for issued access tokens. |
| `ENTERPRISE_MASTER_KEY` | yes | Master key for the per-tenant credential vault. |
| `CHARIOT_PUBLIC_BASE_URL` | yes in production | RFC 8414 issuer identifier; the discovery handler fails closed in production if unset. |
| `CHARIOT_HTTP_PORT` | no (default `3550`) | MCP / OAuth HTTP port (or pass `serve --http <port>`). |

Indexes are created automatically on startup; no manual index step is needed.

### Reference `systemd` unit

```ini
[Unit]
Description=Epic AI Chariot — Cross-App Access (XAA / ID-JAG) resource server
After=network-online.target
Wants=network-online.target

[Service]
User=chariot
Group=chariot
EnvironmentFile=/etc/chariot/chariot.env
ExecStart=/usr/bin/chariot serve --http 3550
Restart=always
RestartSec=2
# Tighten the filesystem; Chariot writes only to its own state dir.
ProtectSystem=strict
ReadWritePaths=/var/lib/chariot
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

`/etc/chariot/chariot.env` holds the environment contract above
(`KEY=value` per line, `chmod 600`). With `Restart=always` plus a `REDIS_URL`
state store, the service survives crashes and restarts without losing active
sessions.

---

## What Chariot Does Not Certify

Chariot is infrastructure. The operator certifies compliance. Specifically:

- protectNIL Inc. does not represent that Chariot is "ITAR compliant," "HIPAA compliant," or "FedRAMP authorized." These are operator certifications, not vendor certifications.
- protectNIL Inc. does not maintain a DDTC registration on behalf of operators. Operators are responsible for their own DDTC registration, Technology Control Plan, personnel screening, and audit attestation.
- The bundled adapter catalog is verified by signature but the upstream vendor APIs are not audited by protectNIL. Operators are responsible for their own vendor-due-diligence on adapter endpoints.
- protectNIL Inc. is never a service operator and never sits in the customer data path. Any regulatory obligation that attaches to the operator of a hosted service attaches to the entity hosting Chariot — not to protectNIL.

---

*Epic AI® is a registered trademark of protectNIL Inc.*
