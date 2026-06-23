# Epic AI® Chariot — Developer Guide

**Package:** `@epicai/chariot`
**Product:** Intelligent Virtual Assistant (IVA) MCP gateway
**Version:** 3.1.1
**License:** Elastic License 2.0
**Runtime:** Node.js >= 22.13.0

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [How Chariot Works](#how-chariot-works)
3. [CLI Commands](#cli-commands)
4. [Internal API Discovery](#internal-api-discovery)
5. [License Management](#license-management)
6. [IAM Configuration](#iam-configuration)
7. [Credential Vault](#credential-vault)
8. [RBAC](#rbac)
9. [Audit Trail](#audit-trail)
10. [Programmatic Usage](#programmatic-usage)
11. [Building from Source](#building-from-source)
12. [Testing](#testing)

For a full explanation of the threat model, architectural layers, attack surface, and deployment hardening guidance, see [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md).

> **Epic AI® Chariot complies with the OWASP Top 10 for LLM Applications (2025) on every applicable item.** Self-asserted by protectNIL Inc. and adversarial-review-pipeline approved. Full item-by-item mapping with eval-gate counts and code citations is in [SECURITY_ARCHITECTURE.md §OWASP Top 10 for LLM Applications (2025)](SECURITY_ARCHITECTURE.md#owasp-top-10-for-llm-applications-2025--self-asserted-compliance).

**Operator-facing security primitives from the LLM01 and LLM08 implementations**:

- **Tool-Result Prompt-Injection Scanner (LLM01).** Every tool-result content string that flows to the model context — REST, MCP stdio/SSE/streamable-HTTP, and CLI-bridge — passes through `applyInjectionScanner` first. On a hard signal the original payload is replaced by an attacker-byte-free quarantine marker before the model ever sees it. Operators see the verdict + signals via the observability emitter; nothing operator-side needs configuration to get the defense.
- **Retrieval Integrity (LLM08).** Chariot routing is **BM25-only** — the precomputed dense/sparse `vector-index.json` artifact is not shipped or loaded, so there is no vector-embedding artifact to poison or stale-replay in this release. The former signed-envelope verifier (`VectorIndexVerifier`) and its integrity eval were removed in the 3.1.1 BM25-only excision; a future release that re-introduces a vector index must re-implement the verifier and gate.

---

## Quick Start

```bash
# Install and run setup wizard
npx @epicai/chariot

# Search and add adapters
chariot search <term>
chariot add <adapter-id>

# Start MCP server
chariot serve

# Discover internal APIs
chariot discover ./src
```

For the full engine documentation (federation, routing, orchestrator, adapters), see the [Chariot Developer Guide](https://github.com/protectnil/epic-ai-chariot/blob/master/docs/product/DEVELOPER_GUIDE.md). The engine is bundled directly in this package.

---

## Deployment Modes

Chariot ships as one codebase that runs in three deployment shapes. The IAM surface (SAML, OIDC, SCIM 2.0, RBAC), credential vault (AES-256-GCM + per-tenant HKDF-SHA256), audit chain, and routing engine are identical across all three. Only the operator boundary differs.

### 1. Air-gapped Enterprise Download (default)

```bash
npx @epicai/chariot
```

Runs single-user or single-tenant inside your perimeter. No outbound dependency on Epic AI®, so no Epic AI®-issued SOC 2 attestation sits in your data path (your own internal compliance review still applies, of course). License file at `~/.epic-ai/chariot.license` (or unlicensed for the free tier).

### 2. Standalone SaaS

The IAM surface (SAML, OIDC, SCIM 2.0, RBAC, credential vault, audit) is multi-tenant by data model: `tenantId` keys every record (`src/iam/types.ts`), credentials are encrypted with per-tenant HKDF-SHA256 derived keys, and the Enterprise router accepts SCIM provisioning at `/enterprise/{tenantId}/scim/v2` (router validator regex `^[a-z0-9][a-z0-9-]{1,63}$` per `src/iam/routes/index.ts`).

The MCP HTTP transport (`src/engine/server/transports/http.ts`) is **process-scoped** to a single tenant per process via `CHARIOT_TENANT_ID`. Multi-tenant SaaS deployment is therefore orchestrated as one Chariot process per customer organization (container-per-tenant), each booted with:

```bash
export CHARIOT_ENTERPRISE=true
export CHARIOT_TENANT_ID=<tenant-slug>   # one per process, matches IAM tenant
export MONGODB_URI=mongodb://...
export REDIS_URL=redis://...
export ENTERPRISE_JWT_SECRET=...        # session signer
export ENTERPRISE_MASTER_KEY=...        # 32-byte base64; per-tenant key derivation root
export CHARIOT_HTTP_TOKEN=...           # optional shared-secret bearer for the HTTP transport
chariot serve --http 3550
```

Tenants share the Mongo/Redis cluster (each row keyed by `tenantId`) and the operator-held master key (each tenant gets its own HKDF-derived subkey). Operators bring their own routing layer (path-based or Host-header-based) to map customer organizations to their tenant process. The credential vault's per-tenant key derivation guarantees that an operator never sees plaintext credentials for any tenant — Epic AI® has no path to the plaintext either.

A future single-process multi-tenant MCP transport (per-request JWT-derived `tenantId`) is on the roadmap; today's deployment shape is multi-process.

### 3. Hyperscaler PaaS

The same `CHARIOT_ENTERPRISE=true` boot, deployed inside a partner cloud. The partner is the master-key holder and the deployment operator; the partner's customers are tenants in the Chariot data model. Integrated into the partner's IAM, billing, and observability surfaces. Partner availability rolls out as channel agreements complete.

In every mode, the architecture below is the same.

---

## How Chariot Works

The Intelligent Virtual Assistant (IVA) surface is delivered by a forked engine + native binary.

```
@epicai/chariot
├── src/engine/             # Bundled MCP engine (Elastic License 2.0)
│   └── Full MCP server, routing engine, adapter catalog
├── src/iam/                # IAM routes + services (Elastic License 2.0)
├── src/license/            # License loader + binding
├── src/discovery/          # Internal API Discovery interface
├── src/bin/chariot.ts      # CLI entry point
└── native/                 # Rust binary (Elastic License 2.0)
    ├── license.rs          # Ed25519 validation
    ├── rbac.rs             # Group-to-adapter access control
    ├── vault.rs            # AES-256-GCM credential encryption
    └── discovery.rs        # Codebase scanner
```

The Rust binary is loaded at runtime via napi-rs. If the binary is not present (e.g., unsupported platform), Chariot runs in single-user mode — full features, no IAM.

---

## CLI Commands

### `chariot`

Run the setup wizard. Detects your AI client, writes MCP config, connects zero-credential integrations.

### `chariot serve`

Start the MCP server (stdio transport). Add this to your AI client's MCP configuration.

### `chariot discover [path]`

Scan a codebase for internal APIs. Currently supports:

- **OpenAPI/Swagger specs** (JSON and YAML)
- **Express.js route definitions** (`app.get`, `router.post`, etc.)

The scanner presents discovered services grouped by name. You select which services to expose. Admin, internal, debug, and health routes are excluded by default.

```bash
chariot discover ./src

# Found 3 services, 47 endpoints:
#   [ ] payment-service    — 18 endpoints (Express)
#   [ ] user-service       — 21 endpoints (OpenAPI)
#   [ ] inventory          —  8 endpoints (OpenAPI)
#
#   Space to toggle, A to select all, Enter to confirm
```

After selection, you configure the base URL and authentication for each service. Generated adapters are saved to `~/.epic-ai/discovered-adapters/`.

### `chariot add <adapter-id>`

Add an adapter. Run `chariot search <term>` first to find the adapter ID.

### `chariot remove <adapter-id>`

Remove an adapter.

### `chariot list [term]`

List Curated and Custom adapters. Pass a term to search all available adapters.

### `chariot health`

Check the health status of connected adapters.

### `chariot license`

Display current license status — mode, company, seat count, expiration.

### `chariot configure`

Interactive credential configuration.

---

## License Management

License state gates the multi-user Intelligent Virtual Assistant (IVA) features (SSO, RBAC, SCIM, shared credential vault). Single-user IVA capability is free and unlicensed.

### Free Tier

No license file needed. Single user. Full functionality. Chariot checks for `~/.epic-ai/chariot.license` at startup. If absent, it runs in free mode.

### Paid Tier

Drop a signed license file into your config directory:

```bash
cp chariot.license ~/.epic-ai/chariot.license
```

The Rust binary validates the Ed25519 signature against the embedded public key. Valid + not expired = multi-user mode activates.

### License File Format

```json
{
  "jwt": "<compact EdDSA JWT — claims include sub, exp, license_epoch, seats>",
  "renewal_secret": "<base64url 32 bytes>"
}
```

### License Validation

- **Signature:** Ed25519 verification against the compiled-in public key set. The validator accepts any key in the embedded accept-list, which enables zero-downtime key rotation. Failed signatures are rejected with no fallback.
- **Expiration:** Per-license, read from the `exp` claim of the signed JWT envelope. The issuer sets the duration at sign time (production licenses are issued for a billing-cycle term defined by the order). After `exp`, the license enters a **14-day grace period** (`GRACE_PERIOD_DAYS = 14` in `src/license/loader.ts`) during which enforcement is non-strict and warnings are surfaced. After grace, the license is `DEGRADED` and multi-user features fall back to single-user mode.
- **Anti-rollback:** Every accepted license bumps a persistent `license_epoch` floor on disk (`~/.epic-ai/state/license_epoch`). An incoming envelope whose epoch is lower than the floor is rejected even if its signature is valid. This blocks a signed-but-stale rollback attack.
- **Seat count:** Enforced at session-creation time via `seatLimitMiddleware`. New sessions are rejected when active users equal `totalSeats`. The middleware returns a 402-like body with the configured `totalSeats` and current `activeUsers` for operator visibility.
- **Cache:** Validation results cache per-tenant for 60 seconds (`CACHE_TTL_MS = 60_000`). Call `revalidateLicense()` to bypass the cache after a renewal write.
- **Offline:** No network call. No phone home. Purely local validation against the compiled-in Ed25519 public-key set. Online renewal is opt-in via `chariot license renew-now`, which is the only command that initiates outbound traffic to the license issuer.

---

## IAM Configuration

### SSO — SAML 2.0

Configure your IdP (Okta, Entra, etc.) with:

- **ACS URL:** `https://your-chariot-host/enterprise/auth/saml/callback`
- **Entity ID:** Your Chariot instance identifier
- **Attributes:** `email` (required), `groups` (optional)

### SSO — OIDC

Configure your IdP with:

- **Redirect URI:** `https://your-chariot-host/enterprise/auth/oidc/callback`
- **Grant type:** Authorization Code + PKCE
- **Scopes:** `openid profile email groups`

### SCIM 2.0 Provisioning

Point your IdP's SCIM client at:

```
https://your-chariot-host/enterprise/{tenantId}/scim/v2
```

Endpoints: `/Users`, `/Groups`, `/ServiceProviderConfig`, `/Schemas`

Full RFC 7644 compliance. Okta-compatible PATCH handling. JIT provisioning. Deprovisioning automatically revokes sessions and credentials.

---

## Credential Vault

API keys and secrets are encrypted at rest using AES-256-GCM with per-tenant key derivation:

1. Master key from `ENTERPRISE_MASTER_KEY` environment variable (base64-encoded, 32 bytes)
2. HKDF-SHA256 derives a unique key per tenant: salt = `tenant:{tenantId}`
3. Each encryption uses a random 12-byte IV
4. Ciphertext includes a 16-byte authentication tag

Encryption and decryption are performed in the Rust binary. The master key and derived keys never leave memory. Credentials are stored as base64-encoded blobs in MongoDB.

### Per-User vs Shared Credentials

- **Per-user:** Each user connects their own API keys. Keys are encrypted under the tenant's derived key and associated with the user's ID.
- **Shared (org-wide):** An admin connects a credential once. All authorized users in the tenant can use it. Flagged as `shared: true`.

---

## RBAC

Role-based access control maps IdP groups to adapter access:

```
Group "DevOps" → adapters: datadog, pagerduty, github
Group "Finance" → adapters: stripe, quickbooks, plaid
Group "Admin"   → adapters: all
```

When a user authenticates via SSO, their group memberships are resolved to a set of allowed adapter IDs. The MCP server only exposes tools from those adapters.

RBAC checks are performed in the Rust binary for speed. The middleware attaches `allowedAdapterIds` to each request.

---

## Audit Trail

Every IAM action is logged to a hash-chained, append-only audit trail:

- **Hash chain:** Each record contains the SHA-256 hash of the previous record
- **Tamper-evident:** Modify or delete any record and the chain breaks
- **Optimistic locking:** CAS-based writes prevent race conditions
- **Chain verification:** `verifyChain()` recomputes hashes and checks linkage

Event types: `login`, `logout`, `user_created`, `user_deactivated`, `adapter_connected`, `credential_revoked`, `settings_updated`, and more.

Export formats: JSON (API), CSV (download).

---

## Programmatic Usage

Embed the IVA capability surface directly in your own service:

```typescript
import { validateLicense, checkSeatLimit } from '@epicai/chariot/license';
import { iam } from '@epicai/chariot';

// Check license
const license = validateLicense();
console.log(license.mode);       // 'free' or 'licensed'
console.log(license.totalSeats); // 25

// Check seats
const seats = checkSeatLimit(currentActiveUsers);
if (!seats.allowed) {
  console.log(`${seats.remaining} seats remaining`);
}

// Create enterprise routes (Express)
import express from 'express';
const app = express();
app.use('/enterprise', iam.createEnterpriseRoutes({ getActiveUserCount }));
```

---

## Building from Source

### Prerequisites

- Node.js >= 22.13.0
- Rust >= 1.70 (for the native binary)
- npm >= 9

### Build

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Build Rust binary (current platform only)
npm run build:native

# Build everything
npm run build:all
```

### Cross-Compilation

For publishing platform-specific packages, use the napi-rs cross-compilation workflow:

```bash
cd native
napi build --platform --release --target x86_64-unknown-linux-gnu
napi build --platform --release --target aarch64-apple-darwin
napi build --platform --release --target x86_64-apple-darwin
napi build --platform --release --target x86_64-pc-windows-msvc
```

---

## Testing

### Native Binary Tests

The native binary's behavioral suite runs in the release pipeline before publish; it is not bundled in the npm package. Coverage:

- License validation (valid, tampered, expired, bad signature)
- RBAC (group resolution, access grants, access denials)
- Credential vault (encrypt/decrypt round-trip, wrong tenant, wrong key)
- Internal API Discovery (structure, empty paths)

### License Signing (Development)

```bash
npx tsx tools/sign-license.ts \
  --company-id "test-001" \
  --company-name "Test Corp" \
  --seats 25 \
  --days 45 \
  --key /path/to/private.pem \
  --output ./test.license
```

---

*Epic AI® is a registered trademark of protectNIL Inc.*
*IVA — Intelligent Virtual Assistant*
