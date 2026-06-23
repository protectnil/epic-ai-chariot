# Git-Commit-Pin Contract for GitHub-Sourced stdio Adapters

**Document:** `docs/git-pin-contract.md`  
**Status:** DRAFT — pending the catalog publisher SHA population (8 adapters) + preinstall.ts extension  
**Date:** 2026-06-08  
**Audience:** Catalog publisher (adapter bundle pipeline), Chariot engine (runtime consumer)

---

## 1. Background and Scope

Chariot's adapter catalog contains two classes of npm stdio adapters:

| Class | Count | Current state |
|-------|------:|--------------|
| npm-registry adapters (e.g. `@modelcontextprotocol/server-filesystem`) | 165 | Pinned: `mcp.version` + `mcp.integrityShasum` (SHA-512 hex of tarball). Runtime guard: `npmIntegrityGuard.ts`. Preinstall: `preinstall.ts:npmFetch`. |
| GitHub-sourced adapters (e.g. `github:CrowdStrike/falcon-mcp`) | 8 | **Unpinned** — this document defines the missing contract. |

### 1.1 Current Bundle Entries (8 Adapters)

These are the exact bundle rows affected. All use `command: "npx"` with
`args: ["-y", "github:<org>/<repo>"]` — the npm GitHub install shorthand:

| Adapter ID | GitHub slug | Bundle row `args` |
|------------|-------------|-------------------|
| `crowdstrike-identity` | `CrowdStrike/falcon-mcp` | `["-y", "github:CrowdStrike/falcon-mcp"]` |
| `egnyte` | `egnyte/egnyte-mcp-server` | `["-y", "github:egnyte/egnyte-mcp-server"]` |
| `google-ads` | `google-marketing-solutions/google_ads_mcp` | `["-y", "github:google-marketing-solutions/google_ads_mcp"]` |
| `google-analytics` | `googleanalytics/google-analytics-mcp` | `["-y", "github:googleanalytics/google-analytics-mcp"]` |
| `merge-api` | `merge-api/merge-mcp` | `["-y", "github:merge-api/merge-mcp"]` |
| `quickbooks` | `intuit/quickbooks-online-mcp-server` | `["-y", "github:intuit/quickbooks-online-mcp-server"]` |
| `secureframe` | `secureframe/secureframe-mcp-server` | `["-y", "github:secureframe/secureframe-mcp-server"]` |
| `zscaler` | `zscaler/zscaler-mcp-server` | `["-y", "github:zscaler/zscaler-mcp-server"]` |

### 1.2 Problem Statement

The `github:` shorthand tells npm to install from GitHub at runtime.
Without a pinned commit, `npx -y github:<org>/<repo>` fetches the repository
HEAD at execution time — breaking both the air-gap guarantee and supply-chain
integrity.

At runtime, the existing `guardNpmStdioAdapter()` (wired into
`toolHandlers.ts` dispatch) already enforces fail-closed: because these 8 rows
carry no `mcp.version` or `mcp.integrityShasum`, the guard rejects them with
`supply_chain_integrity_failure — unpinned adapter`. So the 8 adapters are
currently runtime-unavailable pending catalog population.

This document defines:
- The catalog fields required to pin each adapter to a specific commit
- How the Chariot engine verifies a pinned GitHub adapter at runtime (no new code needed)
- What new preinstall.ts code is required to warm the npm cache for GitHub-sourced rows
- The fail-closed invariants

---

## 2. Required Catalog Fields

Every bundle entry for a GitHub-sourced adapter MUST carry these fields on `mcp`:

```jsonc
{
  "mcp": {
    "transport": "stdio",
    "command": "npx",
    "packageName": "github:CrowdStrike/falcon-mcp#a1b2c3d4",  // CHANGED: pinned slug
    "args": ["--no-install", "github:CrowdStrike/falcon-mcp#a1b2c3d4"], // -y → --no-install + pin
    "gitUrl": "https://github.com/CrowdStrike/falcon-mcp",     // REQUIRED — canonical URL
    "gitCommit": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",  // REQUIRED — full 40-hex SHA1
    "version": "0.0.0-git.a1b2c3d4",                           // REQUIRED — synthetic semver
    "integrityShasum": "<128-char SHA-512 hex of npm pack tarball>"  // REQUIRED — see §3
  }
}
```

### 2.1 Field Definitions

**`mcp.packageName`** and **`mcp.args`** — CHANGED format  
Replace `-y github:<org>/<repo>` with `--no-install github:<org>/<repo>#<gitCommit-first-8>`.  
The `#<hash>` suffix is npm's GitHub commit-pin syntax:
`npx --no-install github:CrowdStrike/falcon-mcp#a1b2c3d4`  
`--no-install` prevents any network fetch at runtime (fail-closed if not pre-warmed).

**`mcp.gitUrl`** (`string`, REQUIRED for informational/operational use)  
Canonical HTTPS URL: `https://github.com/<org>/<repo>`. No `.git` suffix.  
Used in error messages and operator documentation. Not verified by the engine.

**`mcp.gitCommit`** (`string`, REQUIRED)  
Full 40-character SHA-1 hex of the exact commit to pin.  
Format: `/^[0-9a-f]{40}$/i`. Used by the catalog publisher tooling to derive `integrityShasum`
and by operators/audit to trace which commit is running.  
The engine does NOT independently verify this field — integrity is enforced
via `integrityShasum` (the hash of the npm tarball). `gitCommit` is an
informational anchor.

**`mcp.version`** (`string`, REQUIRED)  
Synthetic semver used as the manifest key in `preinstall.ts`: `0.0.0-git.<commit-first-8>`.  
Example: `0.0.0-git.a1b2c3d4`.

**`mcp.integrityShasum`** (`string`, REQUIRED)  
SHA-512 hex digest (128 lowercase hex chars) of the npm tarball produced by
`npm pack github:<org>/<repo>#<gitCommit>`.

This is the SAME field format used by the 165 npm-registry adapters and verified
by `npmIntegrityGuard.ts:verifyNpmIntegrity`. The runtime guard is shared.

Format: exactly 128 lowercase hex characters. Validated by `/^[0-9a-f]{128}$/i`.

---

## 3. Integrity Verification Strategy

### 3.1 Why the npm tarball, not git archive

`npm pack github:<org>/<repo>#<commit>` produces:
- **Deterministic for a given commit** — npm packs the same files from the same commit
- **The exact artifact executed at runtime** — `npx --no-install` runs from the npm cache,
  which is populated from this tarball at preinstall time
- **Compatible with the existing guard** — `integrityShasum` is the same field verified by
  `npmIntegrityGuard.ts:verifyNpmIntegrity`, so no new runtime code is needed

`git archive --format=tar` is NOT used because it covers only the committed tree,
not installed `node_modules` or built `dist/` directories, and is a different artifact
than what npm actually executes at runtime.

### 3.2 What is already implemented

| Component | Status |
|-----------|--------|
| Runtime guard: `guardNpmStdioAdapter` in `toolHandlers.ts` | **COMPLETE** — already rejects the 8 unpinned rows |
| `npmIntegrityGuard.ts:verifyNpmIntegrity` | **COMPLETE** — works with any package name including `github:org/repo#sha8` |
| `extractStdioPackageName` | **COMPLETE** — extracts `github:org/repo#sha8` from `args` |
| RegistryLoader integrity field propagation | **COMPLETE** — propagates `integrityShasum`/`version`/`packageName` to `ServerConnection` |

### 3.3 What requires new preinstall.ts code

The existing `npmFetch` function in `preinstall.ts:539` runs:
```sh
npm pack ${pkg}@${version}
```
This uses `@<version>` suffix syntax, which is valid for registry packages but
NOT for `github:<org>/<repo>#<commit>` slugs. npm requires a different invocation:
```sh
npm pack github:<org>/<repo>#<commit>
```
(No `@version` suffix — the slug IS the pinned reference.)

**Required change to `preinstall.ts`:** add a `githubFetch` variant of `npmFetch`
that detects `pkg.startsWith('github:')` and invokes `npm pack <pkg>` without the
`@${version}` suffix. The SHA verification, audit trail, and warmer infrastructure
(`verifyAndAuditOne`, `warmNpx`, etc.) are unchanged and shared.

This change is tagged as PENDING in §6 and blocks the github-pin closure (tracked separately).

### 3.4 Runtime dispatch (no new code)

At dispatch time, `toolHandlers.ts` already:
1. Calls `extractStdioPackageName(adapter)` → `"github:CrowdStrike/falcon-mcp#a1b2c3d4"`
2. Calls `guardNpmStdioAdapter(adapterId, pkg, mcp.version, mcp.integrityShasum)`
3. `verifyNpmIntegrity` checks `~/.npm/_cacache/content-v2/sha512/<...>`
4. If the tarball is present and hash matches: allows spawn of
   `npx --no-install github:CrowdStrike/falcon-mcp#a1b2c3d4`
5. If absent or mismatch: fail-closed with `supply_chain_integrity_failure`

---

## 4. Fail-Closed Invariants

### 4.1 Current runtime enforcement (already active)

Because the 8 adapters currently have no `mcp.version` or `mcp.integrityShasum`,
`guardNpmStdioAdapter` rejects every dispatch attempt:
```
supply_chain_integrity_failure: crowdstrike-identity (github:CrowdStrike/falcon-mcp)
is missing version and integrityShasum in the adapter catalog. Unpinned npm stdio
adapters cannot be launched at runtime. Run `chariot setup --pre-install`
after the catalog is updated with supply-chain metadata.
```

### 4.2 Catalog field validation (PENDING — not yet in normalizeAdapter)

The following validation must be added at catalog-load time when the 8 adapters
carry the new fields. The recommended location is `loadAllAdapters()` in
`ChariotState.ts`, applied after `normalizeAdapter()`:

| Condition | Action |
|-----------|--------|
| `gitCommit` present but not 40 lowercase hex chars | Drop entry; log `malformed gitCommit (expected 40-hex)` |
| `integrityShasum` present but not 128 hex chars | Drop entry; log `malformed integrityShasum (expected 128-hex)` |
| `gitUrl` present but not starting with `https://github.com/` | Drop entry; log `malformed gitUrl (expected https://github.com/...)` |

Note: `normalizeAdapter()` at `ChariotState.ts:388` currently only bridges field
names (`serverUrl`→`url`, `packageName`→command/args). The above validation is a
separate gate. Implementation is PENDING alongside the preinstall.ts extension.

### 4.3 Runtime dispatch invariants (active via npmIntegrityGuard.ts)

| Condition | Error |
|-----------|-------|
| `mcp.version` absent | `supply_chain_integrity_failure` — unpinned |
| `mcp.integrityShasum` absent | `supply_chain_integrity_failure` — unpinned |
| `integrityShasum` not 128 hex chars | `supply_chain_integrity_failure` — malformed |
| Tarball absent from npm `_cacache` | `supply_chain_integrity_failure` — run preinstall |
| `extractStdioPackageName` returns null | `supply_chain_integrity_failure` — malformed entry |

---

## 5. the catalog publisher Deliverables

For each of the 8 adapters in §1.1, the catalog publisher must:

1. **Identify the commit to pin.**  
   `git ls-remote https://github.com/<org>/<repo> HEAD | awk '{print $1}'`

2. **Compute the tarball digest** (using the github-slug form, not `pkg@version`):
   ```sh
   npm pack github:<org>/<repo>#<full-40-hex-commit> \
     --pack-destination /tmp/chariot-git-pin/
   sha512sum /tmp/chariot-git-pin/*.tgz | awk '{print $1}'
   ```
   Result: 128 lowercase hex characters → `mcp.integrityShasum`

3. **Update the bundle row:**
   - `mcp.packageName` = `"github:<org>/<repo>#<commit-first-8>"`
   - `mcp.args` = `["--no-install", "github:<org>/<repo>#<commit-first-8>"]`
   - `mcp.gitUrl` = `"https://github.com/<org>/<repo>"`
   - `mcp.gitCommit` = `"<full-40-hex-sha>"`
   - `mcp.version` = `"0.0.0-git.<commit-first-8>"`
   - `mcp.integrityShasum` = `"<128-hex-sha512-from-step-2>"`

4. **Re-sign and publish the bundle** via the existing publication pipeline.

---

## 6. Implementation Status

| Item | Status |
|------|--------|
| Runtime guard (`npmIntegrityGuard.ts`) | **COMPLETE** — handles github-slug package names |
| `toolHandlers.ts` dispatch gate | **COMPLETE** — rejects all 8 unpinned adapters today |
| RegistryLoader field propagation | **COMPLETE** — propagates fields when present |
| the catalog publisher bundle population (8 adapters) | **PENDING** |
| `preinstall.ts:githubFetch` variant | **PENDING** — `npm pack <github-slug>` (no `@version`) |
| `loadAllAdapters()` malformed-field drop gate | **PENDING** — see §4.2 |

---

## 7. Testing Plan

After the catalog publisher populates the 8 adapter rows and `preinstall.ts:githubFetch` is implemented:

| Test | Expected |
|------|----------|
| `verifyNpmIntegrity(pkg="github:org/repo#sha8", version, goodSha)` | `ok: true` |
| `verifyNpmIntegrity` with wrong sha | `ok: false` |
| `guardNpmStdioAdapter` with `version="0.0.0-git.a1b2c3d4"` + good sha | `ok: true` |
| `guardNpmStdioAdapter` missing version | `ok: false` |
| `extractStdioPackageName({args: ["--no-install", "github:org/repo#a1b2c3d4"]})` | `"github:org/repo#a1b2c3d4"` ✓ (already verified) |
| preinstall: `githubFetch` runs `npm pack github:org/repo#commit` | warmed |
| preinstall: digest mismatch for github row | `INTEGRITY_MISMATCH` |
| catalog-load: `gitCommit` = `"abc"` (not 40-hex) | entry dropped |

---

*This document is the Chariot-side deliverable for the github-pin supply-chain work.
the catalog publisher populates the SHAs. The runtime guard is already deployed.
Two engine-side changes remain PENDING: `preinstall.ts:githubFetch` and
`loadAllAdapters()` field validation.*
