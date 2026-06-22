/**
 * @epicai/chariot — Runtime npm stdio adapter integrity guard
 *
 * Verifies that a locally-cached npm package tarball matches the SHA-512 hex
 * digest pinned in the adapter catalog (AdapterEntry.mcp.integrityShasum)
 * BEFORE the adapter subprocess is spawned.
 *
 * Design:
 *   - npm stores downloaded tarballs content-addressed under
 *     <cache>/content-v2/sha512/<first-2>/<next-2>/<remainder>.
 *   - When integrityShasum is set, we check that exactly that file exists.
 *     Content-addressable storage means existence ⟺ the correct bytes are
 *     present; no re-hashing is needed.
 *   - When integrityShasum is absent the guard fails CLOSED: the adapter
 *     cannot be spawned at runtime without a pinned hash, even if
 *     npx --no-install would otherwise succeed.  This enforces that every
 *     npm stdio adapter must carry supply-chain provenance before runtime use.
 *   - When the cache entry is missing (hash not found on disk) the guard
 *     fails closed with a clear message instructing the operator to run
 *     `chariot setup --pre-install` to populate the cache.
 *
 * Air-gap guarantee:
 *   The guard never calls npm at runtime.  If the expected file is absent,
 *   the error is unambiguous ("run chariot setup --pre-install") — we do NOT
 *   fall back to `npx -y` or any network fetch.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

// ── npm cache path resolution ─────────────────────────────────────────────

/**
 * Resolve the base npm cache directory.
 * Order: CHARIOT_NPM_CACHE_DIR env (test injection point) →
 *        NPM_CONFIG_CACHE env (npm respects this) →
 *        ~/.npm default.
 */
function npmCacheBase(): string {
  return (
    process.env.CHARIOT_NPM_CACHE_DIR ??
    process.env.NPM_CONFIG_CACHE ??
    join(homedir(), '.npm')
  );
}

/**
 * Resolve the content-addressed path for a SHA-512 hex digest inside
 * the npm `_cacache/content-v2/sha512/` tree.
 *
 * npm splits the hex into 2+2+rest:
 *   sha512/<first2>/<next2>/<rest>
 */
function contentV2Path(sha512hex: string, cacheBase: string): string {
  // npm requires exactly 128 hex chars for sha512
  return join(cacheBase, '_cacache', 'content-v2', 'sha512',
    sha512hex.slice(0, 2),
    sha512hex.slice(2, 4),
    sha512hex.slice(4),
  );
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Outcome of the integrity guard check.
 *
 * - `ok: true`  — the pinned tarball is present in the local npm cache;
 *                 the adapter subprocess may be spawned.
 * - `ok: false` — the adapter must NOT be spawned; `reason` contains a
 *                 human-readable explanation.
 */
export type IntegrityGuardResult =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * Verify that the npm package `pkg@version` is present in the local cache
 * with the expected SHA-512 hex digest.
 *
 * Called in the stdio dispatch path (toolHandlers.ts) and MCPClientAdapter
 * BEFORE spawning any subprocess.  Never throws — all failure modes are
 * returned as `{ ok: false, reason }` so callers can emit a structured error.
 *
 * @param pkg            npm package name (e.g. `@modelcontextprotocol/server-filesystem`)
 * @param version        pinned version string (e.g. `0.6.2`)
 * @param expectedSha    SHA-512 hex digest from AdapterEntry.mcp.integrityShasum
 */
export function verifyNpmIntegrity(
  pkg: string,
  version: string,
  expectedSha: string,
): IntegrityGuardResult {
  // Basic shape validation — catch obviously-corrupt catalog rows early.
  if (!expectedSha || !/^[0-9a-f]{128}$/i.test(expectedSha)) {
    return {
      ok: false,
      reason:
        `air-gap: ${pkg}@${version} — integrityShasum is not a valid 128-char SHA-512 hex string. ` +
        `Run \`chariot setup --pre-install\` to rebuild the adapter bundle.`,
    };
  }

  const cacheBase = npmCacheBase();
  const contentPath = contentV2Path(expectedSha.toLowerCase(), cacheBase);

  if (!existsSync(contentPath)) {
    return {
      ok: false,
      reason:
        `air-gap: ${pkg}@${version} — expected tarball not found in npm cache ` +
        `(${contentPath}). ` +
        `Run \`chariot setup --pre-install\` to download and verify the adapter package.`,
    };
  }

  return { ok: true };
}

/**
 * Enforce integrity for a stdio adapter before spawning.
 *
 * When `version` and `integrityShasum` are both set on the adapter entry,
 * calls `verifyNpmIntegrity` and returns the result.
 *
 * When either field is absent the guard FAILS CLOSED — an unpinned
 * adapter is not permissible at runtime regardless of whether npx would
 * otherwise succeed.
 *
 * @param adapterId   human-readable adapter id for error messages
 * @param pkg         npm package name resolved from the adapter entry
 * @param version     AdapterEntry.mcp.version (undefined → fail-closed)
 * @param shasum      AdapterEntry.mcp.integrityShasum (undefined → fail-closed)
 */
export function guardNpmStdioAdapter(
  adapterId: string,
  pkg: string,
  version: string | undefined,
  shasum: string | undefined,
): IntegrityGuardResult {
  if (!version || !shasum) {
    const missing = !version && !shasum ? 'version and integrityShasum' : !version ? 'version' : 'integrityShasum';
    return {
      ok: false,
      reason:
        `air-gap: ${adapterId} (${pkg}) is missing ${missing} in the adapter catalog. ` +
        `Unpinned npm stdio adapters cannot be launched at runtime. ` +
        `Run \`chariot setup --pre-install\` after the catalog is updated with supply-chain metadata.`,
    };
  }

  return verifyNpmIntegrity(pkg, version, shasum);
}

/**
 * Rewrite npx spawn args so the subprocess executes EXACTLY the version the
 * integrity guard verified, instead of whatever the registry calls `latest`.
 *
 * Catalog rows carry unversioned args (e.g. `["-y", "@scope/pkg"]`). Passing
 * those to npx verbatim re-resolves the package against the registry at
 * spawn time, so a registry-side publish could swap the code out from under
 * a verified pin (bug-tracker-ref). This helper replaces the bare package token with
 * `pkg@version`; the spawner must additionally set `npm_config_offline` so
 * resolution is served from the local cache the guard just verified and the
 * spawn fails closed when it is absent.
 *
 * Returns a NEW array; never mutates `args`. Behaviour depends on whether the
 * package token lives IN `args` (`packageFromArgs`, set by the caller from the
 * manifest shape):
 *   • packageFromArgs=true  — the package token is matched in any form (bare
 *     `pkg`, `pkg@version`, or `pkg@<other-tag>` such as `pkg@latest`) and
 *     replaced IN PLACE, preserving trailing subcommands/flags. If no token for
 *     this package is present, falls back to `['-y', 'pkg@version']`.
 *   • packageFromArgs=false — the package came from `mcp.packageName`, so `args`
 *     carries only subcommands/flags (or a foreign/inferred package token at
 *     index 1 after `-y`). The pinned package is spliced in as `['-y', pinned,
 *     …tail]`: a leading `-y <token>` pair is dropped (that token is the foreign
 *     package, not a subcommand) and the remaining args are preserved.
 */
export function enforcePinnedArgs(
  args: readonly string[] | undefined,
  pkg: string,
  version: string,
  packageFromArgs = false,
): string[] {
  const pinned = `${pkg}@${version}`;
  const source = args ?? [];

  if (packageFromArgs) {
    let replaced = false;
    const out = source.map((arg) => {
      if (!replaced && (arg === pkg || arg === pinned || arg.startsWith(`${pkg}@`))) {
        replaced = true;
        return pinned;
      }
      return arg;
    });
    return replaced ? out : ['-y', pinned];
  }

  if (source[0] === '-y' && source.length >= 2) {
    return ['-y', pinned, ...source.slice(2)];
  }

  return ['-y', pinned, ...source];
}
