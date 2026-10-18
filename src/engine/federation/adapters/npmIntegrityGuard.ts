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
 *   - When integrityShasum is set, we check that the pinned blob exists AND
 *     re-hash its bytes to confirm they match the pin. The path is derived
 *     from the PIN, so existence alone does NOT prove correct bytes: a blob
 *     written directly to the filesystem (the local-cache-tamper threat this
 *     gate defends) could sit at the pinned path with non-matching content.
 *     Do not trust filename ⟺ content.
 *   - The tarball identity is also checked against the declared
 *     `pkg@version`: after the SHA matches, the guard inspects the embedded
 *     `package/package.json` and fails closed unless its `name` and
 *     `version` fields match the pinned catalog entry. This rejects a
 *     correct-SHA blob for the wrong package/version pair.
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

import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { gunzipSync } from 'node:zlib';
import { extractStdioPackageName } from '../../bin/concurrency.js';
import type { AdapterEntry } from '../../server/ChariotState.js';

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

function readTarString(block: Buffer, start: number, end: number): string {
  const raw = block.subarray(start, end).toString('utf8');
  return raw.replace(/\0.*$/, '').trim();
}

function parseTarOctal(block: Buffer, start: number, end: number): number {
  const raw = readTarString(block, start, end);
  if (!raw) return 0;
  return Number.parseInt(raw, 8);
}

function readCachedPackageIdentity(tarballPath: string): { name: string; version: string } | null {
  let tarBytes: Buffer;
  try {
    tarBytes = gunzipSync(readFileSync(tarballPath));
  } catch {
    return null;
  }

  for (let offset = 0; offset + 512 <= tarBytes.length;) {
    const header = tarBytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) return null;

    const size = parseTarOctal(header, 124, 136);
    const name = readTarString(header, 0, 100);
    const prefix = readTarString(header, 345, 500);
    const fullName = prefix ? `${prefix}/${name}` : name;
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;

    if (fullName === 'package/package.json' || fullName === 'package.json') {
      try {
        const parsed = JSON.parse(tarBytes.subarray(dataStart, dataEnd).toString('utf8')) as {
          name?: unknown;
          version?: unknown;
        };
        if (typeof parsed.name === 'string' && typeof parsed.version === 'string') {
          return { name: parsed.name, version: parsed.version };
        }
      } catch {
        return null;
      }
    }

    offset = dataStart + Math.ceil(size / 512) * 512;
  }

  return null;
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

  // Do NOT trust the content-address filename alone: the path is derived from
  // the pin, so a blob written directly to disk (local-cache tamper) could
  // occupy the pinned path with non-matching bytes. Re-hash the actual bytes
  // and fail closed on any mismatch.
  let actualSha: string;
  try {
    actualSha = createHash('sha512').update(readFileSync(contentPath)).digest('hex');
  } catch (err) {
    return {
      ok: false,
      reason:
        `air-gap: ${pkg}@${version} — cached tarball at ${contentPath} could not be read ` +
        `for verification: ${(err as Error).message}. Run \`chariot setup --pre-install\` to repopulate.`,
    };
  }
  if (actualSha !== expectedSha.toLowerCase()) {
    return {
      ok: false,
      reason:
        `air-gap: ${pkg}@${version} — cached tarball bytes at ${contentPath} do NOT match the pinned ` +
        `SHA-512 (content tampered). Refusing to spawn. Run \`chariot setup --pre-install\` to repopulate.`,
    };
  }

  const cachedIdentity = readCachedPackageIdentity(contentPath);
  if (!cachedIdentity) {
    return {
      ok: false,
      reason:
        `air-gap: ${pkg}@${version} — cached tarball at ${contentPath} did not expose a verifiable ` +
        `package/package.json identity. Refusing to spawn. Run \`chariot setup --pre-install\` to repopulate.`,
    };
  }

  if (cachedIdentity.name !== pkg || cachedIdentity.version !== version) {
    return {
      ok: false,
      reason:
        `air-gap: ${pkg}@${version} — cached tarball identity ${cachedIdentity.name}@${cachedIdentity.version} ` +
        `does not match the pinned catalog entry. Refusing to spawn. Run \`chariot setup --pre-install\` to repopulate.`,
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

  const verified = verifyNpmIntegrity(pkg, version, shasum);
  if (!verified.ok) {
    // AS::§1.1::16 (ADAPTER-STANDARD-MAY-2026.md:128) pins the EXACT
    // fail-closed message for "the package is absent or the hash
    // mismatches": `air-gapped: <id> not present (expected
    // <packageName>@<packageVersion>)`. `verifyNpmIntegrity()` (above) has
    // no adapterId in scope and returns a diagnostic-detail reason instead;
    // this is the one caller-facing layer that DOES carry adapterId
    // (per this function's own @param doc), so it is the correct place to
    // emit the literal pinned string — the diagnostic detail is preserved
    // as a trailing clause rather than dropped, for operator remediation.
    return {
      ok: false,
      reason: `air-gapped: ${adapterId} not present (expected ${pkg}@${version}) — ${verified.reason}`,
    };
  }
  return verified;
}

/**
 * Build the SINGLE safe npx argv for a pinned, integrity-verified stdio adapter,
 * shared by every npx dispatch path (enforceNpxStdioGate → serve+query, and the
 * federation MCPClientAdapter): `npx --no-install <pkg@version> [server-args]`.
 *
 * Two properties, both required by CHARIOT §1.4 Win-1 ("launched from the local
 * copy, `npx --no-install`, never `npx -y` registry fetch"):
 *   1. `--no-install` (NOT `-y`/`--yes`) — npx launches ONLY the pre-fetched,
 *      integrity-verified local copy. No registry fetch AND no install step, so
 *      NO npm lifecycle scripts (preinstall/postinstall/prepare) run at dispatch
 *      (npm_config_ignore_scripts does NOT reliably stop npx's target postinstall
 *      on a cold link; --no-install does, by never installing). Absent package →
 *      fail closed, never fetch.
 *   2. Pinned `pkg@version` as the sole command positional — npx cannot
 *      re-resolve `latest` from the registry, so what spawns is what the SHA-512
 *      guard verified. The spawner also sets `npm_config_offline` as belt-and-braces.
 *
 * The package token (bare `pkg`, `pkg@version`, or `pkg@<tag>`) and any install
 * flag (`-y`/`--yes`/`--no-install`) are stripped from the incoming args; the
 * remainder are genuine server args passed to the package's bin. Returns a NEW
 * array; never mutates `args`. `packageFromArgs` is retained for signature
 * compatibility but no longer affects the result (the token is stripped wherever
 * it appears). npx control-execution flags (`-c`/`--call`/`-p`/`--package`) are
 * rejected upstream by enforceNpxStdioGate, not here.
 */
export function enforcePinnedArgs(
  args: readonly string[] | undefined,
  pkg: string,
  version: string,
  _packageFromArgs = false,
): string[] {
  const pinned = `${pkg}@${version}`;
  const source = [...(args ?? [])];
  let serverArgs: string[];
  if (_packageFromArgs) {
    let replaced = false;
    serverArgs = source.map((arg) => {
      if (!replaced && (arg === pkg || arg === pinned || arg.startsWith(`${pkg}@`))) {
        replaced = true;
        return pinned;
      }
      return arg;
    });
    if (!replaced) serverArgs = [pinned, ...serverArgs];
    return ['--no-install', ...serverArgs.filter((a) => a !== '-y' && a !== '--yes' && a !== '--no-install')];
  }
  if ((source[0] === '-y' || source[0] === '--yes' || source[0] === '--no-install') && source.length >= 2) {
    serverArgs = source.slice(2);
  } else {
    serverArgs = source;
  }
  return ['--no-install', pinned, ...serverArgs];
}

/**
 * Environment-variable names that let a spawned child execute attacker code
 * BEFORE (or instead of) the intended program — a code-execution channel that
 * bypasses argv gating entirely: e.g. NODE_OPTIONS='--require
 * /tmp/evil.js' preloads evil.js into npx's node, LD_PRELOAD / DYLD_INSERT_
 * LIBRARIES inject a shared object into any dynamically-linked binary,
 * BASH_ENV runs a file when a child invokes bash. A catalog row MUST NOT be
 * able to forward any of these into a spawned stdio subprocess via mcp.envKeys,
 * regardless of what it declares. Matched case-insensitively so obfuscation by
 * case (on case-insensitive platforms) is also refused.
 *
 * Hardening: npm/npx ALSO reads every CLI option from an `npm_config_<opt>`
 * env alias, so `npm_config_call='node -e "…"'` is exactly `npx --call …` and
 * `npm_config_package` / `npm_config_registry` re-inject a package or redirect
 * resolution — a code-exec/supply-chain channel that survives the argv gate.
 * Every `npm_config_*` name is therefore also dangerous (see isDangerousStdioEnvKey).
 * The engine's own `npm_config_offline` is set AFTER the strip, so it is never
 * sourced from a catalog row.
 */
export const DANGEROUS_STDIO_ENV_KEYS: ReadonlySet<string> = new Set([
  'NODE_OPTIONS', 'NODE_REPL_EXTERNAL_MODULE',
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT',
  'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH',
  'BASH_ENV', 'ENV',
]);

/**
 * True when `key` is a code-execution / preload / npm-config-injection channel
 * that must never be forwarded to a spawned adapter subprocess. Covers the
 * explicit denylist above AND every `npm_config_*` alias (npm reads its full
 * option surface from these — `npm_config_call`, `npm_config_package`,
 * `npm_config_registry`, …).
 */
export function isDangerousStdioEnvKey(key: string): boolean {
  return DANGEROUS_STDIO_ENV_KEYS.has(key.toUpperCase()) || /^npm_config_/i.test(key);
}

/**
 * Strip every code-execution / preload env channel from a subprocess env,
 * IN PLACE, and return it. Last-line-of-defense used by BOTH stdio dispatch
 * paths right before spawn, so a preload var can never reach the child no
 * matter how it entered the env map (mcp.envKeys forwarding, an inherited base,
 * or a future code path).
 */
export function stripDangerousStdioEnv(env: Record<string, string>): Record<string, string> {
  for (const k of Object.keys(env)) {
    if (isDangerousStdioEnvKey(k)) delete env[k];
  }
  return env;
}

/** Result of the shared npx stdio supply-chain gate. */
export interface NpxStdioGateResult {
  ok: boolean;
  /** argv to spawn with: for npx, pinned + rewritten; for a non-npx passthrough, unchanged. */
  spawnArgs: string[];
  /** When true the caller MUST set npm_config_offline=true in the subprocess env. */
  offline: boolean;
  /** Populated only when ok===false. */
  reason?: string;
}

/**
 * Single source of truth for the npx stdio supply-chain gate, shared by BOTH the
 * `serve` dispatch (toolHandlers.handleCall) and the `query` one-shot dispatch
 * (setup.cmdQuery) so the two trust boundaries are provably identical.
 *
 * The query path previously spawned StdioClientTransport
 * after ONLY confineStdioCommand — with NO package/integrity/pin gate — so a
 * catalog row `{command:"npx", args:["-y","evil-pkg"]}` reached spawn unpinned and
 * npx re-resolved it from the registry (arbitrary-code execution). Serve had the
 * gate inline; query did not, and a comment falsely claimed the two boundaries
 * matched. This helper is the shared gate both now call, applying to an npx
 * command the exact serve-path sequence:
 *   1. resolve the package name (extractStdioPackageName) — malformed → fail
 *   2. guardNpmStdioAdapter — SHA-512 local-cache verify; unpinned/absent → fail
 *   3. enforcePinnedArgs — rewrite argv to pkg@version so npx cannot re-resolve
 *      `latest`; caller sets npm_config_offline so resolution is served ONLY from
 *      the verified cache and fails closed when absent.
 * A non-npx command is a passthrough: the launcher allowlist
 * (STDIO_LAUNCHER_ALLOWLIST = ['npx']) has already rejected every other bare
 * launcher, and script paths are confined to the package root upstream by
 * confineStdioCommand — so `command` here is either `npx` or an in-package script.
 */
export function enforceNpxStdioGate(adapter: AdapterEntry): NpxStdioGateResult {
  const args = [...(adapter.mcp?.args ?? [])];
  if (adapter.mcp?.command !== 'npx') {
    return { ok: true, spawnArgs: args, offline: false };
  }
  // Pinning the PACKAGE is not sufficient — npx has
  // its own control-execution flags that run arbitrary code irrespective of the
  // pin, and npx parses them ANYWHERE in argv (not just before the command), so
  // enforcePinnedArgs reordering does not neutralize them:
  //   -c / --call <string>   → runs the string as a SHELL command
  //   -p / --package <spec>  → injects an additional package to install/run
  // e.g. `npx --package=npm --call 'node -e "…"'` executes the -e payload even
  // with a valid pinned package present. Reject these fail-closed. The only
  // legitimate curated form is `npx -y <pkg@version> [server-args]` (server args
  // are passed to the package's bin, not npx); catalog census: 0/516 npx rows
  // use any of these flags, so this refuses attacks without touching real
  // adapters. A server bin flag that must be `-p`/`-c` is passed after a `--`
  // separator (npx end-of-options), which is not matched here.
  const NPX_EXEC_FLAG = /^(-c|--call|-p|--package)(=|$)/;
  const danger = args.find((a): a is string => typeof a === 'string' && NPX_EXEC_FLAG.test(a));
  if (danger !== undefined) {
    return {
      ok: false,
      spawnArgs: [],
      offline: false,
      reason: `air-gap: ${adapter.id} npx args contain the control-execution flag "${danger}" — npx -c/--call runs an arbitrary shell command and -p/--package injects a package, both bypassing the package pin. Refusing to spawn.`,
    };
  }
  const pkg = extractStdioPackageName(adapter);
  if (!pkg) {
    return {
      ok: false,
      spawnArgs: [],
      offline: false,
      reason: `air-gap: ${adapter.id} uses npx but no package name is resolvable from the adapter entry. Catalog may be malformed.`,
    };
  }
  const guard = guardNpmStdioAdapter(adapter.id, pkg, adapter.mcp.version, adapter.mcp.integrityShasum);
  if (!guard.ok) {
    return { ok: false, spawnArgs: [], offline: false, reason: guard.reason };
  }
  // guardNpmStdioAdapter fails closed when version is absent, so it is set here.
  const version = adapter.mcp.version;
  if (!version) {
    return { ok: false, spawnArgs: [], offline: false, reason: `air-gap: ${adapter.id} npx row is unpinned (no version).` };
  }
  // Single-source safe argv: `npx --no-install <pkg@version> [server-args]`
  // (§1.4 Win-1). See enforcePinnedArgs — --no-install runs only the pre-fetched
  // local copy, so no install step and no lifecycle scripts execute at dispatch.
  const packageFromArgs = !(typeof adapter.mcp.packageName === 'string' && adapter.mcp.packageName.length > 0);
  const spawnArgs = enforcePinnedArgs(args, pkg, version, packageFromArgs);
  return { ok: true, spawnArgs, offline: true };
}
