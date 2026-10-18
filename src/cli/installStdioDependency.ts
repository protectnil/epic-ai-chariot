/**
 * @epicai/chariot — shared stdio-adapter dependency installer, used by
 * both `chariot add <adapter>` and the setup wizard's step 4.
 * CHARIOT-SPEC.md:1409 (§17.2 step 4): "Dependency installation — for
 * stdio adapters (npm/pip/go/cargo/brew/binary)." CHARIOT::§17.2::10.
 *
 * MASTER ruling (rulings item 92, 2026-09-04): the 4.0 runtime launches
 * stdio adapters ONLY via `npx --no-install` (AS §1.1;
 * `MCPClientAdapter.ts` `INTEGRITY_GATED_STDIO_COMMANDS = {npx}`) — a
 * stdio adapter installed via pip/go/cargo/brew/binary would have no
 * launch path the dispatcher accepts. This helper therefore installs via
 * npm ONLY for 4.0, matching the runtime's own launch gate; the
 * pip/go/cargo/brew/binary managers stay reserved until AS §1.1 admits
 * those launch paths (see the spec-edit proposal for CHARIOT-SPEC.md:1409
 * in this unit's report). This is the SAME logic previously inlined in
 * `cmdAdd()` (`setup.ts`), extracted so the setup wizard's step 4 can call
 * it too instead of silently skipping dependency installation.
 *
 * W42-FIX (2026-09-04, rulings item 100 — row 1.42 proof, gap 1 of 3):
 * the pre-fix version of this helper ran `npm install -g --ignore-scripts
 * <packageName>` with NO version pin, so it installed the registry's
 * CURRENT `latest` dist-tag rather than the catalog's pinned
 * `mcp.version` — confirmed empirically (see `/tmp/scratch/wave3/w42/run/VERDICT.md`):
 * `chariot add 4fetch` installed `@amcharts/amcharts5-mcp@1.4.0` while the
 * catalog pinned `1.2.0`, so a later `npx --no-install
 * @amcharts/amcharts5-mcp@1.2.0` (the exact form the runtime launches
 * with) found nothing and failed. AS §1.1 sub-clause 1 (ADAPTER-STANDARD-MAY-2026.md:106-111,
 * "Pinned + integrity-stamped (catalog)") and sub-clause 2 (:112-114,
 * "Shipped or pre-fetched (install)... No package is acquired on first
 * use") both require the INSTALLED artifact to be the PINNED one, verified.
 * This version installs exactly `<packageName>@<version>` and then calls
 * `verifyNpmIntegrity()` (the SAME check `guardNpmStdioAdapter()` runs
 * before every dispatch, `npmIntegrityGuard.ts`) — success is reported
 * ONLY when the freshly-installed tarball's SHA-512 matches the catalog's
 * pinned `integrityShasum`. An adapter whose catalog row lacks a pinned
 * `version`/`integrityShasum` is refused up front (`reason: 'unpinned'`)
 * rather than falling back to an unpinned `npm install -g <bare-name>`.
 *
 * W42-FIX CORRECTION (2026-09-04, same wave): the initial version of this
 * fix gated on `adapter.mcp.packageName` — but a direct read of the REAL
 * signed catalog bundle (`chariot-adapter-bundle.json`, registry[]) shows
 * `mcp.packageName` is ABSENT on every stdio/npx row inspected (including
 * `4fetch`, which DOES carry `mcp.version`/`mcp.integrityShasum`); the
 * package name lives ONLY in `mcp.args` (e.g. `['-y',
 * '@amcharts/amcharts5-mcp']`). Gating on `packageName` alone would have
 * made this helper report `not-applicable` for every real catalog row —
 * a silent no-op regression, worse than the pre-fix behavior it replaces.
 * Package-name derivation below mirrors `extractStdioPackageName()`
 * (`src/engine/bin/concurrency.ts` — checks `mcp.packageName` first,
 * falls back to the first non-flag `mcp.args` entry), the established
 * rule for this exact ambiguity elsewhere in the codebase. Reimplemented
 * locally (2 lines) rather than imported: that function's parameter type
 * is the full engine-side `AdapterEntry` (`ChariotState.ts`, requires
 * `id`), which this CLI-layer helper's narrower `StdioInstallTarget`
 * does not carry and should not be forced to — this module already
 * avoids a hard dependency on the engine module graph (see
 * `VerifyNpmIntegrityFn` below, similarly duplicated rather than
 * imported).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export interface StdioInstallSpawnFn {
  (bin: string, argv: string[], timeoutMs: number): {
    error?: Error;
    status: number | null;
    signal: NodeJS.Signals | null;
  };
}

/**
 * Reason code for a `'failed'` result — lets callers/tests distinguish
 * "catalog row has no pin at all" from "the pinned install/verify itself
 * failed", without changing the `StdioInstallResult` discriminant (both
 * call sites already pattern-match on `status`, not on a reason field, so
 * this stays additive rather than requiring every existing `switch`/`if`
 * chain to grow a new case).
 */
export type StdioInstallFailureReason = 'unpinned' | 'spawn-failed' | 'integrity-mismatch';

export type StdioInstallResult =
  | { status: 'not-applicable' }
  | { status: 'installed' }
  | { status: 'failed'; manualCommand: string; reason: StdioInstallFailureReason };

export interface StdioInstallTarget {
  name: string;
  mcp?: {
    transport?: string;
    /** Rarely populated on real catalog rows — see the module-doc
     * correction above. Prefer `extractStdioPackageName()` over reading
     * this field directly. */
    packageName?: string;
    /** Real catalog rows carry the package spec here instead (e.g.
     * `['-y', '@scope/pkg']`) — `extractStdioPackageName()` falls back to
     * the first non-flag entry when `packageName` is absent. */
    args?: string[];
    /** AS §1.1 sub-clause 1 pin — REQUIRED together with `integrityShasum`
     * for this helper to attempt an install at all. */
    version?: string;
    /** AS §1.1 sub-clause 1 pin — 128-hex SHA-512 digest of the pinned
     * tarball, the SAME field `npmIntegrityGuard.ts`'s `verifyNpmIntegrity()`
     * checks against at dispatch time. */
    integrityShasum?: string;
  };
}

/**
 * `verifyNpmIntegrity()`'s exact signature (`npmIntegrityGuard.ts`) —
 * duplicated here as a narrow structural type (not an import of the full
 * module) so this CLI-layer helper does not take a hard dependency on the
 * engine's federation-adapter module graph; the real function is injected
 * by both callers.
 */
export type VerifyNpmIntegrityFn = (
  pkg: string,
  version: string,
  expectedSha: string,
) => { ok: true } | { ok: false; reason: string };

/** Derives the package name per the module-doc correction above. */
function derivePackageName(mcp: NonNullable<StdioInstallTarget['mcp']>): string | null {
  if (typeof mcp.packageName === 'string' && mcp.packageName.length > 0) return mcp.packageName;
  if (Array.isArray(mcp.args)) {
    const pkg = mcp.args.find((x): x is string => typeof x === 'string' && x.length > 0 && !x.startsWith('-'));
    if (pkg) return pkg;
  }
  return null;
}

/**
 * CHARIOT::§17.2::10 / AS::§1.1::11-16 — installs a stdio npm adapter's
 * PINNED package (name derived via `derivePackageName()` above) via `npm
 * install -g --ignore-scripts <packageName>@<version>` (array-form spawn,
 * no shell metacharacter exposure), then verifies the resulting cached
 * tarball against the catalog's pinned `integrityShasum` via the injected
 * `verifyNpmIntegrity` before ever reporting `'installed'`. Returns
 * `'not-applicable'` for any adapter that isn't a stdio/npm adapter with a
 * resolvable package name, and `{status:'failed', reason:'unpinned', ...}`
 * — never attempting an unpinned install — for a catalog row missing
 * `version` or `integrityShasum`. Never throws.
 */
export function installStdioDependency(
  adapter: StdioInstallTarget,
  spawnFn: StdioInstallSpawnFn,
  verifyNpmIntegrity: VerifyNpmIntegrityFn,
  timeoutMs = 60_000,
): StdioInstallResult {
  const packageName = adapter.mcp?.transport === 'stdio' ? derivePackageName(adapter.mcp) : null;
  if (!packageName) {
    return { status: 'not-applicable' };
  }
  const version = adapter.mcp?.version;
  const integrityShasum = adapter.mcp?.integrityShasum;
  if (!version || !integrityShasum) {
    return {
      status: 'failed',
      reason: 'unpinned',
      manualCommand:
        `Catalog entry "${adapter.name}" (${packageName}) has no pinned version/integrityShasum — ` +
        'air-gap install requires both (AS §1.1 sub-clause 1). Cannot install unpinned.',
    };
  }
  const pinned = `${packageName}@${version}`;
  try {
    const r = spawnFn('npm', ['install', '-g', '--ignore-scripts', '--', pinned], timeoutMs);
    if (r.error || (r.status !== null && r.status !== 0) || r.signal) {
      return { status: 'failed', reason: 'spawn-failed', manualCommand: `npm install -g ${pinned}` };
    }
  } catch {
    return { status: 'failed', reason: 'spawn-failed', manualCommand: `npm install -g ${pinned}` };
  }
  // AS §1.1 sub-clause 2 — verify the freshly-installed artifact against
  // the pin BEFORE reporting success; a global install that happened to
  // resolve some other version/tampered bytes must not read as "installed".
  const verified = verifyNpmIntegrity(packageName, version, integrityShasum);
  if (!verified.ok) {
    return { status: 'failed', reason: 'integrity-mismatch', manualCommand: `npm install -g ${pinned}` };
  }
  return { status: 'installed' };
}
