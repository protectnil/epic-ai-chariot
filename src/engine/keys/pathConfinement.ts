/**
 * @epicai/chariot — Defense-in-depth path confinement for `import(modulePath)`
 * sites and any other path field that originates outside the codebase
 * (signed catalog, on-disk manifest, caller-supplied adapter path).
 *
 * The lexical `path.resolve(root, p).startsWith(root + sep)` check
 * misses symlink escapes: if `<root>/x` is a symlink that points
 * outside the package, the lexical string still passes. realpath is
 * what the OS will actually open, so we resolve symlinks before
 * comparing. realpath fails closed — a non-existent path is rejected,
 * which is the correct behavior for an `import()` argument.
 */

import { realpathSync } from 'node:fs';
import { resolve, sep } from 'node:path';

export interface ConfinementResult {
  ok: boolean;
  resolved: string;
  reason?: 'escapes-root' | 'realpath-failed';
}

/**
 * Verify that `candidate` (resolved relative to `root`) lives inside
 * `root` after symlink resolution. Returns `{ ok: true, resolved }`
 * with the realpath-resolved path on success, or `{ ok: false, ... }`
 * with a typed reason on rejection.
 */
export function confinePath(candidate: string, root: string): ConfinementResult {
  const lexical = resolve(root, candidate);
  // realpathSync throws on ENOENT — caught below and reported as
  // realpath-failed. Doing a single syscall (vs `existsSync` + `realpathSync`)
  // closes the TOCTOU window between the existence check and the open.
  let realCandidate: string;
  let realRoot: string;
  try {
    realCandidate = realpathSync.native(lexical);
    realRoot = realpathSync.native(root);
  } catch {
    return { ok: false, resolved: lexical, reason: 'realpath-failed' };
  }
  if (realCandidate !== realRoot && !realCandidate.startsWith(realRoot + sep)) {
    return { ok: false, resolved: realCandidate, reason: 'escapes-root' };
  }
  return { ok: true, resolved: realCandidate };
}

/**
 * Bare command names that dispatch resolves via PATH rather than against the
 * package root. `confinePath` MUST NOT be applied to them — `resolve(root,
 * 'npx')` yields a non-existent path and rejects every legitimate stdio adapter
 * fail-closed. Instead, a bare launcher is accepted ONLY when it is on
 * this allowlist, and its supply-chain integrity is enforced by its own
 * downstream gate.
 *
 * SECURITY hardening: `npx` is the ONLY spec-sanctioned stdio
 * launcher. CHARIOT §1.4 Win-1 names exactly one mechanism — "npx --no-install,
 * never npx -y" launched from the local, integrity-verified copy — and the
 * signed catalog census is 172/172 stdio adapters on `npx`, zero on `node` or
 * `uvx`. `npx` carries a real target gate downstream (extractStdioPackageName →
 * guardNpmStdioAdapter SHA-512 cache verify → enforcePinnedArgs pkg@version +
 * npm_config_offline). `node <script>` and `uvx <pkg>` had NO equivalent
 * target gate — a bare `node`/`uvx` was blanket-trusted by NAME while its argv
 * (an arbitrary script path or arbitrary PyPI package) passed through
 * unverified, i.e. arbitrary-code execution. Per §1.4 fail-closed supply-chain
 * confinement they are REMOVED from the allowlist: a bare `node`/`uvx` command
 * is now refused `launcher-not-allowed`, exactly like `bash`/`curl`. A genuine
 * in-package script is still reachable via the script branch (a path-containing
 * command, confined to the package root by `confinePath`).
 */
export const STDIO_LAUNCHER_ALLOWLIST: readonly string[] = ['npx'];

export interface StdioCommandResult {
  ok: boolean;
  /**
   * The command to hand to StdioClientTransport: the bare launcher name (left
   * for PATH resolution) on the launcher branch, or the realpath-resolved
   * in-package absolute path on the script branch.
   */
  command: string;
  kind: 'launcher' | 'script';
  reason?: 'escapes-root' | 'realpath-failed' | 'launcher-not-allowed';
}

/**
 * Apply the correct trust boundary to a stdio launcher command, distinguishing
 * a PATH-resolved launcher from a package-relative script path:
 *
 *  - A BARE command name (no path separator) is a PATH-resolved launcher. It is
 *    accepted ONLY when it is on the allowlist (`npx` only — see
 *    STDIO_LAUNCHER_ALLOWLIST); the launcher's own pinning/integrity gate
 *    enforces supply-chain safety downstream. Any other bare executable —
 *    including `node`, `uvx`, `bash`, `curl`, `evil` — is refused fail-closed
 *    with `launcher-not-allowed`: it is NOT confined (that would silently pass
 *    through `resolve(root, name)` semantics), it is rejected.
 *
 *  - A command CONTAINING a path separator is a package-relative (or absolute)
 *    script path and MUST be confined to the package root via `confinePath`.
 *    Traversal, absolute escape, symlink escape, and non-existent paths are
 *    refused fail-closed with the confinePath reason.
 *
 * Shared by BOTH the `query` one-shot dispatch and the `serve` runtime dispatch
 * so the two trust boundaries are identical.
 */
export function confineStdioCommand(
  command: string,
  root: string,
  allowlist: readonly string[] = STDIO_LAUNCHER_ALLOWLIST,
): StdioCommandResult {
  const isBareName = !command.includes('/') && !command.includes(sep);
  if (isBareName) {
    if (allowlist.includes(command)) {
      return { ok: true, command, kind: 'launcher' };
    }
    return { ok: false, command, kind: 'launcher', reason: 'launcher-not-allowed' };
  }
  const confined = confinePath(command, root);
  if (!confined.ok) {
    return { ok: false, command: confined.resolved, kind: 'script', reason: confined.reason };
  }
  return { ok: true, command: confined.resolved, kind: 'script' };
}
