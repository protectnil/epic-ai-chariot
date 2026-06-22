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
