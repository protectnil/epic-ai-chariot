/**
 * @epicai/chariot — seccomp confinement wrapper resolver
 * GAP #11 (Wiz "isolate and sandbox"): on the `npx @epicai/chariot`
 * self-hosted path there is no pod, so no K8s NetworkPolicy/seccomp
 * admission controls apply (see helm/chariot for the in-cluster
 * equivalents, GAP #8/#10). Confinement for spawned adapter children must
 * instead be applied to the child process itself.
 *
 * `native/chariot-seccomp-wrapper` (built by scripts/build-seccomp-wrapper.mjs
 * from native/src/bin/seccomp_wrapper.rs) installs a seccomp-bpf deny-list
 * filter + no_new_privs, then execve()s into the real target. Linux/x86_64
 * only — Linux-guarded here so `npm install` / adapter startup on macOS and
 * Windows is completely unaffected (this resolver simply returns null there,
 * which is the existing, unconfined-but-unchanged behavior).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve as pathResolve, dirname } from 'node:path';

// dist/engine/federation/sandbox/seccompWrapper.js -> package root
const PACKAGE_ROOT = pathResolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
export const SECCOMP_WRAPPER_PATH = pathResolve(PACKAGE_ROOT, 'native', 'chariot-seccomp-wrapper');

/**
 * Returns the absolute path to the seccomp confinement wrapper binary, or
 * null when it cannot/should not be used:
 *  - always null on non-Linux (clean no-op; matches today's behavior there)
 *  - null on Linux when the binary hasn't been built (e.g. an npm install
 *    where the Rust toolchain wasn't available). This is a WARN-and-degrade
 *    path, not a silent claim of confinement — callers must log distinctly
 *    from the "confined" path when they receive null on Linux.
 */
export function resolveSeccompWrapper(): string | null {
  if (process.platform !== 'linux') return null;
  try {
    if (existsSync(SECCOMP_WRAPPER_PATH)) return SECCOMP_WRAPPER_PATH;
  } catch {
    // fall through to null
  }
  return null;
}
