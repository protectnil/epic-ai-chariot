/**
 * @epicai/chariot — Audit Filesystem Helpers
 *
 * Shared persist helper for the append-only audit sub-directories.
 * Extracts the mkdirSync + writeFileSync(wx) pattern that previously
 * appeared independently in anchor.ts and length-attestation.ts.
 *
 * Security note: the 'wx' flag (O_EXCL) is the load-bearing invariant —
 * it causes writeFileSync to fail atomically if the target already exists.
 * Keeping this in one place prevents a future patch from accidentally
 * weakening the flag in one of the call sites.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Atomically write a new file into `dir/filename`.
 * Creates `dir` (and all parents) if it does not already exist.
 * Throws with `code: 'EEXIST'` if the file already exists — callers
 * that need collision handling must catch that error and retry with a
 * different filename (see `persistAttestation` for the dup-suffix pattern).
 *
 * @param dir      Target directory (absolute path).
 * @param filename Filename within `dir`.
 * @param data     Content to write (Buffer or UTF-8 string).
 * @param opts     Optional permission overrides.
 *                 `dirMode`  — directory mode bits (default 0o755)
 *                 `fileMode` — file mode bits (default 0o644)
 * @returns        The full absolute path of the written file.
 */
export function atomicWriteNew(
  dir: string,
  filename: string,
  data: Buffer | string,
  opts: { dirMode?: number; fileMode?: number } = {},
): string {
  const dirMode = opts.dirMode ?? 0o755;
  const fileMode = opts.fileMode ?? 0o644;
  mkdirSync(dir, { recursive: true, mode: dirMode });
  const fullPath = join(dir, filename);
  writeFileSync(fullPath, data, { mode: fileMode, flag: 'wx' });
  return fullPath;
}
