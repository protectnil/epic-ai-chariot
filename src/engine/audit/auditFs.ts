/**
 * @epicai/chariot — Audit Filesystem Helpers
 *
 * Shared persist helper for the append-only audit sub-directories.
 * Extracts the mkdirSync + write-temp/fsync/rename pattern that previously
 * appeared independently in anchor.ts and length-attestation.ts.
 *
 * Security note: the 'wx' flag (O_EXCL) is applied to the TEMP file to
 * prevent races; the final rename is atomic on POSIX. Data integrity is
 * ensured by fdatasync() before rename so a crash after rename leaves a
 * complete file rather than a partial write. Keeping this in one place
 * prevents a future patch from accidentally weakening the invariant.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { mkdirSync, openSync, writeSync, fdatasyncSync, closeSync, renameSync, existsSync, unlinkSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

/**
 * Crash-safe atomic write of a new file into `dir/filename`.
 * Creates `dir` (and all parents) if it does not already exist.
 * Throws with `code: 'EEXIST'` if the target file already exists — callers
 * that need collision handling must catch that error and retry with a
 * different filename (see `persistAttestation` for the dup-suffix pattern).
 *
 * Write strategy: write to `<dir>/<filename>.tmp-<random>` with O_EXCL
 * (prevents races against a concurrent writer), fdatasync to flush kernel
 * buffers to storage, then rename to the final path. A crash after rename
 * leaves a complete file; a crash before rename leaves an orphaned temp
 * file (harmless — no reader references it).
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

  const finalPath = join(dir, filename);

  // Preserve the EEXIST contract (callers like persistAttestation rely on it
  // to detect collisions and retry with a dup-suffix). Check before writing the
  // temp file so we never leave an orphan when the target already exists.
  if (existsSync(finalPath)) {
    const err: NodeJS.ErrnoException = new Error(
      `EEXIST: file already exists, open '${finalPath}'`,
    );
    err.code = 'EEXIST';
    throw err;
  }

  const tmpPath = join(dir, `${filename}.tmp-${randomBytes(6).toString('hex')}`);

  // Write to the temp file with O_EXCL (prevents a concurrent writer from
  // clobbering it), fdatasync to flush kernel buffers to storage, then rename
  // to the final path. rename(2) is atomic on POSIX — a crash after rename
  // leaves a complete file; a crash before rename leaves an orphaned temp file
  // (harmless, no reader references it by its temp name).
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf-8');
  const fd = openSync(tmpPath, 'wx', fileMode);
  try {
    writeSync(fd, buf);
    fdatasyncSync(fd);
  } finally {
    closeSync(fd);
  }

  try {
    renameSync(tmpPath, finalPath);
  } catch (err) {
    // Best-effort temp-file cleanup on rename failure; ignore secondary errors.
    try { unlinkSync(tmpPath); } catch { /* ignore */ }
    throw err;
  }

  return finalPath;
}

/**
 * Crash-safe atomic OVERWRITE of an existing file at `dir/filename` (or
 * creates it if absent). Unlike `atomicWriteNew`, this is explicitly for
 * updating an artifact in place — CH-10 upgrade-on-decrypt (CHARIOT §12.2,
 * rulings item 59) re-persists a sealed signing-key artifact with a
 * freshly re-encrypted ciphertext, and that file already exists by
 * definition (it was just read). Same write-temp/fsync/rename strategy as
 * `atomicWriteNew` — a crash after rename leaves a complete file; a crash
 * before rename leaves the original file untouched (the temp file is
 * orphaned, harmless).
 */
export function atomicOverwrite(
  dir: string,
  filename: string,
  data: Buffer | string,
  opts: { dirMode?: number; fileMode?: number } = {},
): string {
  const dirMode = opts.dirMode ?? 0o755;
  const fileMode = opts.fileMode ?? 0o644;
  mkdirSync(dir, { recursive: true, mode: dirMode });

  const finalPath = join(dir, filename);
  const tmpPath = join(dir, `${filename}.tmp-${randomBytes(6).toString('hex')}`);

  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf-8');
  const fd = openSync(tmpPath, 'wx', fileMode);
  try {
    writeSync(fd, buf);
    fdatasyncSync(fd);
  } finally {
    closeSync(fd);
  }

  try {
    renameSync(tmpPath, finalPath);
  } catch (err) {
    try { unlinkSync(tmpPath); } catch { /* ignore */ }
    throw err;
  }

  return finalPath;
}

/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10). Rulings item 59: the
 * upgrade-on-decrypt write-back "MUST persist {encrypted, iv} back to the
 * SAME record, in the SAME operation" — for the sealed-store artifact
 * (a plain JSON file, not a database row), that is a compare-and-set: the
 * on-disk bytes are re-read and compared to `expectedCurrentBytes` (the
 * bytes read BEFORE the caller decrypted/decided to upgrade) immediately
 * before replacing them. A mismatch means a concurrent writer (another
 * process running the same upgrade, a rotation, an operator import) has
 * already changed the file — treated as a benign no-op, never a clobber.
 *
 * HONEST LIMIT: this is read-compare-write, not a single atomic syscall —
 * there is an inherent TOCTOU window between the compare and the rename
 * this function cannot close without OS-level file locking, which this
 * single-operator, low-write-frequency artifact (rotated/imported/
 * upgraded, never concurrently hot-written) does not warrant. What IS
 * still guaranteed regardless: `atomicOverwrite`'s temp-file+fsync+rename
 * means any crash mid-write leaves either the untouched original or a
 * complete replacement, never a partial/corrupt file.
 */
export function atomicOverwriteIfUnchanged(
  dir: string,
  filename: string,
  expectedCurrentBytes: Buffer | string,
  newBytes: Buffer | string,
  opts: { dirMode?: number; fileMode?: number } = {},
): { written: boolean; path: string } {
  const finalPath = join(dir, filename);
  const expectedBuf = Buffer.isBuffer(expectedCurrentBytes)
    ? expectedCurrentBytes
    : Buffer.from(expectedCurrentBytes, 'utf-8');

  let onDisk: Buffer;
  try {
    onDisk = readFileSync(finalPath);
  } catch {
    // Missing (deleted concurrently, or never existed) — do not blindly
    // create it; that is not what a caller expecting to UPDATE an
    // existing artifact asked for.
    return { written: false, path: finalPath };
  }

  if (!onDisk.equals(expectedBuf)) {
    return { written: false, path: finalPath };
  }

  const path = atomicOverwrite(dir, filename, newBytes, opts);
  return { written: true, path };
}
