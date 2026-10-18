/**
 * @epicai/chariot — streaming SHA-256 of a regular file.
 *
 * CHARIOT §5.7 envelope fields (AMENDED 2026-10-14): the file-reference form
 * `"ciphertext": { "file": "<basename>", "sha256": "<hex SHA-256 of that
 * file>" }` names "a regular file, not a symbolic link". A real catalog
 * shard ciphertext is hundreds of megabytes, so it is hashed in fixed 1 MiB
 * chunks (bounded memory, never a JS string). The file is opened
 * `O_RDONLY|O_NOFOLLOW` (a symlink at the final component fails the open)
 * and `fstat`-checked on the SAME descriptor that is read, so the
 * regular-file check and the hashed bytes refer to one inode.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createHash } from 'node:crypto';
import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from 'node:fs';

const CHUNK_BYTES = 1 << 20;

/** Lowercase hex SHA-256 of the regular file at `path`. Throws when `path`
 * is missing, is a symbolic link, or is not a regular file. */
export function sha256FileHex(path: string): string {
  const fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    if (!fstatSync(fd).isFile()) throw new Error(`${path} is not a regular file`);
    const hash = createHash('sha256');
    const buf = Buffer.allocUnsafe(CHUNK_BYTES);
    for (;;) {
      const n = readSync(fd, buf, 0, CHUNK_BYTES, null);
      if (n === 0) break;
      hash.update(buf.subarray(0, n));
    }
    return hash.digest('hex');
  } finally {
    closeSync(fd);
  }
}
