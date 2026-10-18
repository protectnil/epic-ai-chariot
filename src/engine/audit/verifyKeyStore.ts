/**
 * @epicai/chariot — Persistent audit-chain verification-key store (CHARIOT::§9.8.1::3)
 *
 * CHARIOT-SPEC.md §9.8.1 (docs/spec/CHARIOT-SPEC.md:899-906):
 *   "Key rotation is forward-only: rotate to a new key, record the
 *   rotation event in the chain, and publish the new public key via the
 *   same distribution path as the old one. Historical records remain
 *   verifiable only if the old public key is retained in a multi-key
 *   verification set (CH-03 pattern)."
 *
 * gate finding F2 (2026-09-04): the FIRST cut of `rotateSigningKey()`
 * (keyRotation.ts) returned the new public key to the caller but nothing
 * actually PUBLISHED it anywhere — there was no persistent verification-key
 * set for `resolveVerifyKeys()` to read beyond ad hoc env vars, so "publish
 * the new public key via the same distribution path as the old one" had no
 * concrete distribution path at all.
 *
 * This module IS that distribution path: a small JSON file under
 * `<epicAiDir>/audit/verify-keys.json`, `{ [kid]: { publicKeyPem, addedAt,
 * retiredAt? } }`. Rotation appends the new key to this store ATOMICALLY
 * (write-to-temp + fsync + rename) in the same call that records the chain
 * event (keyRotation.ts). Every prior entry is retained forever — this
 * store only grows; `retiredAt` is metadata for operators, never a signal
 * to stop honoring a key for verification (a record signed under a
 * retired-but-still-here key must still verify per CHARIOT §9.8.1::3).
 *
 * `resolveVerifyKeys()` (chainSigner.ts) merges, in this precedence (later
 * sources add to, never remove from, the set):
 *   1. This persistent store (the durable, rotation-maintained set).
 *   2. `CHARIOT_AUDIT_VERIFY_KEYS` (JSON `{kid: pem}`) — an env-level
 *      overlay for keys not yet persisted (e.g. bootstrapping a fresh
 *      install, or an operator injecting a key out-of-band).
 *   3. The legacy single `CHARIOT_AUDIT_VERIFY_KEY`/`CHARIOT_AUDIT_SIGNING_KEY`
 *      fallback, preserved for backward compatibility.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { existsSync, mkdirSync, openSync, writeSync, fdatasyncSync, closeSync, renameSync, readFileSync } from 'node:fs';
import { randomFillSync } from 'node:crypto';
import { join } from 'node:path';

export interface VerifyKeyStoreEntry {
  publicKeyPem: string;
  addedAt: string;
  retiredAt?: string;
}

export type VerifyKeyStore = Record<string, VerifyKeyStoreEntry>;

function storePath(epicAiDir: string): string {
  return join(epicAiDir, 'audit', 'verify-keys.json');
}

/**
 * Load the persistent verify-key store. Returns `{}` if the file does not
 * exist yet (fresh install, no rotation has ever run) or fails to parse
 * (corrupt file is treated as empty rather than thrown — a caller merging
 * this with env-var sources should not be taken down by a damaged
 * distribution file; the underlying chain-signature verification will
 * still fail closed for anything this store can no longer vouch for).
 */
export function loadVerifyKeyStore(epicAiDir: string): VerifyKeyStore {
  const path = storePath(epicAiDir);
  if (!existsSync(path)) return {};
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf-8')) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as VerifyKeyStore;
    }
    return {};
  } catch {
    return {};
  }
}

/**
 * Atomically write `store` to `<epicAiDir>/audit/verify-keys.json`:
 * write-to-temp (unique suffix, avoids colliding with a concurrent writer),
 * fdatasync to flush kernel buffers, then rename over the target. A crash
 * mid-write leaves the PRIOR file intact (rename is atomic on POSIX); a
 * crash after rename leaves the complete new file. Mirrors the
 * write-temp/fsync/rename contract in auditFs.ts's `atomicWriteNew`, but
 * REPLACES an existing file rather than failing on EEXIST — this store is
 * a single mutable document, not an append-only log of distinct records.
 */
function atomicWriteStore(epicAiDir: string, store: VerifyKeyStore): void {
  const dir = join(epicAiDir, 'audit');
  mkdirSync(dir, { recursive: true, mode: 0o755 });
  const path = storePath(epicAiDir);
  const suffix = Buffer.alloc(8);
  randomFillSync(suffix);
  const tmpPath = `${path}.tmp-${suffix.toString('hex')}`;
  const data = Buffer.from(JSON.stringify(store, null, 2) + '\n', 'utf-8');
  const fd = openSync(tmpPath, 'wx', 0o644);
  try {
    writeSync(fd, data);
    fdatasyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmpPath, path);
}

/**
 * Append (or update) one entry in the persistent verify-key store and
 * persist it atomically. Never removes an existing entry — rotation is
 * forward-only (CHARIOT §9.8.1): the only way an entry's shape changes is
 * `retireVerifyKey` stamping `retiredAt` for operator bookkeeping, which
 * still leaves the entry (and its verifiability) in place.
 */
export function appendVerifyKey(epicAiDir: string, kid: string, publicKeyPem: string, addedAt: string = new Date().toISOString()): void {
  const store = loadVerifyKeyStore(epicAiDir);
  store[kid] = { ...(store[kid] ?? {}), publicKeyPem, addedAt: store[kid]?.addedAt ?? addedAt };
  atomicWriteStore(epicAiDir, store);
}

/**
 * Stamp `retiredAt` on an existing entry (bookkeeping only — the key
 * remains in the returned set from `loadVerifyKeyStore`/`resolveVerifyKeys`
 * and continues to verify historical records signed under it, per
 * CHARIOT::§9.8.1::3's "historical records remain verifiable" MUST).
 */
export function retireVerifyKey(epicAiDir: string, kid: string, retiredAt: string = new Date().toISOString()): void {
  const store = loadVerifyKeyStore(epicAiDir);
  if (!store[kid]) return;
  store[kid] = { ...store[kid], retiredAt };
  atomicWriteStore(epicAiDir, store);
}
