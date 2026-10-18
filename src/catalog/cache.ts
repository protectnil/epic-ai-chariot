/**
 * @epicai/chariot — on-disk catalog / tool-schema cache
 *
 * CHARIOT::§3.1::7 — "The system SHALL use ~/.epic-ai/cache/
 * (Chariot-process-owned) for catalog and tool-schema cache, safe to
 * delete." (CHARIOT-SPEC.md:190).
 *
 * This is a fail-safe READ-THROUGH cache: it never sits between the
 * signature verifier and its caller, and it is never the thing that makes
 * an entry authoritative. `artifacts.ts`'s `loadChariotMcpRegistry()`
 * always re-verifies + re-parses the signed bundle bytes from disk on
 * every call (CH-01) — this module only caches the DERIVED (post-
 * verification) catalog/registry join, keyed to the exact source file's
 * mtime+size, so a corrupt, missing, or stale-keyed cache entry is
 * indistinguishable from a cold cache: the caller always falls back to
 * recomputing from the authoritative, already-verified data. Deleting
 * this directory therefore never loses authoritative state — the next
 * read simply recomputes it and repopulates the cache.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { CACHE_DIR } from '../cli/paths.js';
import { createLogger } from '../engine/logger.js';

const log = createLogger('catalog.cache');

interface CacheEnvelope<T> {
  /** mtimeMs of the source artifact at write time. */
  sourceMtimeMs: number;
  /** byte size of the source artifact at write time. */
  sourceSize: number;
  data: T;
}

function cacheFilePath(cacheKey: string): string {
  // cacheKey is always an internal literal (e.g. 'mcp-registry-joined'),
  // never external input, but sanitize defensively so a future caller can
  // never escape CACHE_DIR.
  const safeKey = cacheKey.replace(/[^a-zA-Z0-9._-]/g, '_');
  return join(CACHE_DIR, `${safeKey}.json`);
}

/**
 * Read a cached value for `cacheKey`, valid only when `sourcePath`'s
 * current mtime+size match what was cached (the source artifact is
 * unchanged since the cache was written). Any anomaly — missing cache
 * directory, missing cache file, corrupt JSON, a changed source, a missing
 * source file — is treated as a cache MISS (returns null), never an error:
 * CHARIOT::§3.1::7 requires this directory be safe to delete, which means
 * every failure mode here must degrade to "recompute", not "fail".
 */
export function readCache<T>(cacheKey: string, sourcePath: string): T | null {
  try {
    const sourceStat = statSync(sourcePath);
    const file = cacheFilePath(cacheKey);
    if (!existsSync(file)) return null;
    const raw = readFileSync(file, 'utf-8');
    const parsed = JSON.parse(raw) as Partial<CacheEnvelope<T>>;
    if (
      parsed.sourceMtimeMs !== sourceStat.mtimeMs ||
      parsed.sourceSize !== sourceStat.size ||
      parsed.data === undefined
    ) {
      return null; // stale or malformed entry — miss, not an error
    }
    return parsed.data as T;
  } catch (err) {
    log.debug('catalog.cache_read_miss', { cacheKey, error: String(err) });
    return null;
  }
}

/**
 * Best-effort write of `data` for `cacheKey`, stamped with `sourcePath`'s
 * current mtime+size so a subsequent `readCache` can detect staleness.
 * Atomic via write-temp + rename (mirrors the pattern already used for
 * `~/.epic-ai/state/catalog_state.json` in AdapterCatalog.ts's
 * `persistEpoch`). A write failure (read-only filesystem, disk full, cache
 * directory not creatable) is logged and swallowed — the cache is
 * best-effort derived state, never something the caller can fail on.
 */
export function writeCache<T>(cacheKey: string, sourcePath: string, data: T): void {
  try {
    const sourceStat = statSync(sourcePath);
    if (!existsSync(CACHE_DIR)) mkdirSync(CACHE_DIR, { recursive: true });
    const file = cacheFilePath(cacheKey);
    const tmp = `${file}.${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.tmp`;
    const body: CacheEnvelope<T> = {
      sourceMtimeMs: sourceStat.mtimeMs,
      sourceSize: sourceStat.size,
      data,
    };
    writeFileSync(tmp, JSON.stringify(body), { encoding: 'utf-8', mode: 0o600 });
    try {
      renameSync(tmp, file);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EXDEV') {
        copyFileSync(tmp, file);
        try { unlinkSync(tmp); } catch { /* best-effort */ }
      } else {
        try { unlinkSync(tmp); } catch { /* best-effort */ }
        throw err;
      }
    }
  } catch (err) {
    log.debug('catalog.cache_write_failed', { cacheKey, error: String(err) });
  }
}
