/**
 * CHARIOT::§3.1::7 — "The system SHALL use ~/.epic-ai/cache/
 * (Chariot-process-owned) for catalog and tool-schema cache, safe to
 * delete." (CHARIOT-SPEC.md:190).
 *
 * Failure classes enumerated from the clause and closed here:
 *   - round trip: write then read returns the same data
 *   - stale source: the source file changes (mtime/size) after the cache
 *     was written — must be a miss, never stale data served
 *   - corrupt cache file — must be a miss, never a thrown error
 *   - missing cache directory entirely (the literal "safe to delete" case)
 *     — read is a miss, a subsequent write recreates the directory
 *   - missing source file — read/write must not throw
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, existsSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// paths.ts resolves EPIC_AI_DIR (and therefore CACHE_DIR) once at module
// load time from EPIC_AI_DIR_OVERRIDE, so it must be set BEFORE the first
// import of anything that transitively imports paths.ts (cache.ts does).
const sandbox = mkdtempSync(join(tmpdir(), 'chariot-cache-test-'));
process.env.EPIC_AI_DIR_OVERRIDE = sandbox;

const { readCache, writeCache } = await import('./cache.js');
const { CACHE_DIR } = await import('../cli/paths.js');

function makeSource(dir: string, name: string, contents: string): string {
  const p = join(dir, name);
  writeFileSync(p, contents);
  return p;
}

test('cache.ts resolves under the sandboxed CACHE_DIR (EPIC_AI_DIR_OVERRIDE honored)', () => {
  assert.equal(CACHE_DIR, join(sandbox, 'cache'));
});

test('writeCache then readCache round-trips the data for an unchanged source', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cache-src-'));
  const source = makeSource(dir, 'bundle.json', '{"a":1}');
  writeCache('roundtrip-key', source, { hello: 'world', n: 3 });
  const result = readCache<{ hello: string; n: number }>('roundtrip-key', source);
  assert.deepEqual(result, { hello: 'world', n: 3 });
});

test('readCache is a miss (not a throw) when the source file changed since the cache was written', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cache-stale-src-'));
  const source = makeSource(dir, 'bundle.json', '{"a":1}');
  writeCache('stale-src-key', source, { v: 1 });
  // Force an observable mtime/size change (content AND size differ, so this
  // is robust even on filesystems with coarse mtime resolution).
  writeFileSync(source, '{"a":1,"b":2}');
  const laterMs = Date.now() + 5000;
  utimesSync(source, laterMs / 1000, laterMs / 1000);
  const result = readCache('stale-src-key', source);
  assert.equal(result, null, 'a changed source must invalidate the cache entry');
});

test('readCache is a miss (not a throw) for a corrupt cache file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cache-corrupt-src-'));
  const source = makeSource(dir, 'bundle.json', '{"a":1}');
  writeCache('corrupt-key', source, { v: 1 });
  // Corrupt the cache file this write just produced.
  const cacheFile = join(CACHE_DIR, 'corrupt-key.json');
  assert.ok(existsSync(cacheFile), 'precondition: cache file must exist before corrupting it');
  writeFileSync(cacheFile, 'not valid json {{{');
  const result = readCache('corrupt-key', source);
  assert.equal(result, null, 'corrupt cache bytes must degrade to a miss, never throw');
});

test('readCache is a safe miss when the entire cache directory is deleted ("safe to delete")', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cache-deleted-dir-src-'));
  const source = makeSource(dir, 'bundle.json', '{"a":1}');
  writeCache('deleted-dir-key', source, { v: 1 });
  assert.ok(existsSync(CACHE_DIR), 'precondition: cache dir must exist before deleting it');
  rmSync(CACHE_DIR, { recursive: true, force: true });
  const result = readCache('deleted-dir-key', source);
  assert.equal(result, null);
});

test('writeCache recreates a deleted CACHE_DIR from scratch and the entry is then readable', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cache-recreate-src-'));
  const source = makeSource(dir, 'bundle.json', '{"a":1}');
  if (existsSync(CACHE_DIR)) rmSync(CACHE_DIR, { recursive: true, force: true });
  assert.equal(readCache('recreate-key', source), null);
  writeCache('recreate-key', source, { fresh: true });
  assert.deepEqual(readCache('recreate-key', source), { fresh: true });
});

test('readCache/writeCache never throw for a missing source file', () => {
  const missingSource = join(tmpdir(), 'chariot-cache-does-not-exist', 'nope.json');
  assert.doesNotThrow(() => readCache('missing-src-key', missingSource));
  assert.equal(readCache('missing-src-key', missingSource), null);
  assert.doesNotThrow(() => writeCache('missing-src-key', missingSource, { v: 1 }));
});
