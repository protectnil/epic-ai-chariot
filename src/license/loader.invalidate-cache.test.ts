/**
 * Prove-on-revert for CHARIOT §11.4::3 — "The license loader ... SHALL
 * invalidate the cache on SIGHUP for operator-driven reloads."
 * (CHARIOT-SPEC.md:1167, "The cache is invalidated on `SIGHUP` for
 * operator-driven reloads.")
 *
 * Defect this catches: no production-facing cache-invalidation entry point
 * existed. The only clear-the-cache function, `__resetLicenseCache()`, is
 * explicitly documented "@internal — test-only. Not part of the public
 * Chariot API surface. Do not call from production code" — a SIGHUP
 * handler in src/engine/bin/setup.ts calling it would violate that
 * function's own contract. `invalidateLicenseCache()` is the public,
 * production-facing counterpart the SIGHUP handler actually calls.
 *
 * This module has no env-var override for the license file path
 * (`getLicensePath()` is hardcoded to `homedir()/CONFIG_DIR/LICENSE_FILENAME`),
 * so a full read-populate-invalidate-reread behavioral test would require
 * writing to the real `~/.epic-ai/chariot.license` — invasive for a
 * colocated unit test. Following this repo's established convention for
 * exactly this kind of infrastructure code (see admin.tenant-crud.test.ts,
 * admin.audit-logs-export.test.ts: "this repo has no supertest/
 * mongodb-memory-server dependency for colocated unit tests ... asserts
 * the contract by source inspection"), this file asserts via source that
 * (a) the function exists, is exported, and is distinct in visibility from
 * the test-only `__resetLicenseCache`, and (b) it performs the SAME
 * underlying cache operation (`_licenseCache.clear()` — a full clear, not
 * `invalidateLicenseCacheSlot`'s single-tenant `_licenseCache.invalidate()`)
 * so a SIGHUP on a multi-tenant deployment invalidates every tenant's slot,
 * not just one.
 *
 * Run (after tsc): node --test dist/license/loader.invalidate-cache.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { invalidateLicenseCache } from './loader.js';

const loaderSrc = readFileSync(fileURLToPath(new URL('./loader.js', import.meta.url)), 'utf8');

test('§11.4::3: invalidateLicenseCache is exported (callable from outside this module)', () => {
  assert.equal(typeof invalidateLicenseCache, 'function');
});

test('§11.4::3: invalidateLicenseCache does not throw when called with no license file present / no prior cache population', () => {
  // Behavioral smoke test: the function must be safe to call unconditionally
  // from a SIGHUP handler regardless of process state (before any license
  // was ever loaded, after one was, repeatedly, etc.) — a throw here would
  // crash the long-running server process on an operator-sent signal.
  assert.doesNotThrow(() => invalidateLicenseCache());
  assert.doesNotThrow(() => invalidateLicenseCache());
});

test('§11.4::3: invalidateLicenseCache performs a FULL cache clear (_licenseCache.clear()), not a single-tenant invalidate', () => {
  const start = loaderSrc.indexOf('export function invalidateLicenseCache');
  assert.ok(start >= 0, 'invalidateLicenseCache must be an exported function');
  const body = loaderSrc.slice(start, start + 200);
  assert.match(body, /_licenseCache\.clear\(\)/, 'must call the whole-cache clear() — a SIGHUP has no tenant context, so every tenant slot must invalidate, not just one');
  assert.doesNotMatch(body, /_licenseCache\.invalidate\(/, 'must NOT use the single-slot invalidate() — that is invalidateLicenseCacheSlot()\'s job for per-tenant renewal, a different call site');
});

test('§11.4::3: invalidateLicenseCache is NOT the test-only __resetLicenseCache (distinct, production-facing entry point)', () => {
  const testOnlyDoc = loaderSrc.slice(
    loaderSrc.indexOf('@internal — test-only'),
    loaderSrc.indexOf('export function __resetLicenseCache'),
  );
  assert.match(testOnlyDoc, /Do not call from production code/, 'the pre-existing __resetLicenseCache must remain marked test-only');
  // invalidateLicenseCache's own doc comment legitimately MENTIONS
  // __resetLicenseCache being test-only (as a contrast), so a loose
  // substring check on "test-only" would false-positive on that
  // reference. Check the actual visibility marker instead: the doc block
  // immediately above `export function invalidateLicenseCache` must not
  // itself carry an `@internal` JSDoc tag (the marker __resetLicenseCache
  // and invalidateLicenseCacheSlot both carry).
  const prodStart = loaderSrc.indexOf('export function invalidateLicenseCache');
  const precedingDocStart = loaderSrc.lastIndexOf('/**', prodStart);
  const prodDoc = loaderSrc.slice(precedingDocStart, prodStart);
  assert.doesNotMatch(prodDoc, /@internal/, 'invalidateLicenseCache\'s own doc comment must not carry the @internal tag — it is a production API, unlike __resetLicenseCache and invalidateLicenseCacheSlot');
});
