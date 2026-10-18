/**
 * Prove-on-revert for CHARIOT §11.4::2/::3 (rulings item 88, order B2 -> B3)
 * — the license loader's disk re-read triggers beyond its own 60s TTL.
 *
 * CHARIOT-SPEC.md:1167: "The license loader caches the parsed license in
 * process memory for 60 seconds. Disk re-read happens on cache miss and on
 * every 6-hour renewal cycle. The cache is invalidated on `SIGHUP` for
 * operator-driven reloads."
 *
 * Defect this catches: neither trigger existed. `grep -rln "SIGHUP" src/`
 * had exactly one unrelated hit (a Docker adapter); `grep -rn "setInterval"
 * src/license/ src/engine/server/` had zero hits. License renewal was a
 * manual-only CLI subcommand (`chariot license renew-now`).
 *
 * `startMcpServer()` in this file is deep inside CLI dispatch (gated behind
 * argv parsing, adapter loading, and an actual bound HTTP/REST transport)
 * and is not practically unit-invocable in isolation — this repo's
 * established convention for exactly this shape of code (see
 * admin.tenant-crud.test.ts, admin.audit-logs-export.test.ts) is
 * source-inspection: assert the wiring exists, is scoped correctly, and
 * uses the correct primitives, without standing up a live server.
 *
 * Run (after tsc): node --test dist/engine/bin/setup.sighup-renewal.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const setupSrc = readFileSync(fileURLToPath(new URL('./setup.js', import.meta.url)), 'utf8');

function keepAliveBlock(): string {
  const start = setupSrc.indexOf('// HTTP/REST mode: keep alive until signal');
  assert.ok(start >= 0, 'expected the "HTTP/REST mode: keep alive until signal" block');
  const end = setupSrc.indexOf('let shuttingDown = false;', start);
  assert.ok(end > start, 'expected the keep-alive block to end before the existing shutdown() declaration');
  return setupSrc.slice(start, end);
}

test('§11.4::3: a SIGHUP handler is registered in the HTTP/REST keep-alive block, calling invalidateLicenseCache', () => {
  const block = keepAliveBlock();
  assert.match(block, /process\.on\(\s*'SIGHUP'/, 'a SIGHUP handler must be registered');
  const sighupStart = block.indexOf("process.on('SIGHUP'");
  const sighupHandler = block.slice(sighupStart, block.indexOf('});', sighupStart) + 3);
  assert.match(sighupHandler, /invalidateLicenseCache\(\)/, 'the SIGHUP handler must call invalidateLicenseCache() — not the test-only __resetLicenseCache, and not a single-tenant revalidateLicense(tenantId)');
});

test('§11.4::3: the SIGHUP handler is registered ONLY in the HTTP/REST (handles.length > 0) branch, never for stdio-only', () => {
  // A stdio-only single-user process has no persistent cache-serving loop
  // worth invalidating on an external signal in the same way; wiring it
  // here (inside the block gated by `if (handles.length > 0)`) keeps a
  // plain `npx @epicai/chariot` (no --http/--rest) from loading this code
  // at all, matching how the license/renew-client dynamic imports above it
  // are already scoped.
  const beforeBlockIdx = setupSrc.indexOf('if (handles.length > 0) {');
  const sighupIdx = setupSrc.indexOf("process.on('SIGHUP'");
  const stdioCommentIdx = setupSrc.indexOf('// stdio-only: return here');
  assert.ok(beforeBlockIdx >= 0 && beforeBlockIdx < sighupIdx, 'SIGHUP wiring must be inside the "if (handles.length > 0)" branch');
  assert.ok(sighupIdx < stdioCommentIdx, 'SIGHUP wiring must be registered before the stdio-only fallthrough comment (i.e. still inside the HTTP/REST branch)');
});

test('§11.4::2: a 6-hour setInterval calls the existing renewNow() renewal flow', () => {
  const block = keepAliveBlock();
  assert.match(block, /SIX_HOURS_MS\s*=\s*6\s*\*\s*60\s*\*\s*60\s*\*\s*1000/, 'the interval must be exactly 6 hours in milliseconds');
  assert.match(block, /setInterval\(\s*\(\)\s*=>\s*\{[\s\S]*?renewNow\(\)/, 'the interval callback must invoke renewNow() — reusing the existing, already-instrumented renewal flow rather than reimplementing the HTTP call');
  assert.match(block, /\},\s*SIX_HOURS_MS\s*\)/, 'setInterval must be scheduled at exactly SIX_HOURS_MS');
});

test('§11.4::2: the renewal timer forces a disk re-read via revalidateLicense() after EVERY attempt, success or failure', () => {
  const block = keepAliveBlock();
  const intervalStart = block.indexOf('setInterval(');
  const intervalBody = block.slice(intervalStart, block.indexOf('SIX_HOURS_MS)', intervalStart) + 'SIX_HOURS_MS)'.length);
  assert.match(intervalBody, /\.finally\(\s*\(\)\s*=>\s*\{\s*revalidateLicense\(\)/, 'revalidateLicense() must run in a .finally() so a disk re-read happens on the 6h cycle whether renewNow() resolved or its .catch() ran — the clause text gives the 6h cycle as a trigger independent of outcome');
});

test('§11.4::2: the renewal timer is unref()d so it never blocks SIGTERM/SIGINT shutdown', () => {
  const block = keepAliveBlock();
  assert.match(block, /renewalTimer\.unref\(\)/, 'the interval handle must be unref()d — otherwise a mid-interval SIGTERM/SIGINT could be kept alive by this timer alone, contradicting the existing shutdown() contract');
});

test('§11.4::2: a thrown (not modeled-outcome) error from renewNow() is caught and does not crash the process', () => {
  const block = keepAliveBlock();
  const intervalStart = block.indexOf('setInterval(');
  const intervalBody = block.slice(intervalStart, block.indexOf('}, SIX_HOURS_MS)', intervalStart));
  assert.match(intervalBody, /\.catch\(/, 'the renewNow() call must have a .catch() — an unexpected throw (outside the modeled RenewOutcome contract) must not take down the long-running server process');
});
