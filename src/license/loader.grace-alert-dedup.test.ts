/**
 * Prove-on-revert for CHARIOT §11.2::2 (rulings item 88(3)) — GRACE-mode
 * admin alert dedup.
 *
 * CHARIOT-SPEC.md:1155: "| `GRACE` | Present, signature valid, `exp ≤ now
 * ≤ exp + 14d` | All seats, all features, alert admin |". Ruling item
 * 88(3): "one `license.grace_entered` per grace-period entry (state
 * persisted beside the cached license), re-emitted once per 24h while in
 * grace."
 *
 * Defect this catches: before this unit, `validateLicense`'s cache() helper
 * emitted `license.grace_entered` unconditionally on every cache MISS while
 * mode==='grace' — with the 60s cache TTL, that is up to ~1440 duplicate
 * admin alerts a day for one grace-period entry, not "once per 24h."
 *
 * This is a real behavioral test (not source-inspection): the dedup state
 * is a small JSON file keyed by companyId, independent of any signed JWT,
 * so it is directly testable via `__graceAlertStateForTest` (test-only
 * export) without a license fixture. A random UUID companyId per test run
 * avoids any collision with a real host's license state.
 *
 * Run (after tsc): node --test dist/license/loader.grace-alert-dedup.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { __graceAlertStateForTest as g, shouldEmitGraceAlert, recordGraceAlertEmitted } from './loader.js';

function freshCompanyId(): string {
  return `test-grace-dedup-${randomUUID()}`;
}

test.afterEach(() => {
  // Best-effort cleanup is already the module's own contract (clear() is
  // best-effort); nothing else to tear down since each test uses a fresh
  // random companyId and clear()s its own state file explicitly below.
});

test('§11.2::2: with no prior state, a grace entry is treated as NEW (first alert must fire)', () => {
  const companyId = freshCompanyId();
  assert.equal(g.read(companyId), null, 'a fresh companyId must have no persisted grace-alert state');
});

test('§11.2::2: persist() writes readable state; a second immediate check is within the 24h window (must NOT re-emit)', () => {
  const companyId = freshCompanyId();
  const now = Date.now();
  g.persist({ enteredAt: new Date(now).toISOString(), lastAlertAt: new Date(now).toISOString() }, companyId);
  try {
    assert.ok(existsSync(g.path(companyId)), 'persist() must write the state file to the path read() and clear() operate on');
    const state = g.read(companyId);
    assert.ok(state, 'the just-persisted state must read back');
    const elapsed = Date.now() - Date.parse(state!.lastAlertAt);
    assert.ok(elapsed < g.reemitWindowMs, 'an immediately-following check must be well inside the 24h re-emit window');
  } finally {
    g.clear(companyId);
  }
});

test('§11.2::2: the re-emit window is exactly 24 hours', () => {
  assert.equal(g.reemitWindowMs, 24 * 60 * 60 * 1000);
});

test('§11.2::2: a lastAlertAt older than 24h is due for re-emit (dedup gate must let a fresh 24h-boundary alert through)', () => {
  const companyId = freshCompanyId();
  const stale = Date.now() - (g.reemitWindowMs + 1000); // 24h + 1s ago
  g.persist({ enteredAt: new Date(stale).toISOString(), lastAlertAt: new Date(stale).toISOString() }, companyId);
  try {
    const state = g.read(companyId);
    assert.ok(state, 'stale state must still read back (persist/read do not themselves expire entries — the CALLER in loader.ts\'s cache() computes due-for-reemit from lastAlertAt)');
    const elapsed = Date.now() - Date.parse(state!.lastAlertAt);
    assert.ok(elapsed >= g.reemitWindowMs, 'elapsed time since a 24h+1s-old lastAlertAt must be >= the re-emit window, proving the >= comparison in cache() would fire');
  } finally {
    g.clear(companyId);
  }
});

test('§11.2::2: clear() removes the state file, so a subsequent read() reports NEW again (fresh grace-period entry after a mode transition out of grace)', () => {
  const companyId = freshCompanyId();
  const now = Date.now();
  g.persist({ enteredAt: new Date(now).toISOString(), lastAlertAt: new Date(now).toISOString() }, companyId);
  assert.ok(g.read(companyId), 'state must exist before clear()');
  g.clear(companyId);
  assert.equal(g.read(companyId), null, 'after clear(), read() must report no prior entry — the next grace observation is a NEW entry, not a continuation');
});

test('§11.2::2: clear() on a companyId with no prior state does not throw (called unconditionally on every non-grace mode)', () => {
  const companyId = freshCompanyId();
  assert.doesNotThrow(() => g.clear(companyId));
});

test('§11.2::2: state is scoped per companyId — two different companies never share a dedup file', () => {
  const companyA = freshCompanyId();
  const companyB = freshCompanyId();
  const now = Date.now();
  g.persist({ enteredAt: new Date(now).toISOString(), lastAlertAt: new Date(now).toISOString() }, companyA);
  try {
    assert.equal(g.read(companyB), null, 'companyB must have no state just because companyA does — a shared file would let one tenant\'s grace alert suppress another\'s');
    assert.notEqual(g.path(companyA), g.path(companyB), 'the two companies must resolve to different file paths');
  } finally {
    g.clear(companyA);
  }
});

// ── Behavioral sequence tests, driving the real dedup DECISION functions ──
//
// `validateLicense()`'s licensed/grace/degraded branches require verifying
// a JWT against the embedded PRODUCTION Ed25519 public key — there is no
// test-key override in loader.ts (confirmed by source: `ACCEPTED_KEYS_PEM`
// is a single hardcoded production key, no env-var/injection point), so
// forging a fixture license to drive `validateLicense()` itself into grace
// mode is not achievable in this unit's scope (an independent finding this
// repo's own `loader.taxonomy-adoption.test.ts` records for the same
// function, built concurrently by a different unit touching the same
// helper). Source-regex inspection of the compiled cache() body was tried
// instead (the previous version of this test file) and broke when a
// concurrent edit to that same helper (by that other unit) changed its
// compiled shape — regex-matching generated JS is inherently fragile to
// any edit elsewhere in the same function, by anyone.
//
// `shouldEmitGraceAlert()`/`recordGraceAlertEmitted()` (both exported from
// loader.ts) are the ACTUAL functions `cache()`'s grace branch calls for
// this decision — extracted specifically so the real dedup mechanism can
// be driven directly, with `import.meta.url`-relative Date.now() values
// substituted for what `cache()` passes as `now`, and a local counter
// substituted for `chariotEmitter.send('license.grace_entered', ...)`
// (mirrors "a stubbed emitter" — cache()'s send-then-record pairing is
// mechanically identical to what these tests exercise below).

/** Mirrors cache()'s grace-branch shape exactly: emit iff shouldEmitGraceAlert, then record. Returns whether an emit happened. */
function simulateGraceCacheMiss(companyId: string, now: number): boolean {
  if (shouldEmitGraceAlert(companyId, now)) {
    recordGraceAlertEmitted(companyId, now);
    return true;
  }
  return false;
}

test('§11.2::2 behavioral: first grace-mode observation emits exactly one license.grace_entered', () => {
  const companyId = freshCompanyId();
  const t0 = Date.now();
  try {
    assert.equal(simulateGraceCacheMiss(companyId, t0), true, 'the first-ever observation of grace mode for this companyId must emit');
  } finally {
    g.clear(companyId);
  }
});

test('§11.2::2 behavioral: a second cache-miss inside 24h emits NOTHING', () => {
  const companyId = freshCompanyId();
  const t0 = Date.now();
  try {
    assert.equal(simulateGraceCacheMiss(companyId, t0), true, 'first observation emits');
    const t1 = t0 + 60_000; // 1 minute later — well inside the 24h window
    assert.equal(simulateGraceCacheMiss(companyId, t1), false, 'a cache-miss re-observing grace mode 1 minute later must NOT re-emit — this is exactly the over-alerting defect (emit on every ~60s cache miss) this dedup gate exists to close');
  } finally {
    g.clear(companyId);
  }
});

test('§11.2::2 behavioral: a cache-miss after the dedup state ages past 24h emits AGAIN', () => {
  const companyId = freshCompanyId();
  const t0 = Date.now();
  try {
    assert.equal(simulateGraceCacheMiss(companyId, t0), true, 'first observation emits');
    const stillWithin = t0 + g.reemitWindowMs - 1000; // 24h minus 1s
    assert.equal(simulateGraceCacheMiss(companyId, stillWithin), false, '1s before the 24h boundary must still not re-emit');
    const pastWindow = t0 + g.reemitWindowMs + 1000; // 24h plus 1s
    assert.equal(simulateGraceCacheMiss(companyId, pastWindow), true, 'a cache-miss 24h+1s after the last alert must re-emit — this is the "re-emitted once per 24h while in grace" half of the ruling');
  } finally {
    g.clear(companyId);
  }
});

test('§11.2::2 behavioral: clearing the state (a non-grace mode transition) makes the NEXT grace observation emit fresh, even inside what would have been the old 24h window', () => {
  const companyId = freshCompanyId();
  const t0 = Date.now();
  try {
    assert.equal(simulateGraceCacheMiss(companyId, t0), true, 'first observation emits');
    // cache()'s non-grace branches call clearGraceAlertState(info.companyId)
    // whenever mode !== 'grace' — simulate the license renewing out of
    // grace, then lapsing back into grace later (still well inside what
    // WOULD have been the original 24h dedup window).
    g.clear(companyId);
    const t1 = t0 + 60_000; // 1 minute later — inside the OLD window, but the state was cleared
    assert.equal(simulateGraceCacheMiss(companyId, t1), true, 'after clear(), the next grace observation must be treated as a NEW entry and emit, regardless of how much of the prior 24h window had elapsed');
  } finally {
    g.clear(companyId);
  }
});

// ── Wiring check (minimal source inspection, mechanical wrapper only) ────
// cache()'s grace branch is now a thin 4-line wrapper around the two
// functions the behavioral tests above exercise directly — this one
// remaining source check only proves the wrapper calls them (nothing about
// their internal logic, which is what broke last time), so it is far less
// likely to be invalidated by an unrelated concurrent edit to this file.
const loaderSrc = readFileSync(fileURLToPath(new URL('./loader.js', import.meta.url)), 'utf8');

test('§11.2::2 wiring: the grace branch calls shouldEmitGraceAlert/recordGraceAlertEmitted (not the raw primitives inline)', () => {
  const graceBranchStart = loaderSrc.indexOf("info.mode === 'grace'");
  const degradedBranchStart = loaderSrc.indexOf("info.mode === 'degraded'", graceBranchStart);
  assert.ok(graceBranchStart >= 0 && degradedBranchStart > graceBranchStart, 'expected to locate the grace branch in loader.js');
  const graceBranch = loaderSrc.slice(graceBranchStart, degradedBranchStart);
  assert.match(graceBranch, /shouldEmitGraceAlert\(/, 'the grace branch must gate the emit on shouldEmitGraceAlert()');
  assert.match(graceBranch, /recordGraceAlertEmitted\(/, 'the grace branch must call recordGraceAlertEmitted() after emitting');
});
