/**
 * CHARIOT::§16.1 License (CHARIOT-SPEC.md:1345, rulings item 91) — "...
 * `license.renewed`, `license.renew_failed`."
 *
 * Proves `renewNow()` emits the pinned `license.renewed`/`license.renew_failed`
 * event based on the real `RenewOutcome.kind` it computes, real end-to-end
 * (not source inspection) — via an injected `fetchImpl` (this module's own
 * test-injection point, see `RenewNowOptions.fetchImpl`), which produces a
 * DETERMINISTIC outcome regardless of whether a real `~/.epic-ai/
 * chariot.license` happens to exist on the host this test runs on (this
 * module hardcodes the READ path — no env override exists for it, per the
 * established precedent in `loader.invalidate-cache.test.ts` — so this file
 * deliberately does not depend on that path's contents):
 *   - no local license file present -> `renewNowInner` returns early with
 *     `kind: 'no_local_license'`, BEFORE ever calling `fetchImpl` — a
 *     genuine renewal failure.
 *   - a local license file IS present -> the injected `fetchImpl` always
 *     rejects, forcing `kind: 'network_error'` — also a genuine failure.
 * Either way the real outcome is some non-'renewed'/non-'no_new_billing'
 * kind, so `license.renew_failed` is the only event this test can
 * correctly assert regardless of host state — proving the wrapper's
 * failure-path wiring is real, without a network dependency or a license
 * fixture.
 *
 * Run (after tsc): node --test dist/license/renew-client.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renewNow } from './renew-client.js';
import { chariotEmitter, type ChariotEvent } from '../observability/emitter.js';

const alwaysRejectFetch: typeof fetch = () => Promise.reject(new Error('taxonomy-adoption test: network intentionally unavailable'));

test('§16.1 License: renewNow() emits license.renew_failed on any non-renewed/non-no_new_billing outcome', async () => {
  const events: ChariotEvent[] = [];
  const cb = (e: ChariotEvent) => events.push(e);
  chariotEmitter.on(cb);
  try {
    const outcome = await renewNow({ fetchImpl: alwaysRejectFetch, timeoutMs: 2_000 });

    assert.notEqual(outcome.kind, 'renewed', 'this test cannot assert license.renewed without a real license+server — see the header comment');
    assert.notEqual(outcome.kind, 'no_new_billing', 'an injected always-rejecting fetch cannot itself produce a 304 — if this fires, a local license+working network coincidentally exists on this host');

    const failed = events.find((e) => e.type === 'license.renew_failed');
    assert.ok(failed, `expected license.renew_failed for outcome.kind=${outcome.kind}, got events: ${JSON.stringify(events.map((e) => e.type))}`);
    assert.equal(failed!.data.kind, outcome.kind);
    const renewed = events.find((e) => e.type === 'license.renewed');
    assert.equal(renewed, undefined, 'must not ALSO emit license.renewed for a failure outcome');
  } finally {
    chariotEmitter.off(cb);
  }
});

test('§16.1 License: renewNow() never emits license.renewed or license.renew_failed for a no_new_billing (304) outcome', async () => {
  // Directly exercises the wrapper's skip-both-events branch by injecting a
  // fetch that returns a bare 304 (no license file dependency either — a
  // real license file is required to reach this far, so if this host has
  // none, the earlier no_local_license path fires first and this assertion
  // is vacuously satisfied the same way — either way, neither event fires).
  const fetch304: typeof fetch = (() =>
    Promise.resolve(new Response(null, { status: 304 }))) as unknown as typeof fetch;
  const events: ChariotEvent[] = [];
  const cb = (e: ChariotEvent) => events.push(e);
  chariotEmitter.on(cb);
  try {
    const outcome = await renewNow({ fetchImpl: fetch304, timeoutMs: 2_000 });
    if (outcome.kind === 'no_new_billing') {
      assert.equal(events.find((e) => e.type === 'license.renewed'), undefined);
      assert.equal(events.find((e) => e.type === 'license.renew_failed'), undefined);
    } else {
      // No local license file on this host — the no_local_license path
      // fired first and IS a genuine failure; must have emitted renew_failed.
      assert.ok(events.find((e) => e.type === 'license.renew_failed'));
    }
  } finally {
    chariotEmitter.off(cb);
  }
});
