/**
 * CHARIOT::§16.1 License (CHARIOT-SPEC.md:1345, rulings item 91) — "License:
 * `license.loaded`, `license.expired`, `license.grace_entered`,
 * `license.degraded`, ..."
 *
 * REAL BEHAVIORAL test (revised per chariot-verify-wave1 finding: the prior
 * source-inspection regex targeted `function cache(info: LicenseInfo)`,
 * a TypeScript-only substring erased by compilation — it could never have
 * matched the compiled `dist/license/loader.js` this file reads from, and
 * a concurrent edit to the same helper by another builder (grace-alert
 * dedup gating) made that even more visible).
 *
 * `emitLicenseEvents(info, tenantId)` (loader.ts, exported) was extracted
 * from `validateLicense`'s internal `cache()` helper specifically so this
 * decision logic is directly callable with a constructed `LicenseInfo`
 * fixture per mode — see that function's own doc comment for why this
 * avoids needing a genuinely Ed25519-signed license JWT (this module's
 * embedded public key has no matching private key anywhere in this repo).
 * `cache()` itself still exists, unexported, and now does nothing but
 * write the cache slot and call `emitLicenseEvents` — verified below.
 *
 * Grace-alert dedup gating (CHARIOT §11.2::2, rulings item 88(3), owned by
 * a concurrently-landed unit) is exercised for real here too — NOT
 * reverted, NOT worked around — via the same `__graceAlertStateForTest`
 * test seam `loader.grace-alert-dedup.test.ts` uses, with a fresh random
 * companyId per test so this file never collides with that one or with a
 * real host's license state.
 *
 * Run (after tsc): node --test dist/license/loader.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { emitLicenseEvents, type LicenseInfo } from './loader.js';
import { chariotEmitter, type ChariotEvent } from '../observability/emitter.js';
import { __graceAlertStateForTest as graceState } from './loader.js';

function freshCompanyId(): string {
  return `test-license-taxonomy-${randomUUID()}`;
}

function captureEvents(): { events: ChariotEvent[]; stop: () => void } {
  const events: ChariotEvent[] = [];
  const cb = (e: ChariotEvent) => events.push(e);
  chariotEmitter.on(cb);
  return { events, stop: () => chariotEmitter.off(cb) };
}

test('§16.1 License: mode "licensed" emits license.loaded, and ONLY license.loaded', () => {
  const { events, stop } = captureEvents();
  try {
    const info: LicenseInfo = { valid: true, mode: 'licensed', companyId: 'acme-co' };
    emitLicenseEvents(info, 'tenant-a');

    assert.deepEqual(events.map((e) => e.type), ['license.loaded']);
    assert.equal(events[0].data.companyId, 'acme-co');
    assert.equal(events[0].data.tenantId, 'tenant-a');
  } finally {
    stop();
  }
});

test('§16.1 License: mode "grace" emits BOTH license.expired and license.grace_entered on first entry', () => {
  const companyId = freshCompanyId();
  const { events, stop } = captureEvents();
  try {
    const info: LicenseInfo = {
      valid: true,
      mode: 'grace',
      companyId,
      reason: 'License expired — grace period active',
      graceEndsAt: '2026-12-31',
    };
    emitLicenseEvents(info, undefined);

    const types = events.map((e) => e.type);
    assert.ok(types.includes('license.expired'), 'grace mode must ALSO emit license.expired — the license IS expired');
    assert.ok(types.includes('license.grace_entered'), 'a fresh grace entry (no prior dedup state) must emit grace_entered');
    const graceEvt = events.find((e) => e.type === 'license.grace_entered')!;
    assert.equal(graceEvt.data.graceEndsAt, '2026-12-31');
    assert.equal(graceEvt.message, 'License expired — grace period active');
  } finally {
    stop();
    graceState.clear(companyId);
  }
});

test('§16.1 License / §11.2::2: a SECOND grace-mode call within 24h re-emits license.expired but NOT license.grace_entered (dedup gating preserved, not reverted)', () => {
  const companyId = freshCompanyId();
  const info: LicenseInfo = { valid: true, mode: 'grace', companyId, reason: 'License expired — grace period active', graceEndsAt: '2026-12-31' };

  const first = captureEvents();
  emitLicenseEvents(info, undefined);
  first.stop();
  assert.ok(first.events.some((e) => e.type === 'license.grace_entered'), 'first call must emit grace_entered (sanity)');

  const second = captureEvents();
  try {
    emitLicenseEvents(info, undefined);
    const types = second.events.map((e) => e.type);
    assert.ok(types.includes('license.expired'), 'license.expired is NOT deduped — it must still fire on every grace-mode cache-miss');
    assert.ok(!types.includes('license.grace_entered'), 'a second entry within the 24h re-emit window must NOT re-emit grace_entered — this is the dedup gate this unit must not revert');
  } finally {
    second.stop();
    graceState.clear(companyId);
  }
});

test('§16.1 License: mode "degraded" emits BOTH license.expired and license.degraded', () => {
  const companyId = freshCompanyId();
  const { events, stop } = captureEvents();
  try {
    const info: LicenseInfo = { valid: false, mode: 'degraded', companyId, reason: 'License expired and grace period ended' };
    emitLicenseEvents(info, 'tenant-b');

    const types = events.map((e) => e.type);
    assert.ok(types.includes('license.expired'), 'degraded mode must ALSO emit license.expired — same evidence as grace');
    assert.ok(types.includes('license.degraded'));
    const degradedEvt = events.find((e) => e.type === 'license.degraded')!;
    assert.equal(degradedEvt.severity, 'urgent');
    assert.equal(degradedEvt.alertWorthy, true);
    assert.equal(degradedEvt.message, 'License expired and grace period ended');
  } finally {
    stop();
    graceState.clear(companyId);
  }
});

test('§16.1 License: mode "unlicensed" emits NONE of the 6 pinned License events', () => {
  const companyId = freshCompanyId();
  const { events, stop } = captureEvents();
  try {
    const info: LicenseInfo = { valid: false, mode: 'unlicensed', reason: 'No license file found' };
    emitLicenseEvents(info, undefined);

    assert.deepEqual(events, [], 'an absent/invalid/revoked license is not an "expiry" in the time sense — it must emit nothing');
  } finally {
    stop();
    graceState.clear(companyId);
  }
});

test('§16.1 License / §11.2::2: transitioning OUT of grace (e.g. to "licensed") clears the grace-alert dedup state', () => {
  const companyId = freshCompanyId();
  // Enter grace once to create dedup state.
  const e1 = captureEvents();
  emitLicenseEvents({ valid: true, mode: 'grace', companyId, reason: 'License expired — grace period active', graceEndsAt: '2026-12-31' }, undefined);
  e1.stop();
  assert.ok(graceState.read(companyId), 'grace-alert dedup state must exist after a grace entry');

  // A non-grace mode (licensed) must clear it.
  const e2 = captureEvents();
  try {
    emitLicenseEvents({ valid: true, mode: 'licensed', companyId }, undefined);
    assert.equal(graceState.read(companyId), null, 'a non-grace mode must clear the grace-alert dedup state so a future re-entry into grace is treated as NEW');
  } finally {
    e2.stop();
    graceState.clear(companyId);
  }
});

test('§16.1 License: the internal cache() helper delegates to the exported emitLicenseEvents (compiled output check)', () => {
  const loaderSrc = readFileSync(fileURLToPath(new URL('./loader.js', import.meta.url)), 'utf8');
  assert.match(loaderSrc, /function cache\(info\)\s*\{[\s\S]{0,200}emitLicenseEvents\(info,\s*tenantId\)/, 'cache() must delegate its event-emission decision to emitLicenseEvents, not duplicate the branching inline');
});
