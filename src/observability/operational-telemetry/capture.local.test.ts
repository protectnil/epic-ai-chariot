/**
 * Behavioral tests for capture.ts + telemetry-consent.ts on the LOCAL store
 * (no MongoDB client injected — a workstation/edge install). Real
 * execution against a temp EPIC_AI_DIR_OVERRIDE.
 *
 * C4AMD::§8::2 off by default · §8::6 versioned/revocable · §8 closed
 * nine-field set (amended 2026-10-12) · "Local store" amendment.
 *
 * Run (after tsc): node --test dist/observability/operational-telemetry/capture.local.test.js
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = mkdtempSync(join(tmpdir(), 'chariot-telemetry-capture-'));
process.env.EPIC_AI_DIR_OVERRIDE = tmp;

const { hasMongoClient } = await import('../../iam/db.js');
const { setConsent, revokeConsent, getCurrentConsent, getConsentHistory } = await import('../../iam/services/telemetry-consent.js');
const { captureEvent, getStoredEvents } = await import('./capture.js');
const { recordLoadedCatalogEpoch, __resetRuntimeContextForTests, getPlatformKey } = await import('./runtime-context.js');

after(() => rmSync(tmp, { recursive: true, force: true }));

const call = (tool: string) => ({
  tenantId: 'local-t',
  canonicalToolId: tool,
  outcome: 'success' as const,
  latencyMs: 5,
  failureStage: null,
  occurredAt: new Date('2026-10-12T10:37:11.000Z'),
});

test('precondition: this process has no MongoDB client (local store is selected)', () => {
  assert.strictEqual(hasMongoClient(), false);
});

test('off by default (§8::2): nothing is captured and nothing is written', async () => {
  const consent = await getCurrentConsent('local-t');
  assert.strictEqual(consent.enabled, false);
  assert.strictEqual(consent.version, 0);
  assert.strictEqual(await captureEvent(call('a.b')), null);
  assert.deepStrictEqual(await getStoredEvents('local-t'), []);
});

test('after opt-in a call is captured with exactly the nine closed fields', async () => {
  __resetRuntimeContextForTests();
  recordLoadedCatalogEpoch(9);
  const rec = await setConsent('local-t', true, 'ops', { statement: 'the user said yes' });
  assert.strictEqual(rec.version, 1);
  assert.strictEqual(rec.transport, 'export-only');
  assert.strictEqual(rec.statement, 'the user said yes');

  const ev = await captureEvent(call('stripe.charge_create'));
  assert.ok(ev, 'event stored');
  assert.deepStrictEqual(Object.keys(ev!).sort(), [
    'canonicalToolId', 'catalogEpoch', 'failureStage', 'hourBucket', 'latencyMs', 'outcome', 'platform', 'productVersion', 'tenantId',
  ]);
  assert.strictEqual(ev!.hourBucket, '2026-10-12T10:00:00.000Z', 'floored to the hour (§8::3 minimization)');
  assert.strictEqual(ev!.catalogEpoch, 9);
  assert.strictEqual(ev!.platform, getPlatformKey());
  assert.match(ev!.productVersion, /^[0-9A-Za-z.+_-]{1,64}$/);
  assert.strictEqual((await getStoredEvents('local-t')).length, 1);
});

test('catalogEpoch is null — never 0 — when no signed catalog has been loaded', async () => {
  __resetRuntimeContextForTests();
  const ev = await captureEvent(call('x.y'));
  assert.strictEqual(ev!.catalogEpoch, null);
});

test('a failure event carries its typed stage; a success forces null', async () => {
  const f = await captureEvent({ ...call('x.fail'), outcome: 'failure', failureStage: 'dispatch' });
  assert.strictEqual(f!.failureStage, 'dispatch');
  const s = await captureEvent({ ...call('x.ok'), outcome: 'success', failureStage: 'dispatch' });
  assert.strictEqual(s!.failureStage, null);
});

test('revoke stops capture immediately and is a NEW version, never an edit (§8::6)', async () => {
  const before = (await getStoredEvents('local-t')).length;
  const rec = await revokeConsent('local-t', 'ops');
  assert.strictEqual(rec.enabled, false);
  assert.strictEqual(rec.transport, 'export-only');
  assert.strictEqual(await captureEvent(call('after.revoke')), null);
  assert.strictEqual((await getStoredEvents('local-t')).length, before);
  const hist = await getConsentHistory('local-t');
  assert.deepStrictEqual(hist.map((h) => [h.version, h.enabled]), [[1, true], [2, false]]);
});

test('automatic transport is only recorded alongside an enable and resets on revoke', async () => {
  const on = await setConsent('local-t', true, 'ops', { transport: 'auto', statement: 'ok' });
  assert.strictEqual(on.transport, 'auto');
  assert.strictEqual((await getCurrentConsent('local-t')).transport, 'auto');
  await revokeConsent('local-t', 'ops');
  const again = await setConsent('local-t', true, 'ops', { statement: 'ok again' });
  assert.strictEqual(again.transport, 'export-only', 're-enable without --transport does not inherit auto');
});

test('consent is tenant-scoped (§8::6): another tenant stays off', async () => {
  assert.strictEqual((await getCurrentConsent('other-t')).enabled, false);
  assert.strictEqual(await captureEvent({ ...call('z.z'), tenantId: 'other-t' }), null);
});
