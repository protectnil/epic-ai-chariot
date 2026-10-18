/**
 * Behavioral tests for uploader.ts — C4AMD §8 "Connected deployments"
 * (amended 2026-10-12). Real local store under a temp
 * EPIC_AI_DIR_OVERRIDE; the network is an injected fetch, so nothing
 * leaves the process.
 *
 * Run (after tsc): node --test dist/telemetry-upload/uploader.test.js
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = mkdtempSync(join(tmpdir(), 'chariot-telemetry-upload-'));
process.env.EPIC_AI_DIR_OVERRIDE = tmp;
// A real license on the developer's machine must never influence these tests.
process.env.HOME = tmp;

const up = await import('./uploader.js');
const { setConsent, revokeConsent } = await import('../iam/services/telemetry-consent.js');
const { localAppendEvent, readUploadState, telemetryTenantDir } = await import('../observability/operational-telemetry/local-store.js');
const { appendFileSync } = await import('node:fs');
const { DEFAULT_RENEW_URL } = await import('../license/renew-client.js');

after(() => rmSync(tmp, { recursive: true, force: true }));

const SECRET = Buffer.from('test-renewal-secret-32-bytes-long!!', 'utf8');
const connected = (): import('./uploader.js').UploadEligibility => ({
  eligible: true, companyId: 'co-1', jti: 'jti-1', secret: SECRET, topology: 'public-llm',
});
const ev = (n: number) => ({
  tenantId: 'u1', canonicalToolId: `a.t${n}`, outcome: 'success' as const, latencyMs: n, failureStage: null,
  hourBucket: '2026-10-12T10:00:00.000Z', productVersion: '4.0.0', platform: 'linux-arm64', catalogEpoch: 1,
});
const noSleep = async () => undefined;
type Call = { url: string; body: Record<string, string> };
function fakeFetch(statuses: number[]): { fn: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  let i = 0;
  const fn = (async (url: string, init: { body: string }) => {
    calls.push({ url, body: JSON.parse(init.body) as Record<string, string> });
    const status = statuses[Math.min(i++, statuses.length - 1)];
    return new Response('{}', { status });
  }) as unknown as typeof fetch;
  return { fn, calls };
}

test('the destination is the license host only, and matches the renewal host', () => {
  assert.strictEqual(up.TELEMETRY_UPLOAD_URL, 'https://license.epic-ai.io/api/license/telemetry');
  assert.strictEqual(new URL(up.TELEMETRY_UPLOAD_URL).host, new URL(DEFAULT_RENEW_URL).host);
});

test('proof matches the receiver\'s fixed test vector (lock between client and server implementations)', () => {
  // The identical vector is asserted by epic-ai/website test/billing/telemetry-route.test.ts.
  const proof = up.computeTelemetryProof(SECRET, {
    companyId: 'co-1', jti: 'jti-1', nonce: 'nonce-0123456789abcdef', ts: 1760000000, payload: '[{"a":1}]',
  });
  assert.strictEqual(proof, 'IoHk1f0LzYr661qj4G6KKev_7_ZOVzsu7q-3acwF6B0');
});

test('gate 1: no consent → ineligible, nothing sent', async () => {
  const f = fakeFetch([200]);
  const r = await up.uploadPending('u1', { fetchImpl: f.fn, licenseGate: connected, sleep: noSleep });
  assert.deepStrictEqual([r.kind, (r as { code?: string }).code], ['ineligible', 'CONSENT_DISABLED']);
  assert.strictEqual(f.calls.length, 0);
});

test('gate 2: enabled but export-only → ineligible', async () => {
  await setConsent('u1', true, 'ops', { statement: 'yes' });
  const f = fakeFetch([200]);
  const r = await up.uploadPending('u1', { fetchImpl: f.fn, licenseGate: connected, sleep: noSleep });
  assert.strictEqual((r as { code?: string }).code, 'TRANSPORT_NOT_AUTO');
  assert.strictEqual(f.calls.length, 0);
});

test('gates 3/4: auto selected but air-gapped or undetermined or unlicensed → ineligible, nothing sent', async () => {
  await setConsent('u1', true, 'ops', { transport: 'auto', statement: 'yes' });
  localAppendEvent(ev(1));
  for (const [code, gate] of [
    ['TOPOLOGY_AIR_GAPPED', { eligible: false, code: 'TOPOLOGY_AIR_GAPPED', reason: 'x' }],
    ['TOPOLOGY_UNDETERMINED', { eligible: false, code: 'TOPOLOGY_UNDETERMINED', reason: 'x' }],
    ['NO_LICENSE', { eligible: false, code: 'NO_LICENSE', reason: 'x' }],
  ] as const) {
    const f = fakeFetch([200]);
    const r = await up.uploadPending('u1', { fetchImpl: f.fn, licenseGate: () => gate, sleep: noSleep, force: true });
    assert.strictEqual((r as { code?: string }).code, code);
    assert.strictEqual(f.calls.length, 0, `${code}: no network call`);
  }
});

test('the real license gate fails closed with no license installed', () => {
  const g = up.evaluateConnectedLicenseGate();
  assert.strictEqual(g.eligible, false);
  assert.strictEqual((g as { code: string }).code, 'NO_LICENSE');
});

test('eligible: sends one batch, proof verifies, payload is the nine closed fields only, cursor advances', async () => {
  // A stored row carrying extra keys (a tampered store) must not leave the host.
  appendFileSync(
    join(telemetryTenantDir('u1'), 'events.jsonl'),
    JSON.stringify({ ...ev(2), apiKey: 'sk_live_never', toolResult: 'secret output' }) + '\n',
  );
  const f = fakeFetch([200]);
  const r = await up.uploadPending('u1', { fetchImpl: f.fn, licenseGate: connected, sleep: noSleep, force: true, nowMs: Date.parse('2026-10-12T11:00:00Z') });
  assert.deepStrictEqual(r, { kind: 'uploaded', count: 2 });
  assert.strictEqual(f.calls.length, 1);
  const sent = f.calls[0];
  assert.strictEqual(sent.url, up.TELEMETRY_UPLOAD_URL);
  assert.ok(!sent.body.payload.includes('sk_live_never') && !sent.body.payload.includes('secret output'));
  for (const e of JSON.parse(sent.body.payload) as Array<Record<string, unknown>>) {
    assert.deepStrictEqual(Object.keys(e).sort(), [
      'canonicalToolId', 'catalogEpoch', 'failureStage', 'hourBucket', 'latencyMs', 'outcome', 'platform', 'productVersion', 'tenantId',
    ]);
  }
  const expect = createHmac('sha256', SECRET)
    .update(Buffer.concat([
      Buffer.from('co-1'), Buffer.from([0]), Buffer.from('jti-1'), Buffer.from([0]),
      Buffer.from(sent.body.nonce), Buffer.from([0]), Buffer.from(String(sent.body.ts)), Buffer.from([0]),
      Buffer.from(createHash('sha256').update(sent.body.payload).digest('hex')),
    ])).digest('base64url');
  assert.strictEqual(sent.body.proof, expect, 'proof binds company, jti, nonce, ts and the exact payload bytes');
  assert.strictEqual(readUploadState('u1').cursor, '2');
  assert.strictEqual(readUploadState('u1').lastResult, 'uploaded:2');
});

test('nothing new → nothing_to_upload, no request', async () => {
  const f = fakeFetch([200]);
  const r = await up.uploadPending('u1', { fetchImpl: f.fn, licenseGate: connected, sleep: noSleep, force: true });
  assert.strictEqual(r.kind, 'nothing_to_upload');
  assert.strictEqual(f.calls.length, 0);
});

test('throttle: a second attempt inside the interval is not sent', async () => {
  localAppendEvent(ev(3));
  const now = Date.parse('2026-10-12T11:05:00Z');
  const f = fakeFetch([200]);
  const r = await up.uploadPending('u1', { fetchImpl: f.fn, licenseGate: connected, sleep: noSleep, nowMs: now });
  assert.strictEqual(r.kind, 'throttled');
  assert.strictEqual(f.calls.length, 0);
});

// Each test below uses its OWN tenant so the persisted per-batch attempt
// budget of one test can never leak into another.
async function fresh(tenant: string, n = 1) {
  await setConsent(tenant, true, 'ops', { transport: 'auto', statement: 'yes' });
  for (let i = 0; i < n; i++) localAppendEvent({ ...ev(i), tenantId: tenant, canonicalToolId: `${tenant}.t${i}` });
  return tenant;
}

test('a 5xx is retried a bounded 3 times; the exhausted batch is dropped and never gets a fourth attempt', async () => {
  const T = await fresh('t-5xx');
  const f = fakeFetch([503]);
  const r = await up.uploadPending(T, { fetchImpl: f.fn, licenseGate: connected, sleep: noSleep, force: true });
  assert.deepStrictEqual([r.kind, (r as { status?: number }).status], ['failed', 503]);
  assert.strictEqual(f.calls.length, 3);
  const st = readUploadState(T);
  assert.strictEqual(st.cursor, '1', 'exhausted batch is dropped so it cannot wedge the queue');
  assert.match(st.lastResult ?? '', /^dropped-exhausted/);
  assert.strictEqual(st.batchKey, null);
  const again = fakeFetch([200]);
  assert.strictEqual((await up.uploadPending(T, { fetchImpl: again.fn, licenseGate: connected, sleep: noSleep, force: true })).kind, 'nothing_to_upload');
  assert.strictEqual(again.calls.length, 0);
});

test('every request is sent with redirect:"error" so a 3xx can never forward the batch elsewhere', async () => {
  const T = await fresh('t-redirect');
  const seen: Array<string | undefined> = [];
  const spy = (async (_u: string, init: { redirect?: string }) => { seen.push(init.redirect); return new Response('{}', { status: 200 }); }) as unknown as typeof fetch;
  await up.uploadPending(T, { fetchImpl: spy, licenseGate: connected, sleep: noSleep, force: true });
  assert.deepStrictEqual(seen, ['error']);
});

test('the three-attempt budget is persisted: attempts spent in earlier calls count against the same batch', async () => {
  const T = await fresh('t-budget');
  const f1 = fakeFetch([401]); // a definite answer uses ONE attempt and keeps the batch
  await up.uploadPending(T, { fetchImpl: f1.fn, licenseGate: connected, sleep: noSleep, force: true });
  assert.strictEqual(f1.calls.length, 1);
  assert.strictEqual(readUploadState(T).batchAttempts, 1);
  const f2 = fakeFetch([503]); // a later call: only TWO attempts remain
  const r2 = await up.uploadPending(T, { fetchImpl: f2.fn, licenseGate: connected, sleep: noSleep, force: true });
  assert.strictEqual(f2.calls.length, 2, 'budget of 3 minus the 1 already spent');
  assert.strictEqual(r2.kind, 'failed');
  const f3 = fakeFetch([200]); // exhausted and dropped: nothing is sent
  assert.strictEqual((await up.uploadPending(T, { fetchImpl: f3.fn, licenseGate: connected, sleep: noSleep, force: true })).kind, 'nothing_to_upload');
  assert.strictEqual(f3.calls.length, 0);
});

test('consent revoked during the retry backoff stops further transmission at once', async () => {
  const T = await fresh('t-backoff');
  let sent = 0;
  const failing = (async () => { sent++; return new Response('{}', { status: 503 }); }) as unknown as typeof fetch;
  const r = await up.uploadPending(T, {
    fetchImpl: failing, licenseGate: connected, force: true,
    sleep: async () => { await revokeConsent(T, 'ops'); },
  });
  assert.strictEqual(sent, 1, 'no second transmission after the revoke');
  assert.deepStrictEqual([r.kind, (r as { code?: string }).code], ['ineligible', 'CONSENT_DISABLED']);
});

test('consent revoked AFTER the up-front gate but BEFORE the first transmission: nothing is sent', async () => {
  const T = await fresh('t-first');
  const { localAppendConsent } = await import('../observability/operational-telemetry/local-store.js');
  let calls = 0;
  const gate = (): import('./uploader.js').UploadEligibility => {
    calls++;
    // Simulates the revoke landing while the (possibly slow) batch read was pending.
    if (calls === 1) localAppendConsent(T, { enabled: false, transport: 'export-only', changedBy: 'ops', statement: null });
    return connected();
  };
  const f = fakeFetch([200]);
  const r = await up.uploadPending(T, { fetchImpl: f.fn, licenseGate: gate, sleep: noSleep, force: true });
  assert.deepStrictEqual([r.kind, (r as { code?: string }).code], ['ineligible', 'CONSENT_DISABLED']);
  assert.strictEqual(f.calls.length, 0, 'the first transmission re-evaluates every gate');
});

test('license becomes air-gapped between the up-front gate and the first transmission: nothing is sent', async () => {
  const T = await fresh('t-airgap');
  let calls = 0;
  const gate = (): import('./uploader.js').UploadEligibility => {
    calls++;
    return calls === 1
      ? connected()
      : { eligible: false, code: 'TOPOLOGY_AIR_GAPPED', reason: 'air-gapped license installed' };
  };
  const f = fakeFetch([200]);
  const r = await up.uploadPending(T, { fetchImpl: f.fn, licenseGate: gate, sleep: noSleep, force: true });
  assert.strictEqual((r as { code?: string }).code, 'TOPOLOGY_AIR_GAPPED');
  assert.strictEqual(f.calls.length, 0);
});

test('a network error is retried a bounded 3 times then reported, never thrown', async () => {
  const T = await fresh('t-net');
  let n = 0;
  const boom = (async () => { n++; throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch;
  const r = await up.uploadPending(T, { fetchImpl: boom, licenseGate: connected, sleep: noSleep, force: true });
  assert.deepStrictEqual([r.kind, (r as { stage?: string }).stage], ['failed', 'network']);
  assert.strictEqual(n, 3);
});

test('a 401 is a definite answer: one attempt per call, batch kept until the budget is spent, never a 4th', async () => {
  const T = await fresh('t-401');
  const f = fakeFetch([401]);
  const r = await up.uploadPending(T, { fetchImpl: f.fn, licenseGate: connected, sleep: noSleep, force: true });
  assert.strictEqual(r.kind, 'failed');
  assert.strictEqual(f.calls.length, 1);
  assert.strictEqual(readUploadState(T).cursor, null, 'cursor unchanged: the batch is kept');
  assert.strictEqual(readUploadState(T).batchAttempts, 1);
  await up.uploadPending(T, { fetchImpl: fakeFetch([401]).fn, licenseGate: connected, sleep: noSleep, force: true });
  await up.uploadPending(T, { fetchImpl: fakeFetch([401]).fn, licenseGate: connected, sleep: noSleep, force: true });
  // Third 401 spent the budget: the batch was dropped; a 4th call has nothing to send.
  const f4 = fakeFetch([200]);
  assert.strictEqual((await up.uploadPending(T, { fetchImpl: f4.fn, licenseGate: connected, sleep: noSleep, force: true })).kind, 'nothing_to_upload');
  assert.strictEqual(f4.calls.length, 0, 'a 4th attempt is never made');
});

test('a 422 (server rejects the batch as malformed) drops it so it cannot wedge the queue', async () => {
  const T = await fresh('t-422');
  const f = fakeFetch([422]);
  await up.uploadPending(T, { fetchImpl: f.fn, licenseGate: connected, sleep: noSleep, force: true });
  assert.strictEqual(f.calls.length, 1);
  assert.strictEqual(readUploadState(T).cursor, '1', 'cursor moved past the rejected batch');
});

test('revoking consent stops uploads at once', async () => {
  await revokeConsent('u1', 'ops');
  localAppendEvent(ev(4));
  const f = fakeFetch([200]);
  const r = await up.uploadPending('u1', { fetchImpl: f.fn, licenseGate: connected, sleep: noSleep, force: true });
  assert.strictEqual((r as { code?: string }).code, 'CONSENT_DISABLED');
  assert.strictEqual(f.calls.length, 0);
});
