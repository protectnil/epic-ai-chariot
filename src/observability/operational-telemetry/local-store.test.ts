/**
 * Behavioral tests for local-store.ts — real filesystem I/O under a temp
 * EPIC_AI_DIR_OVERRIDE, no Mongo.
 *
 * C4AMD::§8::6: "Consent state SHALL be tenant-scoped, auditable,
 * versioned, and revocable." — proven here for the local (no-MongoDB)
 * store added by the 2026-10-12 "Local store" amendment.
 *
 * Run (after tsc): node --test dist/observability/operational-telemetry/local-store.test.js
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, appendFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = mkdtempSync(join(tmpdir(), 'chariot-telemetry-store-'));
process.env.EPIC_AI_DIR_OVERRIDE = tmp;

const store = await import('./local-store.js');

before(() => undefined);
after(() => rmSync(tmp, { recursive: true, force: true }));

const EV = {
  tenantId: 't1',
  canonicalToolId: 'stripe.charge_create',
  outcome: 'success' as const,
  latencyMs: 12,
  failureStage: null,
  hourBucket: '2026-10-12T10:00:00.000Z',
  productVersion: '4.0.0',
  platform: 'linux-arm64',
  catalogEpoch: 3,
};

test('a tenant with no consent file is off by default (§8::2): current consent is null', () => {
  assert.strictEqual(store.localCurrentConsent('never-seen'), null);
  assert.deepStrictEqual(store.localConsentHistory('never-seen'), []);
});

test('consent versions are 1,2,3… append-only and history is never rewritten (§8::6)', () => {
  const a = store.localAppendConsent('t1', { enabled: true, transport: 'export-only', changedBy: 'ops', statement: 'yes please' });
  const b = store.localAppendConsent('t1', { enabled: true, transport: 'auto', changedBy: 'ops', statement: null });
  const c = store.localAppendConsent('t1', { enabled: false, transport: 'auto', changedBy: 'ops', statement: null });
  assert.deepStrictEqual([a.version, b.version, c.version], [1, 2, 3]);
  const hist = store.localConsentHistory('t1');
  assert.strictEqual(hist.length, 3);
  assert.strictEqual(hist[0].statement, 'yes please');
  assert.strictEqual(hist[1].transport, 'auto');
  // A revoke always records export-only: re-enable can never inherit `auto`.
  assert.strictEqual(hist[2].enabled, false);
  assert.strictEqual(hist[2].transport, 'export-only');
  assert.strictEqual(store.localCurrentConsent('t1')?.version, 3);
});

test('consent is tenant-scoped: another tenant is unaffected', () => {
  assert.strictEqual(store.localCurrentConsent('t2'), null);
  store.localAppendConsent('t2', { enabled: true, transport: 'export-only', changedBy: 'ops', statement: null });
  assert.strictEqual(store.localCurrentConsent('t2')?.version, 1);
  assert.strictEqual(store.localCurrentConsent('t1')?.version, 3);
});

test('tenant directory names cannot traverse and cannot collide', () => {
  const d1 = store.telemetryTenantDir('../../etc');
  const d2 = store.telemetryTenantDir('.._.._etc');
  assert.ok(d1.startsWith(join(tmp, 'state', 'telemetry')), 'stays under the telemetry root');
  assert.ok(!d1.includes('..'), 'no parent segments');
  assert.notStrictEqual(d1, d2, 'distinct tenant ids hash to distinct directories');
});

test('events append, read back in order, and torn lines are skipped not fatal', () => {
  store.localAppendEvent({ ...EV, canonicalToolId: 'a.one' });
  store.localAppendEvent({ ...EV, canonicalToolId: 'a.two' });
  const file = join(store.telemetryTenantDir('t1'), 'events.jsonl');
  appendFileSync(file, '{"torn":\n');
  store.localAppendEvent({ ...EV, canonicalToolId: 'a.three' });
  const ids = store.localReadEvents('t1').map((e) => e.canonicalToolId);
  assert.deepStrictEqual(ids, ['a.one', 'a.two', 'a.three']);
});

test('localReadEventsFrom pages by index and reports the resume index', () => {
  const first = store.localReadEventsFrom('t1', 0, 2);
  assert.strictEqual(first.events.length, 2);
  assert.strictEqual(first.next, 2);
  const rest = store.localReadEventsFrom('t1', first.next, 10);
  assert.deepStrictEqual(rest.events.map((e) => e.canonicalToolId), ['a.three']);
  assert.strictEqual(rest.next, 3);
  assert.strictEqual(store.localReadEventsFrom('t1', 99, 10).events.length, 0);
});

test('upload state defaults to empty and round-trips atomically', () => {
  assert.deepStrictEqual(store.readUploadState('fresh'), { cursor: null, lastAttemptAt: null, lastResult: null, batchKey: null, batchAttempts: 0 });
  const s = { cursor: '5', lastAttemptAt: '2026-10-12T10:00:00.000Z', lastResult: 'uploaded:5', batchKey: '5', batchAttempts: 2 };
  store.writeUploadState('fresh', s);
  assert.deepStrictEqual(store.readUploadState('fresh'), s);
  assert.ok(existsSync(join(store.telemetryTenantDir('fresh'), 'upload-state.json')));
  assert.ok(!existsSync(join(store.telemetryTenantDir('fresh'), '.lock')), 'lock file is released');
});

test('a corrupt consent line FAILS CLOSED: an older enabled version is never resurrected (§8::6)', () => {
  store.localAppendConsent('cc', { enabled: true, transport: 'auto', changedBy: 'ops', statement: 'yes' });
  assert.strictEqual(store.localCurrentConsent('cc')?.enabled, true);
  assert.strictEqual(store.localConsentCorrupt('cc'), false);
  // The revoke record is damaged on disk (torn write): reading must not fall back to the older enable.
  appendFileSync(join(store.telemetryTenantDir('cc'), 'consent.jsonl'), '{"version":2,"enabled":fal\n');
  assert.strictEqual(store.localConsentCorrupt('cc'), true);
  const cur = store.localCurrentConsent('cc');
  assert.strictEqual(cur?.enabled, false);
  assert.strictEqual(cur?.transport, 'export-only');
  // A structurally valid JSON line with the wrong shape is equally untrusted.
  store.localAppendConsent('cc2', { enabled: true, transport: 'export-only', changedBy: 'ops', statement: null });
  appendFileSync(join(store.telemetryTenantDir('cc2'), 'consent.jsonl'), '{"version":"two","enabled":false}\n');
  assert.strictEqual(store.localCurrentConsent('cc2')?.enabled, false);
});

test('attempt reservation: the budget is atomic across CONCURRENT PROCESSES — never more than max between them', async () => {
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const mod = fileURLToPath(new URL('./local-store.js', import.meta.url));
  const script = `import(${JSON.stringify(mod)}).then(m => { const r = m.reserveUploadAttempt('race', null, 3, new Date().toISOString()); console.log(r.ok ? 'OK' : r.reason); });`;
  const run = () => new Promise<string>((resolve, reject) => {
    const p = spawn(process.execPath, ['--input-type=module', '-e', script], { env: { ...process.env, EPIC_AI_DIR_OVERRIDE: tmp } });
    let out = '';
    p.stdout.on('data', (d: Buffer) => { out += d.toString(); });
    p.on('error', reject);
    p.on('close', () => resolve(out.trim()));
  });
  const results = await Promise.all(Array.from({ length: 8 }, run));
  assert.strictEqual(results.filter((r) => r === 'OK').length, 3, `exactly 3 of 8 racing processes may transmit, got ${JSON.stringify(results)}`);
  assert.strictEqual(results.filter((r) => r === 'exhausted').length, 5);
});

test('attempt reservation: a cursor that has moved (another process sent or dropped the batch) is refused', () => {
  store.writeUploadState('mv', { cursor: '7', lastAttemptAt: null, lastResult: null, batchKey: null, batchAttempts: 0 });
  assert.deepStrictEqual(store.reserveUploadAttempt('mv', '3', 3, new Date().toISOString()), { ok: false, reason: 'moved' });
  assert.deepStrictEqual(store.reserveUploadAttempt('mv', '7', 3, new Date().toISOString()), { ok: true, attempts: 1 });
});

test('the on-disk consent file is plain JSONL with one object per version', () => {
  const lines = readFileSync(join(store.telemetryTenantDir('t1'), 'consent.jsonl'), 'utf8').trim().split('\n');
  assert.strictEqual(lines.length, 3);
  for (const l of lines) assert.doesNotThrow(() => JSON.parse(l));
});
