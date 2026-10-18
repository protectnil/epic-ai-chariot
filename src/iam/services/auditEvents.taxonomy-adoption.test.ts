/**
 * CHARIOT::§16.1 Audit (CHARIOT-SPEC.md:1349, rulings item 91/105) —
 * "Audit: `audit.gap_detected`, `audit.export_started`,
 * `audit.export_completed`."
 *
 * SOURCE INSPECTION (this repo's established convention — see
 * audit.gap-detection.test.ts, which this file's first test complements
 * without duplicating: that file proves the CH-15 mechanism itself;
 * this file proves the NEW §16.1-taxonomy event alongside it).
 *
 * Run (after tsc): node --test dist/iam/services/auditEvents.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const auditSrc = readFileSync(fileURLToPath(new URL('./audit.js', import.meta.url)), 'utf8');
const adminSrc = readFileSync(fileURLToPath(new URL('../routes/admin.js', import.meta.url)), 'utf8');

test('§16.1 Audit: assertChainHeadMatchesCounter emits audit.gap_detected (critical, alertWorthy) ALONGSIDE the pre-existing system.error alert, before the fail-closed throw', () => {
  const fnStart = auditSrc.indexOf('async function assertChainHeadMatchesCounter');
  const throwIdx = auditSrc.indexOf('throw new Error', fnStart);
  const systemErrorIdx = auditSrc.indexOf("chariotEmitter.send('system.error'", fnStart);
  const gapDetectedIdx = auditSrc.indexOf("chariotEmitter.send('audit.gap_detected'", fnStart);
  assert.ok(fnStart >= 0 && throwIdx > fnStart, 'the gap-detection helper and its fail-closed throw must exist');
  assert.ok(systemErrorIdx > fnStart && systemErrorIdx < throwIdx, 'system.error must still fire (not replaced)');
  assert.ok(gapDetectedIdx > systemErrorIdx && gapDetectedIdx < throwIdx, 'audit.gap_detected must fire after system.error, still before the fail-closed throw');
  const body = auditSrc.slice(gapDetectedIdx, throwIdx);
  assert.match(body, /severity:\s*'critical'/);
  assert.match(body, /alertWorthy:\s*true/);
});

test('§16.1 Audit: GET /audit-logs emits audit.export_started before the §9.8.3::4 halt checks', () => {
  const routeStart = adminSrc.indexOf("router.get('/audit-logs'");
  const startedIdx = adminSrc.indexOf("chariotEmitter.send('audit.export_started'", routeStart);
  const unverifiableHaltIdx = adminSrc.indexOf("chariotEmitter.send('audit.attestation_unverifiable'", routeStart);
  const truncationHaltIdx = adminSrc.indexOf("chariotEmitter.send('audit.tail_truncation_detected'", routeStart);
  assert.ok(routeStart >= 0);
  assert.ok(startedIdx > routeStart, 'audit.export_started must be emitted in this route');
  assert.ok(startedIdx < unverifiableHaltIdx && startedIdx < truncationHaltIdx, 'export_started must fire BEFORE either halt check, since the export genuinely began even if it is later halted');
});

test('§16.1 Audit: GET /audit-logs emits audit.export_completed only on the genuine success path, after res.end()', () => {
  const routeStart = adminSrc.indexOf("router.get('/audit-logs'");
  // Regex, not a literal "} catch (err) {" substring — tsc emits the
  // closing brace and `catch` on separate lines in compiled output.
  const catchMatch = /\}\s*catch\s*\(err\)\s*\{/.exec(adminSrc.slice(routeStart));
  const catchIdx = catchMatch ? routeStart + catchMatch.index : -1;
  const completedIdx = adminSrc.indexOf("chariotEmitter.send('audit.export_completed'", routeStart);
  const unverifiableHaltIdx = adminSrc.indexOf("chariotEmitter.send('audit.attestation_unverifiable'", routeStart);
  const truncationHaltIdx = adminSrc.indexOf("chariotEmitter.send('audit.tail_truncation_detected'", routeStart);
  assert.ok(completedIdx > 0 && completedIdx < catchIdx, 'export_completed must be inside the try block, before the catch');
  assert.ok(completedIdx > unverifiableHaltIdx && completedIdx > truncationHaltIdx, 'export_completed must come after both halt-check points in source order, i.e. only reached when neither halt fired');
  const resEndIdx = adminSrc.lastIndexOf('res.end();', completedIdx);
  assert.ok(resEndIdx > 0 && resEndIdx < completedIdx, 'export_completed must be emitted after the response has actually been ended');
});
