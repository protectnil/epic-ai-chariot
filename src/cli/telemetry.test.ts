/**
 * Behavioral tests for `chariot telemetry` (src/cli/telemetry.ts) — the
 * agent-operable control surface, C4AMD §8 (amended 2026-10-12). Real
 * execution: local store under a temp EPIC_AI_DIR_OVERRIDE, no license,
 * no signer key, no network.
 *
 * Run (after tsc): node --test dist/cli/telemetry.test.js
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = mkdtempSync(join(tmpdir(), 'chariot-telemetry-cli-'));
process.env.EPIC_AI_DIR_OVERRIDE = tmp;
process.env.HOME = tmp; // no real license/audit key can leak in
process.env.CHARIOT_TENANT_ID = 'cli-t';
delete process.env.CHARIOT_AUDIT_SIGNER_BACKEND;
delete process.env.ENTERPRISE_MASTER_KEY;

const { runTelemetryCommand } = await import('./telemetry.js');
const { getCommand, buildManifest } = await import('./capabilities.js');
const { captureEvent } = await import('../observability/operational-telemetry/capture.js');

after(() => rmSync(tmp, { recursive: true, force: true }));

test('default subcommand is status; telemetry is OFF out of the box', async () => {
  const env = await runTelemetryCommand([]);
  assert.strictEqual(env.ok, true);
  assert.strictEqual(env.surface, 'cli:telemetry');
  const d = env.data as Record<string, unknown>;
  assert.strictEqual(d.enabled, false);
  assert.strictEqual(d.consentVersion, 0);
  assert.strictEqual(d.store, 'local-file');
  assert.deepStrictEqual((d.fields as string[]).length, 9);
  assert.match(env.human_message ?? '', /OFF/);
});

test('enable without --statement is refused with an instruction to ask the user — consent is never assumed', async () => {
  const env = await runTelemetryCommand(['enable']);
  assert.strictEqual(env.ok, false);
  assert.strictEqual(env.code, 'USAGE_ERROR');
  assert.strictEqual(env.exit_code, 2);
  assert.match(env.agent_message ?? '', /Do NOT enable telemetry on your own initiative/);
  const status = await runTelemetryCommand(['status']);
  assert.strictEqual((status.data as Record<string, unknown>).enabled, false);
});

test('enable with the user\'s words turns it on (export-only by default) and records a version', async () => {
  const env = await runTelemetryCommand(['enable', '--statement', 'Yes, turn on feedback for Chariot.']);
  assert.strictEqual(env.ok, true);
  const d = env.data as Record<string, unknown>;
  assert.deepStrictEqual([d.enabled, d.transport, d.consentVersion], [true, 'export-only', 1]);
  const ev = await captureEvent({
    tenantId: 'cli-t', canonicalToolId: 'a.b', outcome: 'success', latencyMs: 1, failureStage: null, occurredAt: new Date(),
  });
  assert.ok(ev, 'capture now works');
  const st = await runTelemetryCommand(['status']);
  assert.strictEqual((st.data as Record<string, unknown>).eventsStored, 1);
});

test('--transport auto is refused without a verified connected license, with a typed non-retryable answer', async () => {
  const env = await runTelemetryCommand(['enable', '--statement', 'yes', '--transport', 'auto']);
  assert.strictEqual(env.ok, false);
  assert.strictEqual(env.code, 'TELEMETRY_AUTO_NOT_PERMITTED');
  assert.ok((env.must_not ?? []).length > 0);
  // The refusal must not have changed consent.
  const st = await runTelemetryCommand(['status']);
  assert.strictEqual((st.data as Record<string, unknown>).transport, 'export-only');
  assert.strictEqual((st.data as Record<string, unknown>).consentVersion, 1);
});

test('an unknown --transport is a usage error', async () => {
  const env = await runTelemetryCommand(['enable', '--statement', 'yes', '--transport', 'carrier-pigeon']);
  assert.strictEqual(env.code, 'USAGE_ERROR');
});

test('export with no signing key configured fails typed — it never writes an unsigned file', async () => {
  const out = join(tmp, 'x', 'export.json');
  const env = await runTelemetryCommand(['export', '--out', out]);
  assert.strictEqual(env.ok, false);
  assert.strictEqual(env.code, 'SIGNING_KEY_NOT_CONFIGURED');
  assert.ok((env.must_not ?? []).some((m) => /unsigned/.test(m)));
  // The remediation names concrete, working steps (ruling 394), not "set the backend".
  const steps = (env.remediation ?? []).join('\n');
  assert.match(steps, /ENTERPRISE_MASTER_KEY/);
  assert.match(steps, /CHARIOT_AUDIT_SIGNER_BACKEND=kms or vault-transit/);
  assert.match(steps, /--transport auto/);
  // CHARIOT §9.8.1: the remediation never directs an operator to write key material to the host filesystem.
  assert.doesNotMatch(steps, /\.pem|import-key/);
  assert.match(steps, /AUDIT-SIGNING-KEY-RUNBOOK\.md/);
  const { existsSync } = await import('node:fs');
  assert.strictEqual(existsSync(out), false);
});

test('disable stops collection and records a new version', async () => {
  const env = await runTelemetryCommand(['disable']);
  assert.strictEqual(env.ok, true);
  assert.strictEqual((env.data as Record<string, unknown>).consentVersion, 2);
  const ev = await captureEvent({
    tenantId: 'cli-t', canonicalToolId: 'a.b', outcome: 'success', latencyMs: 1, failureStage: null, occurredAt: new Date(),
  });
  assert.strictEqual(ev, null);
});

test('unknown subcommand is a usage error pointing at capabilities', async () => {
  const env = await runTelemetryCommand(['frobnicate']);
  assert.strictEqual(env.code, 'USAGE_ERROR');
});

test('the capability manifest lists telemetry so an agent can discover it (AI is the UI)', () => {
  const cap = getCommand('telemetry');
  assert.ok(cap, 'telemetry capability exists');
  assert.strictEqual(cap!.noninteractive.available, true);
  assert.strictEqual(cap!.interactive, false);
  assert.ok(buildManifest('0.0.0').commands.some((c) => c.name === 'telemetry'));
  const stmt = cap!.args.find((a) => a.name === '--statement');
  assert.match(stmt?.description ?? '', /Ask the user first/);
});
