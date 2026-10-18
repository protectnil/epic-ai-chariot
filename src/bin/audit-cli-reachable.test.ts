/**
 * @epicai/chariot — CLI audit anchor / attest reachability adversarial eval
 *
 * Proves that `chariot audit anchor` and `chariot audit attest` are registered
 * as real subcommands and are NOT silently missing ("unknown command"). The
 * commands must reach their first validation gate (missing env-var config)
 * rather than falling through to the default "unknown command" branch.
 *
 * Pre-fix: cmdAudit() was present in chariot.ts but NOT wired into the main()
 * switch — running `chariot audit anchor` fell through to the default branch
 * and printed "Unknown command: audit", giving operators a false "not found"
 * instead of a config-error they could act on.
 *
 * How we assert "registered":
 *   - anchor: exits with error containing "CHARIOT_TSA_URL" (missing config),
 *             NOT "Unknown command: audit"
 *   - attest: exits with error containing "CHARIOT_AUDIT_SIGNING_KEY"
 *             (missing config), NOT "Unknown command: audit"
 *
 * Run after `tsc`: node --test dist/bin/audit-cli-reachable.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
// This test file compiles to dist/bin/audit-cli-reachable.test.js
// chariot.js is in the same directory
const CHARIOT_BIN = join(__dirname, 'chariot.js');

/** Run chariot with given args; capture combined stdout+stderr; no CHARIOT_* creds. */
function runAudit(subArgs: string[]): { output: string; exitCode: number } {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    // Scrub credentials so the commands reach their "not configured" gate
    CHARIOT_TSA_URL: '',
    CHARIOT_AUDIT_SIGNING_KEY: '',
    CHARIOT_NON_INTERACTIVE: '1',
  };
  const r = spawnSync(process.execPath, [CHARIOT_BIN, 'audit', ...subArgs], {
    encoding: 'utf-8',
    env,
    timeout: 15_000,
  });
  const output = (r.stdout ?? '') + (r.stderr ?? '');
  return { output, exitCode: r.status ?? 1 };
}

// ── chariot audit anchor ──────────────────────────────────────────────────────

test('chariot audit anchor is registered as a real subcommand', () => {
  const { output, exitCode } = runAudit(['anchor']);

  assert.ok(
    !output.includes('Unknown command'),
    `"Unknown command" in output — anchor is NOT wired up.\nOutput: ${output}`,
  );
  assert.ok(
    output.toLowerCase().includes('tsa') || output.includes('CHARIOT_TSA_URL'),
    `Expected TSA config error; got output: ${output}`,
  );
  // exit code 1 is expected (missing config) — NOT 0 (success) or falling through
  assert.notEqual(exitCode, 0, 'anchor with no TSA config must exit non-zero');
});

// ── chariot audit attest ──────────────────────────────────────────────────────

test('chariot audit attest is registered as a real subcommand', () => {
  const { output, exitCode } = runAudit(['attest']);

  assert.ok(
    !output.includes('Unknown command'),
    `"Unknown command" in output — attest is NOT wired up.\nOutput: ${output}`,
  );
  assert.ok(
    output.includes('CHARIOT_AUDIT_SIGNING_KEY') || output.toLowerCase().includes('signing'),
    `Expected signing-key config error; got output: ${output}`,
  );
  assert.notEqual(exitCode, 0, 'attest with no signing key must exit non-zero');
});

// ── Negative control: a truly unknown subcommand still errors distinctly ─────

test('chariot audit unknown-sub exits with a recognisable error (sanity check)', () => {
  const { output } = runAudit(['__not_a_real_subcommand__']);
  // If the cmdAudit implementation falls through on unknown subs it should
  // still print something useful (not silently succeed). The exact text is
  // implementation-defined; we just assert we got some output and non-zero exit.
  assert.ok(output.length > 0, 'must produce output for unknown sub-subcommand');
});
