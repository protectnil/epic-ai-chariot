/**
 * CHARIOT-SPEC §23.1 / CH-24 — the REAL container entrypoint honors the boot
 * entitlement gate.
 *
 * Dockerfile ENTRYPOINT is `node dist/bin/gateway.js`. Clause
 * (CHARIOT-SPEC §23): "`CheckoutLicense` at gateway
 * boot ... License Manager is selected only under an explicit env flag."
 * Before this gate was wired, setting the License Manager env on the image
 * changed nothing at runtime (checkoutEntitlementAtBoot was reachable only via
 * bootstrapEnterprise(), which no entrypoint calls).
 *
 * Spawns the compiled entrypoint as a subprocess:
 *   E1 LM selected + required config missing -> exit 1 BEFORE listening
 *   E2 LM selected + checkout cannot succeed (no credentials, real SDK path)
 *      -> exit 1 BEFORE listening
 *   E3 offline default (no LM env) -> reaches "Listening", never refuses
 *
 * Run after `tsc`: node --test dist/bin/gateway-entitlement-boot.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(here, 'gateway.js');

interface Run {
  code: number | null;
  stdout: string;
  stderr: string;
  sawListening: boolean;
}

function runEntry(env: Record<string, string>, killOnListening: boolean): Promise<Run> {
  const dir = mkdtempSync(join(tmpdir(), 'gw-entry-'));
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [ENTRY, '--port', '0', '--no-auto-discover'], {
      env: {
        PATH: process.env.PATH ?? '',
        HOME: dir,
        EPIC_AI_DIR_OVERRIDE: dir,
        AWS_EC2_METADATA_DISABLED: 'true',
        AWS_SHARED_CREDENTIALS_FILE: join(dir, 'none'),
        AWS_CONFIG_FILE: join(dir, 'none'),
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let sawListening = false;
    const finish = (code: number | null): void => {
      clearTimeout(timer);
      rmSync(dir, { recursive: true, force: true });
      resolve({ code, stdout, stderr, sawListening });
    };
    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString();
      if (!sawListening && stdout.includes('Listening:')) {
        sawListening = true;
        if (killOnListening) child.kill('SIGKILL');
      }
    });
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString();
    });
    child.on('close', (code) => finish(code));
    const timer = setTimeout(() => child.kill('SIGKILL'), 40_000);
  });
}

const LM = {
  CHARIOT_LICENSE_PROVIDER: 'aws-license-manager',
  AWS_REGION: 'us-east-1',
  CHARIOT_LM_TIER: 'basic',
};

test('E1 LM selected, product SKU missing: exits 1 before listening', async () => {
  const r = await runEntry({ ...LM }, false);
  assert.equal(r.code, 1, `stderr=${r.stderr}`);
  assert.match(r.stderr, /Gateway startup refused/);
  assert.match(r.stderr, /CHARIOT_LM_PRODUCT_SKU/);
  assert.equal(r.sawListening, false);
});

test('E2 LM selected, checkout cannot succeed: exits 1 before listening', async () => {
  const r = await runEntry({ ...LM, CHARIOT_LM_PRODUCT_SKU: 'prod-abc123' }, false);
  assert.equal(r.code, 1, `stderr=${r.stderr}`);
  assert.match(r.stderr, /Gateway startup refused/);
  assert.match(r.stderr, /License Manager entitlement check failed/);
  assert.equal(r.sawListening, false);
});

test('E3 offline default: reaches Listening, no entitlement refusal', async () => {
  const r = await runEntry({}, true);
  assert.equal(r.sawListening, true, `stdout=${r.stdout} stderr=${r.stderr}`);
  assert.doesNotMatch(r.stderr, /Gateway startup refused/);
});
