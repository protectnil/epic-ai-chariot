/**
 * @epicai/chariot — CLI adversarial eval for `chariot audit rotate-key`
 * (CHARIOT::§9.8.1::3, gate finding completions #3)
 *
 * Spawns the REAL built CLI (dist/bin/chariot.js) as a child process —
 * same harness pattern as src/cli/cli-honest-signal.test.ts. Zero mocks.
 *
 * Failure classes:
 *   1. `rotate-key --backend sealed-store` in a fresh EPIC_AI_DIR (no prior
 *      key) succeeds, prints/returns a kid and NO private material, and
 *      records oldKid: null (first-ever rotation).
 *   2. A second rotation in the SAME dir succeeds, chains from the first
 *      rotation's kid (oldKid === first kid), and produces a distinct kid.
 *   3. After two rotations, the persistent verify-key store
 *      (<dir>/audit/verify-keys.json) contains BOTH kids — the actual
 *      "publish the new public key via the same distribution path"
 *      wiring, inspected as a real on-disk artifact, not simulated.
 *   4. `--backend kms` without `--kms-key-id` fails with USAGE_ERROR
 *      (never attempts a network call).
 *   5. `--backend vault-transit` without the required Vault env vars fails
 *      with USAGE_ERROR (never attempts a network call).
 *
 * Build first: npm run build
 * Run:         node --test dist/bin/audit-rotate-key.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

const __dirname = dirname(fileURLToPath(import.meta.url));
// dist/bin/audit-rotate-key.test.js → dist/bin/chariot.js
const CLI = resolve(__dirname, 'chariot.js');

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(argv: string[], env: Record<string, string>): RunResult {
  const r = spawnSync(process.execPath, [CLI, ...argv], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 30000,
  });
  return { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function parseEnvelope(stdout: string): Record<string, unknown> {
  const lines = stdout.trim().split('\n').filter(Boolean);
  assert.ok(lines.length > 0, `stdout was empty — no JSON envelope emitted`);
  return JSON.parse(lines[lines.length - 1]) as Record<string, unknown>;
}

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'chariot-rotate-cli-'));
}

const MASTER_KEY = Buffer.alloc(32, 0x37).toString('base64');

test('rotate-key --backend sealed-store: first rotation succeeds, no private material in the envelope, oldKid null', () => {
  const dir = tmp();
  try {
    const r = runCli(['audit', 'rotate-key', '--backend', 'sealed-store', '--json'], {
      EPIC_AI_DIR_OVERRIDE: dir,
      ENTERPRISE_MASTER_KEY: MASTER_KEY,
    });
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, true, `rotate-key must succeed: ${JSON.stringify(env)} stderr=${r.stderr}`);
    const data = env.data as Record<string, unknown>;
    assert.equal(data.oldKid, null, 'first-ever rotation must record oldKid: null');
    assert.equal(typeof data.kid, 'string');
    assert.ok((data.kid as string).length > 0);
    assert.equal(typeof data.publicKeyPem, 'string');
    assert.ok((data.publicKeyPem as string).includes('PUBLIC KEY'));
    // No field anywhere in the envelope may carry a private key.
    const wholeEnvelope = JSON.stringify(env);
    assert.ok(!wholeEnvelope.includes('PRIVATE KEY'), 'rotate-key must never emit private key material');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rotate-key --backend sealed-store: second rotation chains from the first (oldKid === first kid), distinct new kid', () => {
  const dir = tmp();
  try {
    const first = parseEnvelope(
      runCli(['audit', 'rotate-key', '--backend', 'sealed-store', '--json'], {
        EPIC_AI_DIR_OVERRIDE: dir,
        ENTERPRISE_MASTER_KEY: MASTER_KEY,
      }).stdout,
    );
    assert.equal(first.ok, true);
    const firstKid = (first.data as Record<string, unknown>).kid as string;

    const second = parseEnvelope(
      runCli(['audit', 'rotate-key', '--backend', 'sealed-store', '--json'], {
        EPIC_AI_DIR_OVERRIDE: dir,
        ENTERPRISE_MASTER_KEY: MASTER_KEY,
      }).stdout,
    );
    assert.equal(second.ok, true, `second rotation must succeed: ${JSON.stringify(second)}`);
    const secondData = second.data as Record<string, unknown>;
    assert.equal(secondData.oldKid, firstKid, "second rotation must chain from the FIRST rotation's kid");
    assert.notEqual(secondData.kid, firstKid, 'each rotation must mint a distinct kid');

    // The persistent verify-key store must now hold BOTH kids — the real
    // "publish the new public key via the same distribution path" wiring.
    const store = JSON.parse(readFileSync(join(dir, 'audit', 'verify-keys.json'), 'utf-8')) as Record<string, unknown>;
    assert.ok(firstKid in store, `verify-keys.json must retain the first (now-retired) kid: ${JSON.stringify(store)}`);
    assert.ok((secondData.kid as string) in store, 'verify-keys.json must contain the second (current) kid');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rotate-key --backend kms without --kms-key-id fails with USAGE_ERROR, no network attempted', () => {
  const dir = tmp();
  try {
    const r = runCli(['audit', 'rotate-key', '--backend', 'kms', '--json'], {
      EPIC_AI_DIR_OVERRIDE: dir,
    });
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false);
    assert.equal(env.code, 'USAGE_ERROR');
    assert.match(String(env.human_message), /--kms-key-id is required/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rotate-key --backend vault-transit without required Vault env vars fails with USAGE_ERROR, no network attempted', () => {
  const dir = tmp();
  try {
    const r = runCli(['audit', 'rotate-key', '--backend', 'vault-transit', '--json'], {
      EPIC_AI_DIR_OVERRIDE: dir,
      CHARIOT_AUDIT_VAULT_ADDR: '',
      CHARIOT_AUDIT_VAULT_TOKEN: '',
      CHARIOT_AUDIT_VAULT_KEY_NAME: '',
    });
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false);
    assert.equal(env.code, 'USAGE_ERROR');
    assert.match(String(env.human_message), /CHARIOT_AUDIT_VAULT_ADDR/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rotate-key --backend unknown-backend fails with USAGE_ERROR', () => {
  const dir = tmp();
  try {
    const r = runCli(['audit', 'rotate-key', '--backend', 'floppy-disk', '--json'], {
      EPIC_AI_DIR_OVERRIDE: dir,
    });
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false);
    assert.equal(env.code, 'USAGE_ERROR');
    assert.match(String(env.human_message), /Unknown --backend/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
