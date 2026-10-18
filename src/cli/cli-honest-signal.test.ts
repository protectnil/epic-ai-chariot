/**
 * CH-31/CH-32 Honest-Signal Adversarial CLI Evals — d756d58 regression gate
 *
 * Spawns the REAL built CLI (dist/bin/chariot.js) as a child process.
 * Zero mocks. No happy-path-only coverage. Each test is a named attack that
 * asserts the honest-signal contract defined in CH-31/CH-32.
 *
 * Build first: npm run build
 * Run:         node --test dist/cli/cli-honest-signal.test.js
 *
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HashChain } from '../engine/audit/HashChain.js';
import { sealSigningKey } from '../engine/audit/chainSigner.js';

// CHARIOT::§9.8.1::1 (gate finding F1) — the plaintext `env` backend this
// file's attest tests used to rely on (`CHARIOT_AUDIT_SIGNING_KEY: privatePem`
// read directly by `chariot audit attest`) no longer exists. Attest now goes
// through the sealed-store backend (the default), which requires
// ENTERPRISE_MASTER_KEY. Set ONE fixed, deterministic test value for the
// whole file — every test below provisions its own per-test EPIC_AI_DIR
// (`tmp()`), so a shared master key never lets one test's sealed key decrypt
// under another test's directory (the AAD binding is per sealed-store dir,
// not per master key). `runCli`'s env merge starts from `process.env`, so
// setting this once here makes it available to every spawned subprocess
// without touching each individual `env: {...}` block below.
process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 0x42).toString('base64');

/**
 * Provision a sealed-store signing key at `dir` (this test's EPIC_AI_DIR)
 * from an existing Ed25519 private key PEM, so a subsequently spawned
 * `chariot audit attest` subprocess can sign with it. Replaces the removed
 * `CHARIOT_AUDIT_SIGNING_KEY` env-var path — CHARIOT §9.8.1::1 no longer
 * permits a plaintext env key in ANY mode.
 */
function provisionSealedStoreKey(dir: string, privatePem: string): void {
  sealSigningKey(dir, privatePem);
}

const __dirname = dirname(fileURLToPath(import.meta.url));
// dist/cli/cli-honest-signal.test.js → dist/bin/chariot.js
const CLI = resolve(__dirname, '..', 'bin', 'chariot.js');

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(argv: string[], opts: { env?: Record<string, string> } = {}): RunResult {
  const r = spawnSync(process.execPath, [CLI, ...argv], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', ...opts.env },
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 30000,
  });
  return { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** Parse the last non-empty JSON line from stdout (agent-mode envelope). */
function parseEnvelope(stdout: string): Record<string, unknown> {
  const lines = stdout.trim().split('\n').filter(Boolean);
  assert.ok(lines.length > 0, `stdout was empty — no JSON envelope emitted`);
  return JSON.parse(lines[lines.length - 1]) as Record<string, unknown>;
}

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'chariot-eval-'));
}

// ── ATTACK 1: list --json and search --json <term> ─────────────────────────
//
// Neither `list --json` nor `search --json <term>` may treat `--json` as the
// search term. CH-32: the fix in d756d58 extracts the first non-flag positional
// so flags remain flags. These tests assert the fix holds.

test('Attack 1a: chariot list --json emits ok:true envelope with curated+custom arrays, exit 0', () => {
  const r = runCli(['list', '--json']);
  assert.equal(r.code, 0, `expected exit 0, got ${r.code}. stderr: ${r.stderr}`);
  const env = parseEnvelope(r.stdout);
  assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);
  assert.equal(env.code, 'OK', `expected code:OK, got ${env.code}`);
  const data = env.data as Record<string, unknown>;
  assert.ok(data !== null && typeof data === 'object', 'data must be an object');
  assert.ok(Array.isArray(data.curated), 'data.curated must be an array');
  assert.ok(Array.isArray(data.custom), 'data.custom must be an array');
  // --json must not appear as an adapter id in the results
  const allIds = ([...(data.curated as Array<{ id: string }>), ...(data.custom as Array<{ id: string }>)]).map(a => a.id);
  assert.ok(!allIds.includes('--json'), '--json must never be treated as an adapter id');
});

test('Attack 1b: chariot search --json slack → ok:true, term=slack (--json not the term)', () => {
  const r = runCli(['search', '--json', 'slack']);
  assert.equal(r.code, 0, `expected exit 0, got ${r.code}. stderr: ${r.stderr}`);
  const env = parseEnvelope(r.stdout);
  assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);
  const data = env.data as Record<string, unknown>;
  assert.ok(Array.isArray(data.results), 'data.results must be an array');
  // term must be 'slack', never '--json' (the CH-32 fix)
  assert.equal(data.term, 'slack', `search term must be 'slack', got '${data.term}'`);
});

test('Attack 1c: chariot search slack --json → ok:true, term=slack (flag after term)', () => {
  const r = runCli(['search', 'slack', '--json']);
  assert.equal(r.code, 0, `expected exit 0, got ${r.code}`);
  const env = parseEnvelope(r.stdout);
  assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);
  const data = env.data as Record<string, unknown>;
  assert.equal(data.term, 'slack', `search term must be 'slack', got '${data.term}'`);
});

// ── ATTACK 2: no-match query → ok:false AND exit non-zero ──────────────────
//
// CH-31: an ok:false envelope MUST carry a non-zero exit_code AND the process
// must exit with that code. The 3.1.2 dogfood exposed ok:false envelopes that
// still exit 0, which broke CI/agent branching logic. This attack probes that gap.

test('Attack 2: search for a nonexistent term → ok:false AND exit non-zero (honest-signal contract)', () => {
  const r = runCli(['search', '--json', '__NOSUCHADAPTER_xyzzy999__']);
  const env = parseEnvelope(r.stdout);
  assert.equal(env.ok, false, `expected ok:false, got ok:${env.ok}`);
  assert.notEqual(r.code, 0, [
    `exit 0 with ok:false violates the CH-31 honest-signal contract.`,
    `Envelope: ${JSON.stringify(env)}`,
  ].join(' '));
  // exit_code in the envelope must equal the process exit code
  assert.equal(r.code, env.exit_code as number, `process exit code (${r.code}) must match envelope exit_code (${env.exit_code})`);
});

// ── ATTACK 3: approve/revoke/approvals/resume/trace/audit → parseable JSON ──
//
// CH-32 agent mode: every command that accepts --json MUST emit a parseable
// JSON envelope on stdout. Human-readable text on stdout (instead of/in addition
// to an envelope) is an honest-signal contract violation. Proven here by running
// each command in a clean sandbox and verifying that stdout is valid JSON with
// required envelope fields.

test('Attack 3a: chariot approvals --json → parseable JSON envelope, ok:true for empty list', () => {
  const dir = tmp();
  try {
    const r = runCli(['approvals', '--json'], { env: { EPIC_AI_DIR_OVERRIDE: dir } });
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, true, `empty approvals list must be ok:true, got ${JSON.stringify(env)}`);
    assert.equal(env.code, 'OK');
    const data = env.data as Record<string, unknown>;
    assert.ok(Array.isArray(data.approvals), 'data.approvals must be an array');
    assert.equal(data.count, 0, 'empty sandbox must have count:0');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 3b: chariot revoke <nonexistent> --json → parseable JSON envelope, ok:false', () => {
  const dir = tmp();
  try {
    const r = runCli(['revoke', 'nonexistent-eval-adapter-xyz', '--json'], { env: { EPIC_AI_DIR_OVERRIDE: dir } });
    const env = parseEnvelope(r.stdout);
    // Envelope fields must be present
    assert.equal(typeof env.ok, 'boolean', 'ok must be boolean');
    assert.equal(typeof env.code, 'string', 'code must be string');
    assert.equal(typeof env.exit_code, 'number', 'exit_code must be number');
    assert.equal(env.ok, false, 'revoke with no approval must be ok:false');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 3c: chariot resume <fakeid> --json → parseable JSON envelope', () => {
  const dir = tmp();
  try {
    const r = runCli(['resume', 'eval-fake-trace-id-xyz-0000', '--json'], { env: { EPIC_AI_DIR_OVERRIDE: dir } });
    const env = parseEnvelope(r.stdout);
    assert.equal(typeof env.ok, 'boolean', 'ok must be boolean');
    assert.equal(typeof env.code, 'string', 'code must be string');
    assert.equal(typeof env.exit_code, 'number', 'exit_code must be number');
    assert.equal(typeof env.surface, 'string', 'surface must be string');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 3d: chariot trace explain <traceId> --json → parseable JSON envelope', () => {
  const dir = tmp();
  try {
    // With no audit file present the CLI emits AUDIT_FILE_NOT_FOUND — still a
    // parseable envelope, not raw human text. That is the contract being checked.
    const r = runCli(['trace', 'explain', 'eval-fake-trace-id-xyz-0001', '--json'], { env: { EPIC_AI_DIR_OVERRIDE: dir } });
    const env = parseEnvelope(r.stdout);
    assert.equal(typeof env.ok, 'boolean', 'ok must be boolean');
    assert.equal(typeof env.code, 'string', 'code must be string');
    assert.equal(env.surface, 'cli:trace', `surface must be cli:trace, got ${env.surface}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 3e: chariot audit verify-length --json → parseable JSON envelope', () => {
  const dir = tmp();
  try {
    const r = runCli(
      ['audit', 'verify-length', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: 'eval-test-chain' } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(typeof env.ok, 'boolean', 'ok must be boolean');
    assert.equal(typeof env.code, 'string', 'code must be string');
    assert.equal(env.surface, 'cli:audit', `surface must be cli:audit, got ${env.surface}`);
    // Empty chain + no attestations → not truncated → ok:true
    assert.equal(env.ok, true, `verify-length with no chain/attestations must be ok:true, got ${JSON.stringify(env)}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── ATTACK 4: revoke with no approval → distinct from successful revoke ─────
//
// CH-31: a "nothing to revoke" outcome MUST be distinguishable from a genuine
// successful revoke. Prior to d756d58 this was not guaranteed — the outcome
// code was not asserted by any eval. A successful revoke is ok:true/exit-0;
// a nothing-to-revoke must be ok:false/exit-non-zero.

test('Attack 4: revoke with no active approval → ok:false, exit non-zero, code NOT_FOUND', () => {
  const dir = tmp();
  try {
    const r = runCli(['revoke', 'eval-never-approved-xyz-adapter', '--json'], { env: { EPIC_AI_DIR_OVERRIDE: dir } });
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, `expected ok:false — nothing to revoke. Got ${JSON.stringify(env)}`);
    assert.notEqual(r.code, 0, `exit 0 when nothing to revoke violates CH-31 (cannot be distinguished from ok:true)`);
    assert.equal(env.code, 'NOT_FOUND', `expected code:NOT_FOUND, got ${env.code}`);
    // exit_code in envelope must match actual process exit
    assert.equal(r.code, env.exit_code as number, `process exit (${r.code}) must equal envelope exit_code (${env.exit_code})`);
    // must not contain data.revoked:true
    const data = env.data as Record<string, unknown> | undefined;
    if (data) assert.equal(data.revoked, false, 'data.revoked must be false when nothing was revoked');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── ATTACK 5: capability manifest completeness ──────────────────────────────
//
// CH-32: the manifest is the machine-readable "AI UI". Every command the
// operator can run must appear so that agents can auto-discover non-interactive
// invocations without scraping --help prose. Missing entries break agent-driven
// workflows silently.

const REQUIRED_COMMANDS = [
  'status', 'license', 'audit', 'approve', 'approvals',
  'revoke', 'resume', 'trace',
  // core surface
  'query', 'list', 'search', 'add', 'remove', 'health',
  'serve', 'configure', 'capabilities', 'version', 'help', 'discover',
];

test('Attack 5: capabilities --json manifest lists ALL required commands', () => {
  const r = runCli(['capabilities', '--json']);
  assert.equal(r.code, 0, `expected exit 0, got ${r.code}. stderr: ${r.stderr}`);
  // capabilities outputs the manifest directly (not wrapped in an envelope)
  const manifest = parseEnvelope(r.stdout);
  assert.equal(manifest.product, 'epic-ai-chariot', `wrong product: ${manifest.product}`);
  assert.ok(Array.isArray(manifest.commands), 'commands must be an array');
  const names = (manifest.commands as Array<{ name: string }>).map(c => c.name);
  for (const cmd of REQUIRED_COMMANDS) {
    assert.ok(names.includes(cmd), `capability manifest is missing command: "${cmd}". Found: ${JSON.stringify(names)}`);
  }
});

// ── ATTACK 6: path traversal and port boundary ──────────────────────────────
//
// Security: `--chain-id` must reject any value containing `/`, `\`, or `..`
// so an attacker cannot escape the audit/ directory. Port validation must
// silently fall back to the default for out-of-range values — never bind to
// a port like 0 or 99999.

test('Attack 6a: audit --chain-id ../../etc/passwd (path traversal) → REJECTED, ok:false, exit 2', () => {
  const dir = tmp();
  try {
    const r = runCli(
      ['audit', '--chain-id', '../../etc/passwd', 'anchor', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, 'path traversal in --chain-id must be rejected');
    assert.equal(env.code, 'USAGE_ERROR', `expected USAGE_ERROR, got ${env.code}`);
    assert.equal(r.code, 2, `expected exit 2 (USAGE), got ${r.code}`);
    // No /etc/passwd content must leak
    const combined = r.stdout + r.stderr;
    assert.ok(
      !/root:|daemon:|nobody:/.test(combined),
      'stdout/stderr must not contain /etc/passwd content',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 6b: audit --chain-id ../escape (single-hop traversal) → REJECTED', () => {
  const dir = tmp();
  try {
    const r = runCli(
      ['audit', '--chain-id', '../escape', 'anchor', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, 'relative traversal must be rejected');
    assert.equal(env.code, 'USAGE_ERROR', `expected USAGE_ERROR, got ${env.code}`);
    assert.equal(r.code, 2, `expected exit 2, got ${r.code}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 6c: chariot status --http 99999 (out-of-range port) → falls back, never queries port 99999', () => {
  // isValidPort(99999) = false (n > 65535), so the CLI silently defaults to 3550.
  // The test asserts no crash and that 99999 never appears in stdout as the
  // queried port (which would indicate the validation bypass).
  const r = runCli(['status', '--http', '99999']);
  // Valid exit codes: 0 = no listener found; 2 = lsof/ss not available.
  assert.ok(r.code === 0 || r.code === 2, `unexpected exit code ${r.code}. stderr: ${r.stderr}`);
  // Port 99999 must NOT appear in stdout as the port being queried
  assert.ok(
    !r.stdout.includes('port 99999') && !r.stderr.includes('port 99999'),
    `out-of-range port 99999 must not appear as a queried port in output. stdout=${r.stdout} stderr=${r.stderr}`,
  );
});

test('Attack 6d: chariot status --http -1 (negative port) → falls back, does not crash', () => {
  // -1 fails !/^\d{1,5}$/.test('-1') (non-digit), so isValidPort returns false → default 3550.
  const r = runCli(['status', '--http', '-1']);
  assert.ok(r.code === 0 || r.code === 2, `unexpected exit code ${r.code}. stderr: ${r.stderr}`);
  assert.ok(
    !r.stdout.includes('port -1') && !r.stderr.includes('port -1'),
    `negative port -1 must not appear as a queried port. stdout=${r.stdout} stderr=${r.stderr}`,
  );
});

// ── ATTACK 7: verify-length must FAIL CLOSED ─────────────────────────────────
//
// Zero-day regression gate: (a) deleting the attestation directory for a
// NON-EMPTY chain must never read as "chain intact" exit-0 — that was the
// attestation-deletion bypass; (b) forged/unsigned attestations must be
// rejected as tamper evidence (Ed25519 verification is now mandatory);
// (c) valid signed attestations must still detect real truncation.

const CHAIN_ID = 'eval-fail-closed-chain';

/** Fabricate a minimal JSONL hash-chain file with `n` records. */
function writeFakeChain(dir: string, n: number): void {
  mkdirSync(join(dir, 'audit'), { recursive: true });
  const lines: string[] = [];
  for (let i = 1; i <= n; i++) {
    lines.push(JSON.stringify({ sequenceNumber: i, hash: i.toString(16).padStart(64, '0') }));
  }
  writeFileSync(join(dir, 'audit', `${CHAIN_ID}.jsonl`), lines.join('\n') + '\n');
}

/**
 * Fabricate a GENUINELY VALID JSONL hash-chain: each record's `hash` is the
 * real SHA-256 over its canonicalized contents (via the production
 * HashChain.computeHash — single source of truth) and each `previousHash`
 * links to the prior record's hash, so HashChain.verifyChain(records) is
 * `valid:true`. Unlike writeFakeChain (index-hex hashes that fail per-record
 * integrity immediately) this survives every truncation/signature check and
 * the per-record integrity check — exactly the state Attack 7e must reach
 * before it tampers. Returns the on-disk record objects so the caller can
 * rewrite a field / zero a hash and re-serialize.
 */
function writeValidChain(dir: string, n: number): Record<string, unknown>[] {
  mkdirSync(join(dir, 'audit'), { recursive: true });
  const records: Record<string, unknown>[] = [];
  let previousHash = '';
  for (let i = 1; i <= n; i++) {
    const rec: Record<string, unknown> = {
      id: `rec-${i}`,
      sequenceNumber: i,
      previousHash,
      timestamp: new Date(1751400000000 + i * 1000).toISOString(),
      action: 'tool.call',
      tool: `tool-${i}`,
      server: 'srv',
      tier: 'auto',
      status: 'completed',
      input: { i },
      output: { ok: true },
      persona: 'default',
      durationMs: 5,
    };
    const hash = HashChain.computeHash(rec as unknown as Parameters<typeof HashChain.computeHash>[0]);
    rec.hash = hash;
    previousHash = hash;
    records.push(rec);
  }
  writeFileSync(
    join(dir, 'audit', `${CHAIN_ID}.jsonl`),
    records.map((r) => JSON.stringify(r)).join('\n') + '\n',
  );
  return records;
}

function ed25519Pems(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

test('Attack 7a: non-empty chain + deleted/absent attestation dir → ok:false NO_LENGTH_ATTESTATIONS, exit non-zero', () => {
  const dir = tmp();
  try {
    writeFakeChain(dir, 3);
    const r = runCli(
      ['audit', 'verify-length', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, `removed attestation evidence must never read as "chain intact": ${JSON.stringify(env)}`);
    assert.equal(env.code, 'NO_LENGTH_ATTESTATIONS', `expected NO_LENGTH_ATTESTATIONS, got ${env.code}`);
    assert.notEqual(r.code, 0, 'exit 0 with deleted attestations violates fail-closed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 7b: forged unsigned attestation → ok:false ATTESTATION_SIGNATURE_INVALID (never truncated=true from forged evidence)', () => {
  const dir = tmp();
  try {
    writeFakeChain(dir, 3);
    const { publicPem } = ed25519Pems();
    const attDir = join(dir, 'audit', 'length-attestations');
    mkdirSync(attDir, { recursive: true });
    // Forged: schemaVersion 1, matching chainId, absurd length, no valid signature.
    writeFileSync(
      join(attDir, `${CHAIN_ID}-1751400000000.json`),
      JSON.stringify({ schemaVersion: 1, chainId: CHAIN_ID, length: 9999999, headHash: 'f'.repeat(64), attestedAt: new Date().toISOString(), signature: 'Zm9yZ2Vk' }),
    );
    const r = runCli(
      ['audit', 'verify-length', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID, CHARIOT_AUDIT_VERIFY_KEY: publicPem } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, `forged attestation must be rejected: ${JSON.stringify(env)}`);
    assert.equal(env.code, 'ATTESTATION_SIGNATURE_INVALID', `expected ATTESTATION_SIGNATURE_INVALID, got ${env.code}`);
    assert.notEqual(r.code, 0, 'forged attestation must exit non-zero');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 7c: attestations present but no verify key configured → ok:false, never silently skips verification', () => {
  const dir = tmp();
  try {
    writeFakeChain(dir, 3);
    const attDir = join(dir, 'audit', 'length-attestations');
    mkdirSync(attDir, { recursive: true });
    writeFileSync(
      join(attDir, `${CHAIN_ID}-1751400000001.json`),
      JSON.stringify({ schemaVersion: 1, chainId: CHAIN_ID, length: 3, headHash: '3'.padStart(64, '0'), attestedAt: new Date().toISOString(), signature: 'Zm9yZ2Vk' }),
    );
    const r = runCli(
      ['audit', 'verify-length', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID, CHARIOT_AUDIT_VERIFY_KEY: '', CHARIOT_AUDIT_SIGNING_KEY: '' } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, `missing verify key must fail closed: ${JSON.stringify(env)}`);
    assert.equal(env.code, 'AUDIT_VERIFY_KEY_NOT_CONFIGURED', `expected AUDIT_VERIFY_KEY_NOT_CONFIGURED, got ${env.code}`);
    assert.notEqual(r.code, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 7d: genuinely truncated chain with a VALID signed attestation → CHAIN_TRUNCATION_DETECTED', () => {
  const dir = tmp();
  try {
    // Boot 1: 3-record chain, real `audit attest` signs length=3.
    writeFakeChain(dir, 3);
    const { privatePem, publicPem } = ed25519Pems();
    provisionSealedStoreKey(dir, privatePem);
    const attest = runCli(
      ['audit', 'attest', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID } },
    );
    assert.equal(parseEnvelope(attest.stdout).ok, true, `attest must succeed: ${attest.stdout} ${attest.stderr}`);
    // Attack: truncate the chain to 1 record.
    writeFakeChain(dir, 1);
    const r = runCli(
      ['audit', 'verify-length', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID, CHARIOT_AUDIT_VERIFY_KEY: publicPem } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, `truncation must be detected: ${JSON.stringify(env)}`);
    assert.equal(env.code, 'CHAIN_TRUNCATION_DETECTED', `expected CHAIN_TRUNCATION_DETECTED, got ${env.code}`);
    assert.notEqual(r.code, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 7e: per-record field rewrite + zeroed hash (line count preserved) with a VALID signed attestation → CHAIN_INTEGRITY_VIOLATION', () => {
  // The core attack the 7a–7d harness does NOT cover: an attacker with
  // write access rewrites a record's fields and zeroes its hash while keeping
  // the line count and the head record intact, so the length attestation still
  // matches — every truncation/signature check passes and the chain used to
  // read as "intact" / exit 0. Only the per-record hash-chain integrity check
  // The head-hash binding catches it. This locks that fix so it can't silently regress.
  const dir = tmp();
  try {
    // Boot 1: a genuinely valid 3-record chain; real `audit attest` signs length=3 + head hash.
    const records = writeValidChain(dir, 3);
    const { privatePem, publicPem } = ed25519Pems();
    provisionSealedStoreKey(dir, privatePem);
    const attest = runCli(
      ['audit', 'attest', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID } },
    );
    assert.equal(parseEnvelope(attest.stdout).ok, true, `attest must succeed: ${attest.stdout} ${attest.stderr}`);

    // Attack: rewrite an INTERIOR record's fields AND zero its hash. Line count
    // stays 3 and the head record (seq 3) is untouched, so the signed length
    // attestation still matches → truncation + signature checks all pass.
    records[1].output = { ok: false, exfiltrated: true };
    records[1].status = 'failed';
    records[1].hash = '0'.repeat(64);
    writeFileSync(
      join(dir, 'audit', `${CHAIN_ID}.jsonl`),
      records.map((r) => JSON.stringify(r)).join('\n') + '\n',
    );

    const r = runCli(
      ['audit', 'verify-length', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID, CHARIOT_AUDIT_VERIFY_KEY: publicPem } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, `per-record tamper must be detected, never read as intact: ${JSON.stringify(env)}`);
    assert.equal(env.code, 'CHAIN_INTEGRITY_VIOLATION', `expected CHAIN_INTEGRITY_VIOLATION, got ${env.code}`);
    assert.notEqual(r.code, 0, 'per-record tamper must exit non-zero');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 7f: interior tamper + chain RECOMPUTED FORWARD (verifyChain passes) with a VALID signed attestation → CHAIN_INTEGRITY_VIOLATION via head-hash binding', () => {
  // The gate-HIGH gap 7e does NOT reach: a sophisticated attacker does not
  // zero the hash (7e, caught by verifyChain) — they mutate an interior record
  // AND recompute the chain forward, re-hashing the mutated record, relinking
  // and re-hashing every record after it up to the head. The result is a chain
  // that HashChain.verifyChain accepts as fully valid, at the SAME length
  // (truncation clean, signatures clean, per-record integrity clean). Under the
  // pre-fix handler this read as "Chain intact" / exit 0 — the exact bypass.
  // What the attacker cannot forge is the Ed25519-SIGNED head: `audit attest`
  // signed the PRE-tamper head hash, and recomputing forward changes the head.
  // The head-hash binding compares the attested headHash to the live
  // chain head at the attested length and fails closed. This locks that fix.
  const dir = tmp();
  try {
    // Boot 1: genuinely valid 3-record chain; real attest signs length=3 + head.
    const records = writeValidChain(dir, 3);
    const { privatePem, publicPem } = ed25519Pems();
    provisionSealedStoreKey(dir, privatePem);
    const attest = runCli(
      ['audit', 'attest', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID } },
    );
    assert.equal(parseEnvelope(attest.stdout).ok, true, `attest must succeed: ${attest.stdout} ${attest.stderr}`);

    // Attack: mutate interior record 2 (index 1), then RECOMPUTE FORWARD so the
    // chain stays internally consistent — verifyChain will report valid:true.
    records[1].output = { ok: false, exfiltrated: true };
    records[1].status = 'failed';
    for (let i = 1; i < records.length; i++) {
      records[i].previousHash = records[i - 1].hash;
      records[i].hash = HashChain.computeHash(
        records[i] as unknown as Parameters<typeof HashChain.computeHash>[0],
      );
    }
    writeFileSync(
      join(dir, 'audit', `${CHAIN_ID}.jsonl`),
      records.map((r) => JSON.stringify(r)).join('\n') + '\n',
    );

    const r = runCli(
      ['audit', 'verify-length', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID, CHARIOT_AUDIT_VERIFY_KEY: publicPem } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, `recompute-forward tamper must be detected, never read as intact: ${JSON.stringify(env)}`);
    assert.equal(env.code, 'CHAIN_INTEGRITY_VIOLATION', `expected CHAIN_INTEGRITY_VIOLATION from head-hash binding, got ${env.code}`);
    assert.notEqual(r.code, 0, 'recompute-forward tamper must exit non-zero');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Attack 7g: attestation-DOWNGRADE — delete the newest (longer) attestation, then tamper+recompute the now-un-attested suffix → CHAIN_UNATTESTED_SUFFIX (never exit 0)', () => {
  // gate-HIGH downgrade the per-attestation head binding (7f) alone did NOT
  // cover: the attacker cannot forge a signature, so instead DELETES the newest
  // (length-3) attestation from the append-only dir, downgrading the verifier to
  // the surviving length-1 attestation, then rewrites records 2-3 and recomputes
  // the chain forward. The length-1 prefix still binds cleanly and detectTruncation
  // is clean (current 3 >= surviving max 1), so the tampered records sit in the
  // now-"un-attested growth window" (§9.8.3) and used to pass. The
  // fully-attestation-covered invariant (length === lastAttestedLength) closes it:
  // a suffix beyond the highest surviving attestation is never certified intact.
  const dir = tmp();
  try {
    const { privatePem, publicPem } = ed25519Pems();
    // Sealed once — both attest calls below reuse the SAME sealed key
    // (re-sealing under the same kid would collide on the append-only
    // sealed-artifact filename).
    provisionSealedStoreKey(dir, privatePem);
    const attestEnv = { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID };
    // Boot 1: attest at length 1.
    writeValidChain(dir, 1);
    assert.equal(parseEnvelope(runCli(['audit', 'attest', '--json'], { env: attestEnv }).stdout).ok, true, 'attest@1 must succeed');
    // Boot 2: grow to length 3 (record 1 is byte-identical — writeValidChain is
    // deterministic), attest at length 3. Two attestations now exist (1 and 3).
    const records = writeValidChain(dir, 3);
    assert.equal(parseEnvelope(runCli(['audit', 'attest', '--json'], { env: attestEnv }).stdout).ok, true, 'attest@3 must succeed');
    // Attack step 1: delete the length-3 attestation → downgrade to length-1.
    const attDir = join(dir, 'audit', 'length-attestations');
    for (const name of readdirSync(attDir)) {
      const att = JSON.parse(readFileSync(join(attDir, name), 'utf-8'));
      if (att.length === 3) rmSync(join(attDir, name));
    }
    // Attack step 2: tamper records 2-3 and recompute forward (verifyChain passes).
    records[1].output = { ok: false, exfiltrated: true };
    records[1].status = 'failed';
    for (let i = 1; i < records.length; i++) {
      records[i].previousHash = records[i - 1].hash;
      records[i].hash = HashChain.computeHash(
        records[i] as unknown as Parameters<typeof HashChain.computeHash>[0],
      );
    }
    writeFileSync(
      join(dir, 'audit', `${CHAIN_ID}.jsonl`),
      records.map((r) => JSON.stringify(r)).join('\n') + '\n',
    );

    const r = runCli(
      ['audit', 'verify-length', '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID, CHARIOT_AUDIT_VERIFY_KEY: publicPem } },
    );
    const env = parseEnvelope(r.stdout);
    assert.equal(env.ok, false, `downgrade + suffix tamper must be detected, never intact: ${JSON.stringify(env)}`);
    assert.equal(env.code, 'CHAIN_UNATTESTED_SUFFIX', `expected CHAIN_UNATTESTED_SUFFIX, got ${env.code}`);
    assert.notEqual(r.code, 0, 'downgrade attack must exit non-zero');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── ATTACK 8: unknown command + flag-first dispatch (CH-31/CH-32) ───────────

test('Attack 8a: chariot bogus --json → single parseable ok:false envelope on stdout, exit non-zero', () => {
  const r = runCli(['bogus-command-xyz', '--json']);
  const lines = r.stdout.trim().split('\n').filter(Boolean);
  assert.equal(lines.length, 1, `agent-mode stdout must be exactly one JSON line, got ${lines.length}: ${r.stdout}`);
  const env = JSON.parse(lines[0]) as Record<string, unknown>;
  assert.equal(env.ok, false, 'unknown command must be ok:false');
  assert.equal(env.code, 'USAGE_ERROR', `expected USAGE_ERROR, got ${env.code}`);
  assert.notEqual(r.code, 0, 'unknown command must exit non-zero');
  assert.equal(r.code, env.exit_code as number, `process exit (${r.code}) must equal envelope exit_code (${env.exit_code})`);
});

test('Attack 8b: chariot --json list (global flag BEFORE command) → dispatches list, ok:true', () => {
  const r = runCli(['--json', 'list']);
  assert.equal(r.code, 0, `--json before the command must still dispatch it. stderr: ${r.stderr}`);
  const env = parseEnvelope(r.stdout);
  assert.equal(env.ok, true, `expected ok:true from list, got ${JSON.stringify(env)}`);
  const data = env.data as Record<string, unknown>;
  assert.ok(Array.isArray(data.curated), 'data.curated must be an array — proves list actually ran');
});

// ── ATTACK 9: discover --json stdout purity (CH-32) ─────────────────────────

test('Attack 9: chariot discover --path <emptydir> --json → stdout is exactly one JSON envelope line', () => {
  const dir = tmp();
  const scanDir = tmp();
  try {
    const r = runCli(
      ['discover', '--path', scanDir, '--json'],
      { env: { EPIC_AI_DIR_OVERRIDE: dir } },
    );
    const lines = r.stdout.trim().split('\n').filter(Boolean);
    assert.equal(lines.length, 1, `discover --json stdout must be exactly one line (no banner/tables), got ${lines.length}: ${r.stdout}`);
    const env = JSON.parse(lines[0]) as Record<string, unknown>;
    assert.equal(env.ok, true, `empty scan dir → ok:true with services:0, got ${JSON.stringify(env)}`);
    assert.equal(env.surface, 'cli:discover');
    const data = env.data as Record<string, unknown>;
    assert.equal(data.services, 0, 'data.services must be 0 for an empty directory');
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(scanDir, { recursive: true, force: true });
  }
});
