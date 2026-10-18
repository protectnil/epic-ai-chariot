/**
 * @epicai/chariot — CLI end-to-end eval: `verify-length` reads the
 * persistent verify-key store through `resolveVerifyKeys()` (CHARIOT::§9.8.1::3,
 * gate round-3 finding)
 *
 * Spawns the REAL built CLI (dist/bin/chariot.js) as a child process — same
 * harness pattern as src/cli/cli-honest-signal.test.ts and
 * audit-rotate-key.test.ts. Zero mocks.
 *
 * Prior finding: `chariot audit verify-length` built its candidate PEM set
 * from CHARIOT_AUDIT_VERIFY_KEY / CHARIOT_AUDIT_SIGNING_KEY /
 * CHARIOT_AUDIT_VERIFY_KEYS only, never consulting
 * `resolveVerifyKeys(<epicAiDir>)` — so a key `rotateSigningKey()`
 * published into `audit/verify-keys.json` was invisible to the CLI even
 * though the admin export route (src/iam/routes/admin.ts) read it
 * correctly. `verify-length` now sources its ENTIRE candidate set from
 * `resolveVerifyKeys(packageRoot)`.
 *
 * Failure classes:
 *   1. Rotate (sealed-store) once -> kid1. Attest while kid1 is current ->
 *      a length attestation signed under kid1, covering the chain as it
 *      stood at that point. Rotate AGAIN -> kid2 becomes current — this
 *      itself appends an `audit.signing_key.rotated` record to the live
 *      chain, so the chain is now LONGER than the kid1 attestation covers
 *      (an un-attested suffix, correctly refused by verify-length if left
 *      unaddressed). Attest AGAIN (now under kid2) to cover that suffix.
 *      `verify-length` — with NO CHARIOT_AUDIT_VERIFY_KEY /
 *      CHARIOT_AUDIT_SIGNING_KEY / CHARIOT_AUDIT_VERIFY_KEYS env vars set
 *      at all — must verify cleanly, and the two on-disk attestation
 *      records are independently confirmed (via `verifyLengthAttestation`
 *      called directly in this test, not just trusting the CLI's exit
 *      code) to be signed one under kid1 and the other under kid2 — both
 *      verifying from the persistent store alone, kid1 retired-but-retained.
 *   2. A forged/foreign attestation, signed under a kid NEVER published
 *      anywhere (not the store, not any env var), must fail closed
 *      (ATTESTATION_SIGNATURE_INVALID) — an unknown kid is never trusted.
 *   3. Unit (in-process, CLI seam): the `audit.signing_key.rotated` record
 *      `rotate-key` appends chains correctly onto a REAL prior chain — the
 *      SAME `HashChain.verifyChain()` function `verify-length`'s per-record
 *      integrity check calls returns `valid:true`, checked directly against
 *      the on-disk JSONL (not by re-spawning `verify-length` and reading its
 *      exit code) — pinning the hash-chain-integrity failure class
 *      independently of the full e2e round trip in test 1.
 *
 * 2026-09-04 fix: test 1 previously used `writeFakeChain()` — a fixture
 * with placeholder `hash` values (`i.toString(16).padStart(64,'0')`), NOT
 * the real `HashChain.computeHash()` of each record's own content. That
 * fixture was ALWAYS going to fail `verify-length`'s deep per-record
 * integrity check (HashChain.verifyChain, chariot.ts's `sub ===
 * 'verify-length'` handler) at sequenceNumber=1 — the very FIRST
 * (fake) record — with or without any rotation involved; the pre-existing
 * attack tests that reuse `writeFakeChain` (cli-honest-signal.test.ts
 * Attacks 7a-7d) never reach that deep check, because they're designed to
 * fail earlier (truncation / missing-attestation / bad-signature). Test 1
 * asserts `ok:true`, which DOES require passing the deep check, so it
 * needed the REAL fixture (`writeValidChain`, the same one Attacks 7e-7g
 * use) all along — this was a test-fixture bug, not a `rotate-key` product
 * defect. `AuditTrail._doRecord` (AuditTrail.ts:156) and `HashChain.verifyChain`
 * both call the SAME `HashChain.computeHash` (HashChain.ts:39) to
 * compute/recompute a record's hash, so a record appended via
 * `AuditTrail.record()` (which `rotateSigningKey()` uses, keyRotation.ts)
 * onto a chain whose LAST record's hash was itself computed the same way
 * is self-consistent and chains correctly — confirmed empirically by test 3
 * below, in-process, independent of the fixture bug in test 1.
 *
 * Build first: npm run build
 * Run:         node --test dist/bin/audit-verify-length-rotation.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyLengthAttestation, type LengthAttestation } from '../engine/audit/length-attestation.js';
import { HashChain } from '../engine/audit/HashChain.js';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(__dirname, 'chariot.js');
const CHAIN_ID = 'verify-rotation-e2e';

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
  return mkdtempSync(join(tmpdir(), 'chariot-verify-rotation-'));
}

function writeFakeChain(dir: string, n: number): void {
  mkdirSync(join(dir, 'audit'), { recursive: true });
  const lines: string[] = [];
  for (let i = 1; i <= n; i++) {
    lines.push(JSON.stringify({ sequenceNumber: i, hash: i.toString(16).padStart(64, '0') }));
  }
  writeFileSync(join(dir, 'audit', `${CHAIN_ID}.jsonl`), lines.join('\n') + '\n');
}

/**
 * Fabricate a GENUINELY VALID JSONL hash-chain — each record's `hash` is
 * the real SHA-256 over its canonicalized contents (via the production
 * `HashChain.computeHash`, the single source of truth) and each
 * `previousHash` links to the prior record's hash, so
 * `HashChain.verifyChain(records)` is `valid:true`. Same pattern as
 * src/cli/cli-honest-signal.test.ts's `writeValidChain` (Attacks 7e-7g),
 * duplicated here rather than imported since that file does not export it.
 * Required whenever a test needs `verify-length`'s deep per-record
 * integrity check to actually PASS — `writeFakeChain` above never can.
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
  writeFileSync(join(dir, 'audit', `${CHAIN_ID}.jsonl`), records.map((r) => JSON.stringify(r)).join('\n') + '\n');
  return records;
}

/** Read every JSONL line of a chain file back as parsed records — the
 * exact same read chariot.ts's `readChainRecords` does for verify-length,
 * duplicated here so this test can call `HashChain.verifyChain` directly
 * without spawning the CLI again. */
function readChainFile(path: string): Record<string, unknown>[] {
  return readFileSync(path, 'utf-8')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

const MASTER_KEY = Buffer.alloc(32, 0x51).toString('base64');

test('verify-length: attestations spanning a rotation (one signed under a RETIRED kid, one under current) both verify from the persistent store alone, no env vars', async () => {
  const dir = tmp();
  try {
    const baseEnv = { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID, ENTERPRISE_MASTER_KEY: MASTER_KEY };
    // A REAL hash-chain fixture — required because this test asserts
    // verify-length returns ok:true, which means passing its deep
    // per-record HashChain.verifyChain check (writeFakeChain's placeholder
    // hashes can never pass that check, rotation or not — see the module
    // doc comment's 2026-09-04 fix note).
    writeValidChain(dir, 3);

    // Rotation 1 -> kid1 becomes the current sealed-store key.
    const rot1 = parseEnvelope(runCli(['audit', 'rotate-key', '--backend', 'sealed-store', '--json'], baseEnv).stdout);
    assert.equal(rot1.ok, true, `first rotation must succeed: ${JSON.stringify(rot1)}`);
    const kid1 = (rot1.data as Record<string, unknown>).kid as string;
    const kid1PublicKeyPem = (rot1.data as Record<string, unknown>).publicKeyPem as string;

    // Attest WHILE kid1 is current — this attestation is signed under kid1
    // and covers the chain as it stands right now (length 3).
    const attest1 = runCli(['audit', 'attest', '--json'], baseEnv);
    const attest1Env = parseEnvelope(attest1.stdout);
    assert.equal(attest1Env.ok, true, `first attest must succeed: ${attest1.stdout} ${attest1.stderr}`);

    // Rotation 2 -> kid2 becomes current; kid1 is retired from "current"
    // but remains published in the persistent verify-key store. This
    // rotation itself APPENDS an `audit.signing_key.rotated` record to the
    // live chain, so the chain is now one record longer than the kid1
    // attestation covers.
    const rot2 = parseEnvelope(runCli(['audit', 'rotate-key', '--backend', 'sealed-store', '--json'], baseEnv).stdout);
    assert.equal(rot2.ok, true, `second rotation must succeed: ${JSON.stringify(rot2)}`);
    const kid2 = (rot2.data as Record<string, unknown>).kid as string;
    const kid2PublicKeyPem = (rot2.data as Record<string, unknown>).publicKeyPem as string;
    assert.equal((rot2.data as Record<string, unknown>).oldKid, kid1, "second rotation's oldKid must equal the first rotation's kid");

    // Attest AGAIN — now signed under kid2 — to cover the rotation
    // record's growth. This is the step the sequence was missing: without
    // it the chain has a genuine un-attested suffix and verify-length is
    // CORRECT to refuse (CHAIN_UNATTESTED_SUFFIX), not a product defect.
    const attest2 = runCli(['audit', 'attest', '--json'], baseEnv);
    const attest2Env = parseEnvelope(attest2.stdout);
    assert.equal(attest2Env.ok, true, `second attest must succeed: ${attest2.stdout} ${attest2.stderr}`);

    // Sanity: the store really does hold both kids, on disk.
    const store = JSON.parse(readFileSync(join(dir, 'audit', 'verify-keys.json'), 'utf-8')) as Record<string, unknown>;
    assert.ok(kid1 in store, 'kid1 must be in the persistent store before verify-length runs');
    assert.ok(kid2 in store, 'kid2 must be in the persistent store before verify-length runs');

    // Independently confirm (not just via the CLI's exit code) that ONE
    // on-disk attestation is signed under kid1 and the OTHER under kid2.
    // Sort by each attestation's own `attestedAt` field (not the filename)
    // — robust even if both attest calls landed in the same millisecond
    // and persistAttestation's collision suffix kicked in.
    const attDir = join(dir, 'audit', 'length-attestations');
    const attFiles = readdirSync(attDir);
    assert.equal(attFiles.length, 2, `expected exactly 2 attestation files, got: ${JSON.stringify(attFiles)}`);
    const attRecords = attFiles
      .map((f) => JSON.parse(readFileSync(join(attDir, f), 'utf-8')) as LengthAttestation)
      .sort((a, b) => Date.parse(a.attestedAt) - Date.parse(b.attestedAt) || a.length - b.length);
    const [firstAtt, secondAtt] = attRecords;
    assert.ok(firstAtt.length <= secondAtt.length, 'the earlier attestation must cover a length no greater than the later one');

    const firstUnderKid1 = await verifyLengthAttestation(firstAtt, kid1PublicKeyPem);
    assert.equal(firstUnderKid1.valid, true, `first attestation must verify under kid1: ${firstUnderKid1.error ?? ''}`);
    const firstUnderKid2 = await verifyLengthAttestation(firstAtt, kid2PublicKeyPem);
    assert.equal(firstUnderKid2.valid, false, 'first attestation must NOT verify under kid2 (it was signed under kid1)');

    const secondUnderKid2 = await verifyLengthAttestation(secondAtt, kid2PublicKeyPem);
    assert.equal(secondUnderKid2.valid, true, `second attestation must verify under kid2: ${secondUnderKid2.error ?? ''}`);
    const secondUnderKid1 = await verifyLengthAttestation(secondAtt, kid1PublicKeyPem);
    assert.equal(secondUnderKid1.valid, false, 'second attestation must NOT verify under kid1 (it was signed under kid2)');

    // verify-length with NO verify-key env vars set at all — the ONLY
    // source of truth available is the persistent store — must now
    // succeed: the kid1-signed attestation and the kid2-signed attestation
    // together fully cover the chain, with no un-attested suffix.
    const verify = runCli(['audit', 'verify-length', '--json'], {
      EPIC_AI_DIR_OVERRIDE: dir,
      CHARIOT_CHAIN_ID: CHAIN_ID,
    });
    const verifyEnv = parseEnvelope(verify.stdout);
    assert.equal(
      verifyEnv.ok,
      true,
      `verify-length must verify cleanly from the persistent store alone: ${JSON.stringify(verifyEnv)} stderr=${verify.stderr}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verify-length: an attestation signed under a kid NEVER published anywhere fails closed', () => {
  const dir = tmp();
  try {
    // Provision a real sealed-store key (so a fresh install with NOTHING
    // provisioned doesn't just hit the earlier "zero candidates" gate —
    // this must specifically prove an UNKNOWN kid fails, not merely "no
    // keys configured at all").
    const rot = parseEnvelope(
      runCli(['audit', 'rotate-key', '--backend', 'sealed-store', '--json'], {
        EPIC_AI_DIR_OVERRIDE: dir,
        ENTERPRISE_MASTER_KEY: MASTER_KEY,
      }).stdout,
    );
    assert.equal(rot.ok, true);

    writeFakeChain(dir, 3);
    const attDir = join(dir, 'audit', 'length-attestations');
    mkdirSync(attDir, { recursive: true });

    // Forge an attestation signed under a THROWAWAY key that was never
    // published to the store, any env var, or anywhere else.
    const { privateKey } = generateKeyPairSync('ed25519');
    const payload = {
      schemaVersion: 1,
      chainId: CHAIN_ID,
      length: 3,
      headHash: '3'.padStart(64, '0'),
      attestedAt: new Date().toISOString(),
    };
    const canonical = JSON.stringify(payload);
    const signature = edSign(null, Buffer.from(canonical, 'utf-8'), privateKey).toString('base64url');
    writeFileSync(
      join(attDir, `${CHAIN_ID}-1751400000002.json`),
      JSON.stringify({ ...payload, signature }),
    );

    const verify = runCli(['audit', 'verify-length', '--json'], {
      EPIC_AI_DIR_OVERRIDE: dir,
      CHARIOT_CHAIN_ID: CHAIN_ID,
    });
    const verifyEnv = parseEnvelope(verify.stdout);
    assert.equal(verifyEnv.ok, false, `an attestation signed under an unpublished kid must fail closed: ${JSON.stringify(verifyEnv)}`);
    assert.equal(verifyEnv.code, 'ATTESTATION_SIGNATURE_INVALID', `expected ATTESTATION_SIGNATURE_INVALID, got ${verifyEnv.code}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('unit (in-process, CLI seam): rotate-key + attest, spanning a rotation, appends chain records that pass HashChain.verifyChain directly', () => {
  const dir = tmp();
  try {
    const baseEnv = { EPIC_AI_DIR_OVERRIDE: dir, CHARIOT_CHAIN_ID: CHAIN_ID, ENTERPRISE_MASTER_KEY: MASTER_KEY };
    writeValidChain(dir, 3);

    const rot1 = parseEnvelope(runCli(['audit', 'rotate-key', '--backend', 'sealed-store', '--json'], baseEnv).stdout);
    assert.equal(rot1.ok, true, `first rotation must succeed: ${JSON.stringify(rot1)}`);

    const attest1 = parseEnvelope(runCli(['audit', 'attest', '--json'], baseEnv).stdout);
    assert.equal(attest1.ok, true, `first attest must succeed: ${JSON.stringify(attest1)}`);

    // The second rotation is the exact seam under scrutiny: it appends an
    // `audit.signing_key.rotated` record (via keyRotation.ts's
    // `auditTrail.record()`) onto a chain a DIFFERENT process instance
    // (the first rotate-key's subprocess) already extended — a fresh
    // `AuditTrail` per CLI invocation, `.init()` re-reading sequenceNumber/
    // lastHash off disk each time (AuditTrail.ts:94-108), unlike
    // keyRotation.test.ts's in-process coverage which reuses one
    // AuditTrail instance across both rotations.
    const rot2 = parseEnvelope(runCli(['audit', 'rotate-key', '--backend', 'sealed-store', '--json'], baseEnv).stdout);
    assert.equal(rot2.ok, true, `second rotation must succeed: ${JSON.stringify(rot2)}`);

    const attest2 = parseEnvelope(runCli(['audit', 'attest', '--json'], baseEnv).stdout);
    assert.equal(attest2.ok, true, `second attest must succeed: ${JSON.stringify(attest2)}`);

    // Read the on-disk chain and call HashChain.verifyChain DIRECTLY — the
    // exact function chariot.ts's verify-length handler calls
    // (`const { HashChain } = await import('../engine/audit/HashChain.js'); ...
    // const integrity = HashChain.verifyChain(chainRecords);`) — without
    // re-spawning the CLI, so this pins the hash-chain-integrity failure
    // class independently of the full verify-length round trip.
    const chainFile = join(dir, 'audit', `${CHAIN_ID}.jsonl`);
    const chainRecords = readChainFile(chainFile);
    // 3 original + 2 rotation records = 5.
    assert.equal(chainRecords.length, 5, `expected 5 chain records (3 original + 2 rotations), got: ${chainRecords.length}`);
    const rotationRecords = chainRecords.filter((r) => r.action === 'audit.signing_key.rotated');
    assert.equal(rotationRecords.length, 2, 'both rotate-key invocations must have appended a chain record');

    const integrity = HashChain.verifyChain(chainRecords as unknown as Parameters<typeof HashChain.verifyChain>[0]);
    assert.equal(
      integrity.valid,
      true,
      `rotate-key's appended records must chain correctly onto the real prior chain: brokenAt=${integrity.brokenAt}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
