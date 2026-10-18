/**
 * @epicai/chariot — Hash-chain tamper detection adversarial eval (aa3570e hardening)
 *
 * Proves that status, output, and durationMs are ALL included in the SHA-256
 * hash on the serve-sink path so any post-hoc edit to those fields is detected
 * by HashChain.verifyChain. Before aa3570e the computeHash path omitted these
 * fields on the JSONLAdapter, leaving tampered serve-path records undetected.
 *
 * Attack vectors:
 *   1. Flip status  completed→failed on a real JSONL record → verifyChain FAILS
 *   2. Alter output.isError on a real JSONL record          → verifyChain FAILS
 *   3. Alter durationMs on a real JSONL record              → verifyChain FAILS
 *   4. Untampered 3-record chain (control)                  → verifyChain PASSES
 *
 * Run after `tsc`: node --test dist/engine/audit/hash-chain-tamper.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditTrail } from './AuditTrail.js';
import { HashChain } from './HashChain.js';
import type { ActionRecord } from '../types/index.js';

// Minimal valid partial record (excludes id/sequenceNumber/previousHash/hash)
const RECORD_BASE: Omit<ActionRecord, 'id' | 'sequenceNumber' | 'previousHash' | 'hash'> = {
  timestamp: new Date('2026-01-01T00:00:00.000Z'),
  action: 'chariot_call',
  tool: 'search',
  server: 'test-adapter',
  tier: 'auto',
  status: 'completed',
  input: { argKeys: ['query'] },
  output: { isError: false, contentBytes: 42 },
  persona: 'tenant-001',
  durationMs: 123,
};

/**
 * Build a real 3-record JSONL hash chain in a temp dir.
 * Returns the path and the parsed records.
 */
async function buildChain(dir: string): Promise<{ chainFile: string }> {
  const chainFile = join(dir, 'chain.jsonl');
  const trail = new AuditTrail({
    store: 'append-only-log',
    path: chainFile,
    integrity: 'sha256-chain',
  });
  await trail.init();
  for (let i = 0; i < 3; i++) {
    await trail.record({ ...RECORD_BASE, tool: `tool_${i}`, durationMs: 100 + i });
  }
  return { chainFile };
}

/** Read and parse all records from the JSONL file. */
function readChain(chainFile: string): ActionRecord[] {
  return readFileSync(chainFile, 'utf-8')
    .trim()
    .split('\n')
    .map((l) => {
      const r = JSON.parse(l) as ActionRecord;
      r.timestamp = new Date(String(r.timestamp));
      return r;
    });
}

/** Rewrite the JSONL with one record mutated at the given index (by sequenceNumber). */
function tamperFile(
  chainFile: string,
  seqNum: number,
  mutate: (r: Record<string, unknown>) => void,
): void {
  const records = readFileSync(chainFile, 'utf-8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as Record<string, unknown>);
  const idx = records.findIndex((r) => r['sequenceNumber'] === seqNum);
  if (idx === -1) throw new Error(`Record with sequenceNumber=${seqNum} not found`);
  mutate(records[idx]);
  writeFileSync(
    chainFile,
    records.map((r) => JSON.stringify(r)).join('\n') + '\n',
    'utf-8',
  );
}

// ── Control: untampered chain passes ─────────────────────────────────────────

test('untampered 3-record JSONL chain verifies OK', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-tamper-'));
  try {
    const { chainFile } = await buildChain(dir);
    const records = readChain(chainFile);
    const result = HashChain.verifyChain(records);
    assert.equal(result.valid, true, `expected valid chain; brokenAt=${result.brokenAt}`);
    assert.equal(result.chainLength, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Attack 1: status field tamper ─────────────────────────────────────────────

test('tamper status completed→failed on record[1] causes verifyChain to fail', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-tamper-'));
  try {
    const { chainFile } = await buildChain(dir);
    tamperFile(chainFile, 1, (r) => {
      r['status'] = 'failed'; // flip: completed → failed
    });
    const records = readChain(chainFile);
    const result = HashChain.verifyChain(records);
    assert.equal(result.valid, false, 'expected chain to be invalid after status tamper');
    assert.equal(result.brokenAt, 1, 'break must be at the tampered record (sequenceNumber=1)');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Attack 2: output field tamper ─────────────────────────────────────────────

test('tamper output.isError on record[0] causes verifyChain to fail', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-tamper-'));
  try {
    const { chainFile } = await buildChain(dir);
    tamperFile(chainFile, 0, (r) => {
      const out = r['output'] as Record<string, unknown>;
      out['isError'] = true; // flip: false → true
    });
    const records = readChain(chainFile);
    const result = HashChain.verifyChain(records);
    assert.equal(result.valid, false, 'expected chain to be invalid after output tamper');
    assert.equal(result.brokenAt, 0, 'break must be at the tampered record (sequenceNumber=0)');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Attack 3: durationMs field tamper ────────────────────────────────────────

test('tamper durationMs on record[2] causes verifyChain to fail', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-tamper-'));
  try {
    const { chainFile } = await buildChain(dir);
    tamperFile(chainFile, 2, (r) => {
      r['durationMs'] = 99999; // alter timing data
    });
    const records = readChain(chainFile);
    const result = HashChain.verifyChain(records);
    assert.equal(result.valid, false, 'expected chain to be invalid after durationMs tamper');
    assert.equal(result.brokenAt, 2, 'break must be at the tampered record (sequenceNumber=2)');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
