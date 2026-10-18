/**
 * @epicai/chariot — Append-failure no-corruption adversarial eval
 *
 * Proves that when JSONLAdapter.append() fails due to a read-only storage path
 * (simulated via chmod 000 on the JSONL file), the AuditTrail does NOT advance
 * its internal sequenceNumber or lastHash. A subsequent record() call after the
 * path is restored succeeds with the correct sequence number and produces a
 * clean, fully-verifiable hash chain — no gap, no stale-hash link.
 *
 * The dangerous failure mode this guards against: if the trail advanced state
 * on a failed write, the next successful record would reference a
 * sequenceNumber/previousHash that is absent from the persisted chain, breaking
 * HashChain.verifyChain and making the chain unusable for auditing.
 *
 * Run after `tsc`: node --test dist/engine/audit/append-failure-no-corruption.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditTrail } from './AuditTrail.js';
import { JSONLAdapter } from './adapters/JSONLAdapter.js';
import type { ActionRecord } from '../types/index.js';

const RECORD_PARTIAL: Omit<ActionRecord, 'id' | 'sequenceNumber' | 'previousHash' | 'hash'> = {
  timestamp: new Date('2026-01-01T00:00:00.000Z'),
  action: 'chariot_call',
  tool: 'probe',
  server: 'adapter-a',
  tier: 'auto',
  status: 'completed',
  input: { argKeys: [] },
  output: { isError: false },
  persona: 'tenant-x',
  durationMs: 55,
};

test('EROFS simulation: sequenceNumber and lastHash do NOT advance on write failure', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'chariot-erofs-'));
  const chainFile = join(tmpDir, 'chain.jsonl');

  // Build the trail and write first record (seq 0)
  const trail = new AuditTrail({
    store: 'append-only-log',
    path: chainFile,
    integrity: 'sha256-chain',
  });
  await trail.init();

  const rec0 = await trail.record({ ...RECORD_PARTIAL, tool: 'first' });
  assert.equal(rec0.sequenceNumber, 0, 'first record should have sequenceNumber 0');

  // Make the JSONL file read-only so the next append fails
  chmodSync(chainFile, 0o444);

  // record() should reject — the adapter cannot write
  let appendFailed = false;
  try {
    await trail.record({ ...RECORD_PARTIAL, tool: 'blocked' });
  } catch {
    appendFailed = true;
  }
  assert.ok(appendFailed, 'expected record() to throw when JSONL path is read-only');

  // Restore write permission
  chmodSync(chainFile, 0o644);

  // The next record() must use sequenceNumber=1 and previousHash=rec0.hash
  // (NOT sequenceNumber=2 or previousHash from the failed attempt)
  const rec1 = await trail.record({ ...RECORD_PARTIAL, tool: 'recovery' });
  assert.equal(rec1.sequenceNumber, 1, 'recovery record must have sequenceNumber 1 (no gap)');
  assert.equal(rec1.previousHash, rec0.hash, 'recovery record must link to rec0.hash (no stale link)');

  // Full chain verify: should be clean (2 records, no gap, intact links)
  const adapter = new JSONLAdapter(chainFile);
  const verification = await adapter.verify();
  assert.equal(verification.valid, true, `chain must verify OK after recovery; brokenAt=${verification.brokenAt}`);
  assert.equal(verification.chainLength, 2, 'chain must have exactly 2 records (the blocked one was never written)');

  rmSync(tmpDir, { recursive: true, force: true });
});

test('write failure does not permanently silence subsequent record() calls', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'chariot-erofs-'));
  const chainFile = join(tmpDir, 'chain.jsonl');

  const trail = new AuditTrail({
    store: 'append-only-log',
    path: chainFile,
    integrity: 'sha256-chain',
  });
  await trail.init();

  // Write initial record to create the file
  const r0 = await trail.record({ ...RECORD_PARTIAL, tool: 'initial' });
  assert.equal(r0.sequenceNumber, 0);

  // Make the JSONL file itself read-only so appendFile fails with EACCES
  chmodSync(chainFile, 0o444);

  // Second write must fail — appendFile is blocked
  let failed1 = false;
  try {
    await trail.record({ ...RECORD_PARTIAL, tool: 'fail1' });
  } catch { failed1 = true; }
  assert.ok(failed1, 'expected failure when JSONL file is read-only');

  // Third write must ALSO fail — error must not be swallowed silently
  let failed2 = false;
  try {
    await trail.record({ ...RECORD_PARTIAL, tool: 'fail2' });
  } catch { failed2 = true; }
  assert.ok(failed2, 'second failure: storage error must remain visible to caller, not silently no-op');

  // Restore write permission
  chmodSync(chainFile, 0o644);

  // After restore, record must succeed
  const recAfter = await trail.record({ ...RECORD_PARTIAL, tool: 'after' });
  assert.ok(
    recAfter.sequenceNumber >= 1,
    'post-restore record must have a non-zero sequenceNumber (queued state was preserved)',
  );
  assert.ok(recAfter.hash.length === 64, 'post-restore record must have a valid SHA-256 hash');

  rmSync(tmpDir, { recursive: true, force: true });
});

test('verifyChain on a chain written after recovered from write failure passes', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'chariot-erofs-'));
  const chainFile = join(tmpDir, 'chain.jsonl');

  const trail = new AuditTrail({
    store: 'append-only-log',
    path: chainFile,
    integrity: 'sha256-chain',
  });
  await trail.init();

  const r0 = await trail.record({ ...RECORD_PARTIAL, tool: 'r0' });

  // Cause a write failure
  chmodSync(chainFile, 0o444);
  try { await trail.record({ ...RECORD_PARTIAL, tool: 'lost' }); } catch { /* expected */ }
  chmodSync(chainFile, 0o644);

  // Write 2 more records cleanly
  const r1 = await trail.record({ ...RECORD_PARTIAL, tool: 'r1' });
  const r2 = await trail.record({ ...RECORD_PARTIAL, tool: 'r2' });

  // Chain: r0 → r1 → r2 (the "lost" record is absent — but the remaining chain is valid)
  const adapter = new JSONLAdapter(chainFile);
  const verification = await adapter.verify();
  assert.equal(verification.valid, true, `chain must verify OK; brokenAt=${verification.brokenAt}`);
  assert.equal(verification.chainLength, 3, 'exactly 3 records written (r0, r1, r2)');

  // Sequence continuity: r1.prev = r0.hash, r2.prev = r1.hash
  assert.equal(r1.previousHash, r0.hash);
  assert.equal(r2.previousHash, r1.hash);

  rmSync(tmpDir, { recursive: true, force: true });
});
