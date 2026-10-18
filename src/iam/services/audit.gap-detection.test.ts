/**
 * Prove-on-revert for CHARIOT §3.5::21 (CH-15) — "Audit gap detection SHALL
 * compare the chain head against the iam_audit_counters document on every read
 * and SHALL raise an integrity alert on a gap."
 *
 * Spec, CHARIOT-SPEC.md line 258:
 *   | CH-15 | Audit gap detection compares the chain head against the
 *     `iam_audit_counters` document on every read. A gap raises an integrity
 *     alert. | `src/iam/services/audit.ts` |
 *
 * Defect this catches: query() — the actual read path — performed NO gap
 * detection at all, and verifyChain() only compared consecutive events INSIDE
 * its own fetched window, never consulting iam_audit_counters. Tail truncation
 * (deleting the last N events) therefore left a perfectly self-consistent chain
 * that both functions reported as intact.
 *
 * Behavioral coverage against a live Mongo lives in the infra-gated eval
 * harness; this asserts the contract by source inspection, without Mongo.
 *
 * Run (after tsc): node --test dist/iam/services/audit.gap-detection.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('./audit.js', import.meta.url)), 'utf8');

test('§3.5::21: query() performs head-vs-counter gap detection on every read', () => {
  const queryBody = src.slice(src.indexOf('async function query('));
  assert.ok(queryBody.length > 0, 'query() must exist');
  const firstReturn = queryBody.indexOf('return {');
  const body = queryBody.slice(0, firstReturn);
  assert.ok(
    /assertChainHeadMatchesCounter\s*\(/.test(body),
    'query() must run the head-vs-counter check before returning events',
  );
});

test('§3.5::21: the check compares the counter against the true chain head', () => {
  const fn = src.slice(src.indexOf('async function assertChainHeadMatchesCounter'));
  assert.ok(fn.length > 0, 'the gap-detection helper must exist');
  assert.ok(/ensureCounter\s*\(/.test(fn), 'must read the iam_audit_counters document');
  assert.ok(/sort:\s*\{\s*seq:\s*-1\s*\}/.test(fn), 'must select the maximum-seq event as the head');
  assert.ok(/counter\.lastHash/.test(fn), 'must compare the counter hash, not only the seq');
});

test('§3.5::21: a gap raises an integrity alert AND fails closed', () => {
  const fn = src.slice(src.indexOf('async function assertChainHeadMatchesCounter'));
  const upToThrow = fn.slice(0, fn.indexOf('throw new Error'));
  assert.ok(
    /chariotEmitter\.send\(\s*'system\.error'/.test(upToThrow),
    'a gap must emit a system.error integrity alert',
  );
  assert.ok(/alertWorthy:\s*true/.test(upToThrow), 'the alert must be alertWorthy');
  assert.ok(/severity:\s*'critical'/.test(upToThrow), 'the alert must be critical severity');
  assert.ok(/throw new Error/.test(fn), 'a gap must fail closed, never serve a tampered log');
});

test('§3.5::21: verifyChain also compares the head against the counter', () => {
  const fn = src.slice(src.indexOf('async function verifyChain'));
  assert.ok(
    /Counter\/head mismatch/.test(fn),
    'verifyChain must detect tail truncation via the counter, not only in-window gaps',
  );
  assert.ok(/ensureCounter\s*\(/.test(fn), 'verifyChain must read iam_audit_counters');
});
