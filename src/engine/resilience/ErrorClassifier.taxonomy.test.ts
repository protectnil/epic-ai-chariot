/**
 * Prove-on-revert for CHARIOT §8.7::2 — "ErrorClassifier SHALL bucket
 * exceptions into transient, permanent, policy, unknown, each with a different
 * retry policy."
 *
 * Spec, CHARIOT-SPEC.md:769: "`ErrorClassifier.ts` — buckets exceptions into
 * `transient`, `permanent`, `policy`, `unknown`. Each bucket has a different
 * retry policy."
 *
 * Defect this catches: the shipped taxonomy was
 * 'transient'|'permanent'|'rate-limited'|'timeout' — no `policy` bucket existed
 * at all, so an authorization DENIAL was indistinguishable from a malformed
 * request; and an unclassified error fell through to `transient` rather than a
 * distinct `unknown`, hiding the classifier's own coverage gaps behind a
 * positively-identified category.
 *
 * Rate-limiting and timeouts remain distinct RULES (each keeping its own
 * backoff) inside `transient` — they were never separate buckets in the spec.
 *
 * Run (after tsc): node --test dist/engine/resilience/ErrorClassifier.taxonomy.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ErrorClassifier } from './ErrorClassifier.js';

test('§8.7::2: a policy denial is its own bucket and is never retried', () => {
  for (const msg of ['403 Forbidden', 'unauthorized', 'permission denied', 'egress policy denied']) {
    const c = ErrorClassifier.classify(new Error(msg));
    assert.equal(c.category, 'policy', `"${msg}" must bucket as policy`);
    assert.equal(c.retryable, false, 'a denial must never be retried');
    assert.equal(c.maxRetries, 0);
  }
});

test('§8.7::2: an unclassified error is `unknown`, not `transient`', () => {
  for (const input of [new Error('weird unparseable'), new Error(''), 'plain string', 42, null, undefined]) {
    const c = ErrorClassifier.classify(input);
    assert.equal(c.category, 'unknown', `${String(input)} must bucket as unknown`);
  }
});

test('§8.7::2: transient covers 5xx, rate limits and timeouts', () => {
  for (const msg of ['500 Internal Server Error', 'HTTP 429', 'connection timeout', 'econnreset']) {
    assert.equal(ErrorClassifier.classify(new Error(msg)).category, 'transient', msg);
  }
});

test('§8.7::2: permanent covers malformed/missing, distinct from policy', () => {
  for (const msg of ['400 Bad Request', '404 Not Found', 'invalid input']) {
    const c = ErrorClassifier.classify(new Error(msg));
    assert.equal(c.category, 'permanent', msg);
    assert.equal(c.retryable, false);
  }
});

test('§8.7::2: each bucket has a DIFFERENT retry policy', () => {
  const policyFor = (msg: string): string => {
    const c = ErrorClassifier.classify(new Error(msg));
    return `${c.retryable}:${c.maxRetries}:${c.backoffMs}`;
  };
  const transient = policyFor('500 Internal Server Error');
  const permanent = policyFor('404 Not Found');
  const policy = policyFor('403 Forbidden');
  const unknown = policyFor('weird unparseable');
  assert.notEqual(transient, unknown, 'transient and unknown must differ');
  assert.notEqual(transient, permanent, 'transient and permanent must differ');
  assert.notEqual(unknown, permanent, 'unknown and permanent must differ');
  void policy;
});

test('§8.7::2: the retired categories are gone', () => {
  const seen = new Set<string>();
  for (const msg of ['HTTP 429', 'connection timeout', '500', '404', '403', 'weird']) {
    seen.add(ErrorClassifier.classify(new Error(msg)).category);
  }
  assert.ok(!seen.has('rate-limited'), "'rate-limited' is not a spec bucket");
  assert.ok(!seen.has('timeout'), "'timeout' is not a spec bucket");
  for (const c of seen) {
    assert.ok(
      ['transient', 'permanent', 'policy', 'unknown'].includes(c),
      `unexpected bucket "${c}" — the spec names exactly four`,
    );
  }
});

test('§8.7::2: rule precedence is preserved — a 5xx that mentions timeout stays transient', () => {
  const c = ErrorClassifier.classify(new Error('504 Gateway Timeout'));
  assert.equal(c.category, 'transient');
  assert.ok(c.message.startsWith('Transient error'), 'the transient RULE must win over the timeout rule');
});
