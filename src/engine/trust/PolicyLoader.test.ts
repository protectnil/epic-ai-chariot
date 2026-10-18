/**
 * Coverage for CHARIOT §8.9::10 — "PolicyLoader SHALL read policy rules from
 * JSON, validate against a Zod schema, and hand them to AccessPolicyEngine."
 *
 * (This file was lost in an unrelated revert; restored. It exercises the JSON
 * parse + Zod validation contract with no external dependencies — a broken
 * loader that skipped validation, or accepted a malformed rule, fails here.)
 *
 * Run (after tsc): node --test dist/engine/trust/PolicyLoader.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadPolicyFromFile, validatePolicyRules } from './PolicyLoader.js';

const validRule = {
  id: 'r1',
  effect: 'allow' as const,
  principal: { roles: ['admin'] },
  resource: { toolNames: ['search'] },
  priority: 1,
};

test('§8.9::10: validatePolicyRules accepts a well-formed rule', () => {
  const out = validatePolicyRules([validRule]);
  assert.equal(out.length, 1);
  assert.equal(out[0].id, 'r1');
  assert.equal(out[0].effect, 'allow');
});

test('§8.9::10: validatePolicyRules rejects a rule missing required fields', () => {
  assert.throws(() => validatePolicyRules([{ id: 'r1', effect: 'allow' }]), /validation failed/i);
});

test('§8.9::10: validatePolicyRules rejects an invalid effect enum', () => {
  assert.throws(() => validatePolicyRules([{ ...validRule, effect: 'maybe' }]), /validation failed/i);
});

test('§8.9::10: loadPolicyFromFile parses + validates a JSON policy file', async () => {
  const p = join(tmpdir(), `chariot-policy-${process.pid}-ok.json`);
  writeFileSync(p, JSON.stringify({ rules: [validRule] }));
  try {
    const rules = await loadPolicyFromFile(p);
    assert.equal(rules.length, 1);
    assert.equal(rules[0].effect, 'allow');
  } finally {
    rmSync(p, { force: true });
  }
});

test('§8.9::10: loadPolicyFromFile throws on non-JSON content (no silent accept)', async () => {
  const p = join(tmpdir(), `chariot-policy-${process.pid}-bad.json`);
  writeFileSync(p, 'not json {');
  try {
    await assert.rejects(() => loadPolicyFromFile(p), /not valid JSON/i);
  } finally {
    rmSync(p, { force: true });
  }
});

test('§8.9::10: loadPolicyFromFile throws when a rule violates the schema', async () => {
  const p = join(tmpdir(), `chariot-policy-${process.pid}-badrule.json`);
  writeFileSync(p, JSON.stringify({ rules: [{ id: 'r1', effect: 'allow' }] }));
  try {
    await assert.rejects(() => loadPolicyFromFile(p), /validation failed/i);
  } finally {
    rmSync(p, { force: true });
  }
});
