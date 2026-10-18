/**
 * @epicai/chariot — Test Harness Canonical Tool List Conformance
 * CHARIOT::§8.11::2 (CHARIOT-SPEC.md:824): "Each profile SHALL run eight
 * canonical tools (list, search, read, write-shadow, delete-shadow,
 * error-handling, auth-failure, rate-limit) ...". This asserts the harness's
 * registered tool set is exactly that list — no extra, no missing — for the
 * shared definition and for each of the three live backends.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CANONICAL_TOOL_NAMES, CANONICAL_TOOLS } from './toolDefs.js';
import { ApiHarnessBackend } from '../api/server.js';

// The exact tool list quoted from CHARIOT-SPEC.md:824.
const SPEC_TOOL_NAMES = [
  'list',
  'search',
  'read',
  'write-shadow',
  'delete-shadow',
  'error-handling',
  'auth-failure',
  'rate-limit',
];

test('CANONICAL_TOOL_NAMES equals the exact CHARIOT::§8.11::2 spec list (order-insensitive)', () => {
  assert.deepEqual([...CANONICAL_TOOL_NAMES].sort(), [...SPEC_TOOL_NAMES].sort());
  assert.equal(CANONICAL_TOOL_NAMES.length, 8, 'clause requires exactly eight tools');
});

test('CANONICAL_TOOLS tool-info names equal the exact CHARIOT::§8.11::2 spec list (order-insensitive)', () => {
  const names = CANONICAL_TOOLS.map(t => t.name).sort();
  assert.deepEqual(names, [...SPEC_TOOL_NAMES].sort());
});

test('CANONICAL_TOOL_NAMES rejects any extra or missing tool', () => {
  const asSet = new Set<string>(CANONICAL_TOOL_NAMES);
  for (const expected of SPEC_TOOL_NAMES) {
    assert.ok(asSet.has(expected), `missing required tool: ${expected}`);
  }
  for (const actual of CANONICAL_TOOL_NAMES) {
    assert.ok(SPEC_TOOL_NAMES.includes(actual), `unexpected extra tool not in spec: ${actual}`);
  }
});

test('api profile backend registers exactly the CHARIOT::§8.11::2 spec tool list', async () => {
  const backend = new ApiHarnessBackend();
  await backend.start();
  try {
    const tools = await backend.listTools();
    const names = tools.map(t => t.name).sort();
    assert.deepEqual(names, [...SPEC_TOOL_NAMES].sort());
  } finally {
    await backend.stop();
  }
});
