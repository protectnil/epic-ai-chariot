/**
 * Regression eval: BM25 stopword set includes MCP-specific noise tokens (§4.2).
 *
 * The defect this exists to catch: STOPWORDS held only English stopwords;
 * `tool`, `call`, `get`, `list`, `mcp` — tokens that appear in nearly every
 * MCP tool description/name and therefore carry no discriminative BM25
 * signal — were NOT filtered, inflating their IDF weight on almost every
 * query. This test tokenizes a string containing exactly those five words
 * and asserts none survive; it would FAIL against the pre-fix STOPWORDS set
 * (all five would be returned as tokens).
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/ToolPreFilter.stopwords.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { tokenize } from './ToolPreFilter.js';

test('tokenize strips the MCP-specific noise tokens', () => {
  const tokens = tokenize('please call the tool to get the list from mcp');
  for (const noise of ['tool', 'call', 'get', 'list', 'mcp']) {
    assert.ok(!tokens.includes(noise), `expected "${noise}" to be filtered as a stopword`);
  }
});

test('tokenize still preserves real semantic content', () => {
  const tokens = tokenize('create a stripe invoice for the customer');
  assert.ok(tokens.includes('stripe'));
  assert.ok(tokens.includes('invoice'));
  assert.ok(tokens.includes('customer'));
});
