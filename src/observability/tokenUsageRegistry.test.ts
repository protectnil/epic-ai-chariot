/**
 * CHARIOT::§16.3::1 / gate finding 114(i) (thread 01a06d96-0132-71b2-92f4-a87dd7611393)
 * — "add a registration seam ... so any process that embeds the SDK feeds
 * the gateway metrics without a second wiring site."
 *
 * Unit-level coverage of the registry itself (registration, most-recent-
 * wins, clear). The full EpicAI -> registry -> ChariotMetrics integration
 * (a real dispatch producing real byAdapter numbers) is covered separately
 * in EpicAI.token-usage-registration.test.ts.
 *
 * Run (after tsc): node --test dist/observability/tokenUsageRegistry.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  registerTokenUsageSource,
  getRegisteredTokenUsageSource,
  clearRegisteredTokenUsageSource,
} from './tokenUsageRegistry.js';

test('gate finding 114(i): no registration -> null', () => {
  clearRegisteredTokenUsageSource();
  assert.equal(getRegisteredTokenUsageSource(), null);
});

test('gate finding 114(i): registering a source makes it retrievable', () => {
  clearRegisteredTokenUsageSource();
  const source = { getTokenUsageByAdapter: () => ({ github: { tokens: 100, costUsd: 0.01 } }) };
  registerTokenUsageSource(source);
  assert.equal(getRegisteredTokenUsageSource(), source);
});

test('gate finding 114(i): MOST RECENT registration wins (documented last-write-wins, not a merge)', () => {
  clearRegisteredTokenUsageSource();
  const first = { getTokenUsageByAdapter: () => ({ first: { tokens: 1, costUsd: 0 } }) };
  const second = { getTokenUsageByAdapter: () => ({ second: { tokens: 2, costUsd: 0 } }) };

  registerTokenUsageSource(first);
  assert.equal(getRegisteredTokenUsageSource(), first);

  registerTokenUsageSource(second);
  assert.equal(getRegisteredTokenUsageSource(), second, 'the second registration must REPLACE the first, not merge with it');
  assert.deepEqual(getRegisteredTokenUsageSource()?.getTokenUsageByAdapter(), { second: { tokens: 2, costUsd: 0 } });
});

test('gate finding 114(i): clearRegisteredTokenUsageSource() resets to null (test seam)', () => {
  registerTokenUsageSource({ getTokenUsageByAdapter: () => ({}) });
  assert.notEqual(getRegisteredTokenUsageSource(), null);
  clearRegisteredTokenUsageSource();
  assert.equal(getRegisteredTokenUsageSource(), null);
});
