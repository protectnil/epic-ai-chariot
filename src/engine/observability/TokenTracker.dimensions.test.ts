/**
 * CHARIOT::§8.12::5 — "TokenTracker.ts — token counting by adapter, by
 * tool, by tenant. Backs the per-tenant cost-attribution surface."
 *
 * Defect this catches: record()'s prior signature (provider, model, role,
 * usage) carried NO adapter/tool/tenant dimension at all, so summary()
 * could not answer "how many tokens did tenant X spend on adapter Y's
 * tool Z" — exactly what §8.12::5 and §16.3::1's "token usage by adapter"
 * group require.
 *
 * Run (after tsc):
 *   node --test dist/engine/observability/TokenTracker.dimensions.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { TokenTracker } from './TokenTracker.js';

test('§8.12::5: record() requires adapterId/toolName/tenantId and summary() groups by each', () => {
  const tracker = new TokenTracker();

  tracker.record({
    provider: 'anthropic', model: 'claude-sonnet-4-6', role: 'generator',
    usage: { inputTokens: 100, outputTokens: 50, totalTokens: 150 },
    adapterId: 'github', toolName: 'search_repos', tenantId: 'tenant-a',
  });
  tracker.record({
    provider: 'anthropic', model: 'claude-sonnet-4-6', role: 'generator',
    usage: { inputTokens: 200, outputTokens: 100, totalTokens: 300 },
    adapterId: 'github', toolName: 'read_file', tenantId: 'tenant-a',
  });
  tracker.record({
    provider: 'anthropic', model: 'claude-sonnet-4-6', role: 'orchestrator',
    usage: { inputTokens: 10, outputTokens: 5, totalTokens: 15 },
    adapterId: 'slack', toolName: 'post_message', tenantId: 'tenant-b',
  });

  const summary = tracker.summary();

  assert.equal(summary.byAdapter['github'].tokens, 450, 'github adapter total = 150 + 300');
  assert.equal(summary.byAdapter['slack'].tokens, 15, 'slack adapter total isolated from github');
  assert.equal(summary.byTool['search_repos'].tokens, 150);
  assert.equal(summary.byTool['read_file'].tokens, 300);
  assert.equal(summary.byTool['post_message'].tokens, 15);
  assert.equal(summary.byTenant['tenant-a'].tokens, 450, 'tenant-a = both github calls');
  assert.equal(summary.byTenant['tenant-b'].tokens, 15, 'tenant-b isolated from tenant-a — backs per-tenant cost attribution');
  assert.equal(summary.totalTokens, 465);

  // Every entry carries the three dimension fields for downstream audit.
  for (const entry of summary.entries) {
    assert.ok(typeof entry.adapterId === 'string' && entry.adapterId.length > 0);
    assert.ok(typeof entry.toolName === 'string' && entry.toolName.length > 0);
    assert.ok(typeof entry.tenantId === 'string' && entry.tenantId.length > 0);
  }
});

test('§8.12::5: byAdapter/byTool/byTenant cost totals accumulate correctly (not just token counts)', () => {
  const tracker = new TokenTracker({ 'test-model': { input: 1, output: 2 } });

  tracker.record({
    provider: 'test', model: 'test-model', role: 'generator',
    usage: { inputTokens: 1_000_000, outputTokens: 1_000_000, totalTokens: 2_000_000 },
    adapterId: 'adapter-x', toolName: 'tool-x', tenantId: 'tenant-x',
  });

  const summary = tracker.summary();
  // 1_000_000/1M * $1 + 1_000_000/1M * $2 = $3
  assert.equal(summary.byAdapter['adapter-x'].costUsd, 3);
  assert.equal(summary.byTool['tool-x'].costUsd, 3);
  assert.equal(summary.byTenant['tenant-x'].costUsd, 3);
});
