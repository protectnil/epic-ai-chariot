/**
 * Adversarial eval: ToolPreFilter.select() async boundary (Finding 2, commit 2f61fe9)
 *
 * The fix changed select() from:
 *   return Promise.resolve(this.selectInternal(query, options).tools);
 * to:
 *   async select(...) { return this.selectInternal(query, options).tools; }
 *
 * The old pattern let a synchronous throw inside selectInternal escape BEFORE the
 * Promise was constructed — callers' .catch() / try-catch-await never saw it.
 * Making the function async ensures all throws become rejections.
 *
 * selectInternal calls expandQuery(query) which calls query.toLowerCase() — a null
 * query throws TypeError synchronously (no mocking required; this is real input
 * that triggers the real throw path). The evals verify that the throw is surfaced
 * as a rejection, not as an uncaught synchronous exception.
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/ToolPreFilter.select-async.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ToolPreFilter } from './ToolPreFilter.js';
import type { Tool } from '../types/index.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeTool(server: string, name: string, description: string): Tool {
  return {
    server,
    name,
    description,
    parameters: { type: 'object', properties: {} },
    tier: 'direct',
  };
}

/** Build a ToolPreFilter indexed with a small but real catalog. */
function buildFilter(): ToolPreFilter {
  const f = new ToolPreFilter();
  f.index([
    makeTool('stripe', 'create_invoice', 'Create a Stripe payment invoice for a customer'),
    makeTool('github', 'list_repos', 'List all GitHub repositories for the authenticated user'),
    makeTool('pagerduty', 'create_incident', 'Create a PagerDuty incident and notify on-call engineer'),
  ]);
  return f;
}

// ── eval 2a: null query → TypeError becomes a promise rejection ───────────────

test('select() null query: does not throw synchronously — returns a Promise', async () => {
  const filter = buildFilter();

  let threwSynchronously = false;
  let returned: unknown;

  try {
    // Force null as the query: triggers query.toLowerCase() inside expandQuery()
    // which is called synchronously from selectInternal(). With the old
    // Promise.resolve() pattern this TypeError escaped before the Promise was
    // constructed; with async select() it becomes a rejection.
    returned = filter.select(null as unknown as string);
  } catch {
    threwSynchronously = true;
  }

  assert.equal(
    threwSynchronously,
    false,
    'select() must never throw synchronously — it is typed as Promise<Tool[]>',
  );
  assert.ok(
    returned instanceof Promise,
    'select() must return a Promise even when selectInternal throws synchronously internally',
  );
  // Drain the rejection so it does not become an unhandledRejection in this test.
  await (returned as Promise<unknown>).catch(() => {});
});

test('select() null query: .catch() caller receives the TypeError', async () => {
  const filter = buildFilter();

  let caughtError: unknown = null;

  // With the old Promise.resolve() pattern, the TypeError escaped before the
  // Promise was constructed, so attaching .catch() after the fact was too late —
  // the exception was already propagating on the synchronous call stack.
  // With async select(), .catch() is always the correct interception point.
  const p = filter.select(null as unknown as string);
  await p.catch((err: unknown) => {
    caughtError = err;
  });

  assert.ok(
    caughtError instanceof TypeError,
    `TypeError from expandQuery(null) must reach .catch(), got: ${String(caughtError)}`,
  );
});

// ── eval 2b: await/try-catch caller receives the TypeError ───────────────────

test('select() null query: await try-catch receives the TypeError', async () => {
  const filter = buildFilter();

  let caughtError: unknown = null;
  try {
    await filter.select(null as unknown as string);
  } catch (err) {
    caughtError = err;
  }

  assert.ok(
    caughtError instanceof TypeError,
    `TypeError must be catchable by await/try-catch, got: ${String(caughtError)}`,
  );
  assert.match(
    String(caughtError),
    /toLowerCase|Cannot read/,
    'error message must identify the null.toLowerCase() failure site',
  );
});

// ── eval 2c: valid query still works normally after async change ──────────────

test('select() valid query: returns tools normally after async refactor', async () => {
  const filter = buildFilter();

  const tools = await filter.select('create invoice payment stripe');

  assert.ok(Array.isArray(tools), 'select() must return an array of tools');
  assert.ok(tools.length > 0, 'must return at least one tool for a matching query');
  // stripe:create_invoice should rank highly for "create invoice payment stripe"
  assert.ok(
    tools.some(t => t.server === 'stripe'),
    'stripe tools must appear in the shortlist for a stripe-targeted query',
  );
});

// ── eval 2d: selectWithVerdict() is unaffected — stays synchronous ────────────

test('selectWithVerdict() still returns synchronously (not a Promise)', () => {
  const filter = buildFilter();

  // selectWithVerdict() returns RoutingVerdict — plain object, not Promise.
  // The fix comment explicitly says "selectWithVerdict() at line 627 returns
  // RoutingVerdict synchronously (no Promise wrapper) and is unaffected."
  const verdict = filter.selectWithVerdict('list repositories github');

  assert.ok(!(verdict instanceof Promise), 'selectWithVerdict() must remain synchronous');
  assert.ok(Array.isArray(verdict.tools), 'verdict.tools must be an array');
  assert.equal(typeof verdict.confidence, 'number', 'verdict.confidence must be a number');
  assert.equal(typeof verdict.abstain, 'boolean', 'verdict.abstain must be a boolean');
});
