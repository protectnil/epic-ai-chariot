/**
 * Adversarial eval: catalog-driven query expansion (CHARIOT::§4.6::1)
 *
 * CHARIOT-SPEC.md §4.6: "`QueryExpander` (`src/engine/federation/
 * QueryExpander.ts`) rewrites queries that contain known abbreviations (e.g.,
 * "PD" -> "PagerDuty incident"). The expansion list is loaded from the
 * catalog `keywords` field per adapter."
 *
 * EARS (CHARIOT::§4.6::1): "QueryExpander SHALL rewrite queries containing
 * known abbreviations using the expansion list loaded from each adapter's
 * catalog keywords field."
 * Acceptance: "QueryExpander expands known abbreviations (e.g. PD->PagerDuty
 * incident) from catalog keywords."
 *
 * Before this node's fix, `expandQuery` had no parameter for catalog data at
 * all — the ONLY expansion source was the hand-authored `EXPANSIONS` table,
 * with zero code path reading any adapter's `keywords` field. These evals
 * fail on that prior implementation and pass on
 * `buildCatalogExpansionIndex` + `expandQuery(query, catalogIndex)`.
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/QueryExpander.catalog-driven.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { expandQuery, buildCatalogExpansionIndex, type CatalogAdapterLike } from './QueryExpander.js';

// ── eval: the clause's own worked example — PD -> PagerDuty incident ────────

test('catalog-driven: a known abbreviation from an adapter catalog keyword expands the query (PD -> PagerDuty incident)', () => {
  const adapters: CatalogAdapterLike[] = [
    { id: 'pagerduty', name: 'PagerDuty', keywords: ['PD', 'PagerDuty', 'incident', 'oncall'] },
  ];
  const index = buildCatalogExpansionIndex(adapters);

  const expanded = expandQuery('page the PD team', index);

  assert.notEqual(expanded, 'page the PD team', 'a catalog keyword hit must expand the query');
  assert.ok(expanded.includes('PagerDuty'), 'expansion must inject the adapter name from the catalog keywords entry');
  assert.ok(expanded.includes('incident'), 'expansion must inject sibling catalog keywords');
  assert.ok(expanded.includes('pagerduty'), 'expansion must inject the adapter id');
});

// ── eval: expansion is genuinely catalog-sourced, not the legacy static table ──

test('catalog-driven: a keyword present ONLY in the catalog (absent from the legacy EXPANSIONS table) still expands', () => {
  // A synthetic abbreviation guaranteed absent from the hand-authored
  // EXPANSIONS map, so a pass here can only be explained by the catalog path.
  const adapters: CatalogAdapterLike[] = [
    { id: 'zyx-widget-tracker', name: 'ZyxWidgetTracker', keywords: ['ZWTX9', 'widget-tracking'] },
  ];
  const index = buildCatalogExpansionIndex(adapters);

  const withoutCatalog = expandQuery('open a ZWTX9 ticket');
  assert.equal(withoutCatalog, 'open a ZWTX9 ticket', 'sanity: no catalog wired, no expansion for a synthetic term');

  const withCatalog = expandQuery('open a ZWTX9 ticket', index);
  assert.ok(withCatalog.includes('ZyxWidgetTracker'));
  assert.ok(withCatalog.includes('widget-tracking'));
  assert.ok(withCatalog.includes('zyx-widget-tracker'));
});

// ── eval: no catalog wired -> no catalog-driven expansion (backward compatible) ──

test('catalog-driven: expandQuery(query) with no catalogIndex argument is unchanged (backward compatible)', () => {
  assert.equal(expandQuery('the quick brown fox'), 'the quick brown fox');
});

// ── eval: word-boundary matching — a short abbreviation must not false-fire mid-token ──

test('catalog-driven: a short keyword must match as a whole word, not as a substring inside an unrelated token', () => {
  const adapters: CatalogAdapterLike[] = [
    { id: 'pagerduty', name: 'PagerDuty', keywords: ['PD'] },
  ];
  const index = buildCatalogExpansionIndex(adapters);

  // "PD" is a substring of "UPDATE" — must NOT trigger the PagerDuty expansion.
  const expanded = expandQuery('please UPDATE the record', index);
  assert.equal(expanded, 'please UPDATE the record', 'a substring match inside an unrelated word must not fire');

  // A real standalone token still fires.
  const expandedReal = expandQuery('please PD the record', index);
  assert.notEqual(expandedReal, 'please PD the record');
});

// ── eval: multiple adapters sharing a keyword union their expansion terms ────

test('catalog-driven: a keyword shared by two adapters expands to the union of both adapters\' terms', () => {
  const adapters: CatalogAdapterLike[] = [
    { id: 'okta', name: 'Okta', keywords: ['sso', 'login'] },
    { id: 'auth0', name: 'Auth0', keywords: ['sso', 'identity'] },
  ];
  const index = buildCatalogExpansionIndex(adapters);

  const expanded = expandQuery('debug the sso flow', index);
  assert.ok(expanded.includes('Okta'));
  assert.ok(expanded.includes('Auth0'));
  assert.ok(expanded.includes('login'));
  assert.ok(expanded.includes('identity'));
});

// ── eval: an adapter with no keywords contributes no expansion rule ──────────

test('catalog-driven: an adapter with an empty/absent keywords field contributes nothing', () => {
  const adapters: CatalogAdapterLike[] = [
    { id: 'no-keywords-adapter', name: 'NoKeywordsAdapter' },
    { id: 'empty-keywords-adapter', name: 'EmptyKeywordsAdapter', keywords: [] },
  ];
  const index = buildCatalogExpansionIndex(adapters);
  assert.equal(index.length, 0, 'zero rules when no adapter publishes keywords');

  const expanded = expandQuery('NoKeywordsAdapter please run', index);
  assert.equal(expanded, 'NoKeywordsAdapter please run');
});

// ── eval: legacy EXPANSIONS heuristic still runs alongside the catalog path ───

test('catalog-driven: the legacy heuristic table and the catalog-driven path both contribute when both fire', () => {
  const adapters: CatalogAdapterLike[] = [
    { id: 'pagerduty', name: 'PagerDuty', keywords: ['PD'] },
  ];
  const index = buildCatalogExpansionIndex(adapters);

  // 'malware' is a legacy EXPANSIONS phrase; 'PD' is catalog-only in this test.
  const expanded = expandQuery('malware and PD alert', index);
  assert.ok(expanded.includes('crowdstrike'), 'legacy heuristic term still present');
  assert.ok(expanded.includes('PagerDuty'), 'catalog-driven term also present');
});
