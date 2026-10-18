/**
 * Regression eval — CHARIOT::§5.4::5.
 *
 * CHARIOT-SPEC.md §5.4 table row: "`registry` | Optional; connected; reads
 * `registryUrl` set by the customer's deployment config | Falls back to
 * bundle when refresh fails". EARS text (spec_nodes CHARIOT::§5.4::5):
 * "WHEN source is `registry` the system SHALL read the operator-configured
 * registryUrl and SHALL fall back to bundle when refresh fails."
 *
 * Two failure paths existed pre-fix, neither of which read
 * chariot-adapter-bundle.json on a registry failure:
 *   1. `load()` (initial, boot-time): a `source: 'registry'` load with no
 *      try/catch around `loadFromRegistry()` — the thrown error propagated
 *      out of `load()` uncaught, with no bundle-file read attempted at all.
 *   2. `startRefresh()` (periodic): the interval callback's `.catch()`
 *      logged and did nothing else — "retaining current catalog" — which
 *      means whatever was ALREADY in memory stayed, never a fresh read of
 *      the bundle file. That is not a bundle fallback.
 *
 * Both tests here point `registryUrl` at `http://127.0.0.1:1/catalog` — TCP
 * port 1 on loopback refuses the connection immediately (no external
 * network access needed, no mocking of `fetch`), giving a real,
 * deterministic `loadFromRegistry()` failure.
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/AdapterCatalog.registry-bundle-fallback.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AdapterCatalog, type AdapterCatalogEntry } from './AdapterCatalog.js';

const UNREACHABLE_REGISTRY_URL = 'http://127.0.0.1:1/catalog';

function entry(name: string): AdapterCatalogEntry {
  return {
    name,
    displayName: name,
    version: '1.0.0',
    category: 'productivity',
    keywords: ['foo'],
    toolNames: ['do_thing'],
    description: `The ${name} adapter`,
    author: 'community',
  };
}

function writeBundle(dir: string, epoch: number, entries: AdapterCatalogEntry[]): string {
  const catalogPath = join(dir, 'adapter-bundle.json');
  writeFileSync(
    catalogPath,
    JSON.stringify({ epoch, catalogVersion: 1, catalog: entries, registry: [] }),
  );
  return catalogPath;
}

test('an initial (load-time) registry failure falls back to reading the bundle file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cs54-load-'));
  const catalogPath = writeBundle(dir, 1_700_000_000_000, [entry('alpha'), entry('beta')]);
  const epochPath = join(dir, '.chariot-catalog-epoch.json');

  const catalog = new AdapterCatalog({
    source: 'registry',
    registryUrl: UNREACHABLE_REGISTRY_URL,
    verifySignature: false,
    catalogPath,
    epochPath,
  });

  // Pre-fix: this threw (ECONNREFUSED / fetch failure) uncaught, with no
  // bundle read attempted, and `entries()` was never populated.
  await assert.doesNotReject(() => catalog.load());
  assert.deepEqual(
    catalog.entries().map((e) => e.name).sort(),
    ['alpha', 'beta'],
    'load() must fall back to the bundle catalog when the registry read fails',
  );
});

test('a periodic registry refresh failure falls back to the bundle catalog, not the stale in-memory set', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cs54-refresh-'));
  const catalogPath = writeBundle(dir, 1_700_000_000_001, [entry('gamma'), entry('delta')]);
  const epochPath = join(dir, '.chariot-catalog-epoch.json');

  const catalog = new AdapterCatalog({
    source: 'registry',
    registryUrl: UNREACHABLE_REGISTRY_URL,
    verifySignature: false,
    catalogPath,
    epochPath,
    refreshIntervalMs: 20,
  });

  // Seed a DIFFERENT in-memory set via setEntries() (bypasses monotonicity,
  // as in AdapterCatalog.atomic-swap.test.ts) so "fell back to bundle
  // content" is distinguishable from "retained the stale in-memory set" —
  // the pre-fix behavior kept exactly this seeded entry forever.
  catalog.setEntries([entry('stale-only')]);
  assert.deepEqual(catalog.entries().map((e) => e.name), ['stale-only']);

  catalog.startRefresh();
  try {
    // Wait past at least one refresh tick (20ms interval) plus the
    // ECONNREFUSED + bundle-read-and-rebuild time.
    await new Promise((resolve) => setTimeout(resolve, 500));
    assert.deepEqual(
      catalog.entries().map((e) => e.name).sort(),
      ['delta', 'gamma'],
      'a refresh failure must rebuild the catalog from the bundle file, not retain the stale seeded set',
    );
  } finally {
    catalog.stopRefresh();
  }
});
