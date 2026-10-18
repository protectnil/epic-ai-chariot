/**
 * Regression eval — the strictly-increasing epoch check bricked
 * boot on every restart after the first.
 *
 * These are the bug record's own `stepsToReproduce`, executed verbatim:
 *
 *   1. Write a valid bundle with epoch E and catalogVersion V to a temp dir
 *   2. new AdapterCatalog({catalogPath, epochPath, verifySignature:false})
 *      .load() -> OK, persists E
 *   3. Construct a SECOND AdapterCatalog instance over the SAME catalogPath
 *      and epochPath (a process restart) and call load()
 *   4. Observe CatalogIntegrityError: bundle epoch E equals persisted epoch E
 *
 * Step 4 is the DEFECT. Against the fixed code the second load must succeed as
 * a §5.6 re-admission (CHARIOT-SPEC.md:431) — the on-disk bundle does not
 * change between boots, so identity, not recency, decides whether the runtime
 * may re-attach to the artifact it already accepted.
 *
 * A second instance is used rather than one, deliberately: `_lastAcceptedEpoch`
 * caches the mark in-process, so a single instance would short-circuit the disk
 * read and never exercise the restart path at all.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AdapterCatalog, type AdapterCatalogEntry } from './AdapterCatalog.js';

const EPOCH = 1_700_000_000_000;
const CATALOG_VERSION = 7;

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

/** Step 1 — a valid bundle at a FIXED epoch, written once and never rewritten. */
function writeBundle(dir: string): string {
  const catalogPath = join(dir, 'adapter-bundle.json');
  writeFileSync(
    catalogPath,
    JSON.stringify({
      epoch: EPOCH,
      catalogVersion: CATALOG_VERSION,
      catalog: [entry('alpha'), entry('beta')],
      registry: [],
    }),
  );
  return catalogPath;
}

test('a second AdapterCatalog over the same unchanged bundle re-admits instead of bricking', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-bug972-'));
  const catalogPath = writeBundle(dir);
  const epochPath = join(dir, '.chariot-catalog-epoch.json');

  // Step 2 — first boot. Establishes the identity-bound high-water mark.
  const first = new AdapterCatalog({
    source: 'bundle',
    verifySignature: false,
    catalogPath,
    epochPath,
  });
  await first.load();
  assert.equal(first.entries().length, 2, 'first boot must load the catalog');
  assert.ok(existsSync(epochPath), 'first boot must persist the epoch mark');

  const persisted = JSON.parse(readFileSync(epochPath, 'utf-8')) as {
    epoch: number;
    catalogVersion: number;
    bundleSha256?: string;
  };
  assert.equal(persisted.epoch, EPOCH);
  assert.equal(persisted.catalogVersion, CATALOG_VERSION);
  assert.equal(
    typeof persisted.bundleSha256,
    'string',
    'the mark must be identity-bound to the bundle bytes, or re-admission can never be proven (§5.6:431)',
  );

  const markAfterFirstBoot = readFileSync(epochPath, 'utf-8');

  // Step 3 — process restart: a SECOND instance over the SAME paths, with the
  // bundle bytes untouched. This is the normal restart, not a replay.
  const second = new AdapterCatalog({
    source: 'bundle',
    verifySignature: false,
    catalogPath,
    epochPath,
  });

  // Step 4 — the defect was a CatalogIntegrityError here.
  await second.load();
  assert.equal(
    second.entries().length,
    2,
    'restart over the identical on-disk bundle must re-admit, not throw',
  );

  // A re-admission is NOT a publication: the mark SHALL NOT be rewritten
  // (CHARIOT-SPEC.md:431, :457).
  assert.equal(
    readFileSync(epochPath, 'utf-8'),
    markAfterFirstBoot,
    'a re-admission must not rewrite the high-water mark (§5.6:431)',
  );
});

/**
 * The two-replica CAS race (§5.6:458 — "before advertising the catalog to any
 * consumer").
 *
 * A shared-backend store advances the mark only when the candidate is strictly
 * newer. If a sibling replica persists a NEWER epoch between this replica's
 * load() and its write, the CAS predicate no longer holds and the write does
 * not land. Treating that as benign was a defect: the classifier had already
 * returned `advance`, so this replica would go on to advertise a catalog whose
 * high-water mark never landed, while the shared mark named a newer bundle it
 * had not loaded.
 *
 * `CatalogEpochStore.persist` is contracted to THROW in that case. This test
 * drives the caller half through an injected store, proving AdapterCatalog
 * fails closed and advertises nothing.
 */
test('§5.6:458: a replica whose epoch CAS is lost fails closed and advertises no catalog', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-cas-lost-'));
  const catalogPath = writeBundle(dir);

  const losingStore = {
    load: async () => null, // fresh replica: no mark read → classifier says advance
    persist: async () => {
      // A sibling replica persisted a newer epoch first; the CAS predicate
      // {epoch: {$lt: candidate}} no longer matched, so nothing was written.
      throw new Error('adapter-catalog epoch CAS lost: a sibling replica persisted an epoch at or above 1700000000000');
    },
    describe: () => 'test:losing-cas-store',
  };

  const catalog = new AdapterCatalog({
    source: 'bundle',
    verifySignature: false,
    catalogPath,
    epochStore: losingStore,
  });

  await assert.rejects(
    () => catalog.load(),
    /CAS lost/,
    'a lost CAS must propagate, not be swallowed (§5.6:458)',
  );
  assert.equal(
    catalog.entries().length,
    0,
    'a replica whose mark did not land must advertise NO catalog (§5.6:458)',
  );
});

test('a DIFFERENT bundle at the same epoch is still rejected as a replay', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-bug972-replay-'));
  const catalogPath = writeBundle(dir);
  const epochPath = join(dir, '.chariot-catalog-epoch.json');

  await new AdapterCatalog({
    source: 'bundle',
    verifySignature: false,
    catalogPath,
    epochPath,
  }).load();

  // Tamper: same epoch and catalogVersion, DIFFERENT payload bytes. The whole
  // point of the anti-replay rule is that this must not be admitted just
  // because the fix relaxed the equal-epoch case.
  writeFileSync(
    catalogPath,
    JSON.stringify({
      epoch: EPOCH,
      catalogVersion: CATALOG_VERSION,
      catalog: [entry('alpha'), entry('beta'), entry('gamma-injected')],
      registry: [],
    }),
  );

  await assert.rejects(
    () =>
      new AdapterCatalog({
        source: 'bundle',
        verifySignature: false,
        catalogPath,
        epochPath,
      }).load(),
    /replay|different|identity/i,
    'a different artifact at the persisted epoch must stay rejected (§5.6:431)',
  );
});
