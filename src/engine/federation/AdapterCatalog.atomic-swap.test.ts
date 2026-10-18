/**
 * Regression eval: catalog refresh SHALL atomically swap the in-memory
 * catalog reference (CHARIOT §5.5::15).
 *
 * The defect this exists to catch: buildIndex() cleared the LIVE
 * this.categoryIndex/keywordIndex/nameIndex/revocationSet Maps/Set in place
 * and refilled them incrementally, with this.entries_ reassigned only at the
 * very end. A build that throws partway through (e.g. a
 * CatalogIntegrityError on a name collision, thrown from inside the same
 * loop that mutates the live indexes) left the catalog PERMANENTLY
 * corrupted: cleared, then only partially repopulated, with the throw never
 * reaching the final this.entries_ assignment.
 *
 * This test loads a good catalog via setEntries(), then calls setEntries()
 * again with a bundle that collides on `name` (guaranteed throw partway
 * through the build loop), and asserts the catalog after the failed rebuild
 * still returns the ORIGINAL good entries — proving the failed build did not
 * touch the live catalog. Against the pre-fix code (which cleared the live
 * Maps before the throw), entries() after the failed rebuild would return
 * an empty/corrupted result instead of the original two entries.
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/AdapterCatalog.atomic-swap.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AdapterCatalog, CatalogIntegrityError, type AdapterCatalogEntry } from './AdapterCatalog.js';

function makeEntry(name: string): AdapterCatalogEntry {
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

test('a failed rebuild (mid-build throw) leaves the live catalog untouched', () => {
  const catalog = new AdapterCatalog({ source: 'bundle', verifySignature: false });

  const good = [makeEntry('alpha'), makeEntry('beta')];
  catalog.setEntries(good);

  assert.equal(catalog.entries().length, 2);
  assert.deepEqual(
    catalog.entries().map((e) => e.name).sort(),
    ['alpha', 'beta'],
  );

  // A colliding-name bundle guarantees buildIndex() throws partway through
  // its loop, after it has already begun mutating (pre-fix: the live)
  // indexes.
  const colliding = [makeEntry('gamma'), makeEntry('gamma')];
  assert.throws(() => catalog.setEntries(colliding), CatalogIntegrityError);

  // The catalog must still reflect the last GOOD state, not a
  // cleared-and-partially-refilled one.
  assert.equal(catalog.entries().length, 2);
  assert.deepEqual(
    catalog.entries().map((e) => e.name).sort(),
    ['alpha', 'beta'],
  );
  assert.equal(catalog.byCategory('productivity').length, 2);
});
