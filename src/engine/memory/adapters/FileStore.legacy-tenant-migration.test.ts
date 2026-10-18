/**
 * CHARIOT §8.5::1 — hydrate-time migration semantics for legacy unscoped rows.
 *
 * These assertions are derived from the FAILURE ENUMERATION of the clause, not
 * from the implementation's shape. A memory row persisted before tenantId
 * became a required scope key has no tenant. Every disposal of such a row is
 * either unsafe or lossy, so the clause admits exactly three failure classes
 * and each is asserted here:
 *
 *   1. VALUE  — the row is given a default/placeholder tenant, making it
 *               readable by whichever tenant happens to carry that value.
 *   2. ALIAS  — the row is admitted with tenantId absent/empty and then matches
 *               a scope lookup built from an absent/empty tenant.
 *   3. SILENT LOSS — the row is dropped with no operator-visible signal, so a
 *               migration gap looks identical to an empty store.
 *
 * The shipped disposition is: SKIP the row, never assign a tenant, and WARN so
 * the loss is visible. Cases 1 and 2 must not occur; case 3 must be loud.
 *
 * Run (after tsc): node --test dist/engine/memory/adapters/FileStore.legacy-tenant-migration.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { FileStore } from './FileStore.js';

const TENANT = 'tenant-a';
const USER = 'user-1';

function storeWith(rows: unknown[]): FileStore {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-mem-'));
  const file = join(dir, 'memory.json');
  writeFileSync(file, JSON.stringify(rows), 'utf8');
  return new FileStore(file);
}

/** A row as it was persisted BEFORE tenantId existed — no tenant field at all. */
function legacyRow(id: string, userId = USER) {
  return {
    id,
    userId,
    content: `legacy-${id}`,
    importance: 'normal',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    isDeleted: false,
    accessCount: 0,
  };
}

test('§8.5::1: a legacy row with no tenantId is not readable under any tenant', async () => {
  const store = storeWith([legacyRow('m1')]);

  // The row must not surface for the user it originally belonged to...
  const asTenantA = await store.recall(TENANT, USER, {});
  assert.deepEqual(asTenantA, [], 'legacy row must not surface under an arbitrary tenant');

  // ...nor for any other tenant carrying that same userId.
  const asTenantB = await store.recall('tenant-b', USER, {});
  assert.deepEqual(asTenantB, [], 'legacy row must not surface under a second tenant');
});

test('§8.5::1: an empty-string tenantId is treated as absent, not as a real scope', async () => {
  // The boundary case: '' is a string, so a `typeof === string` check alone
  // would admit it and create a real, addressable empty-tenant scope.
  const store = storeWith([{ ...legacyRow('m2'), tenantId: '' }]);

  assert.deepEqual(await store.recall('', USER, {}), [], 'empty tenant must not address a scope');
  assert.deepEqual(await store.recall(TENANT, USER, {}), [], 'and must not leak into a real tenant');
});

test('§8.5::1: a legacy row is never assigned a default tenant', async () => {
  // If any default were assigned ('default', 'local', the env tenant, ...), the
  // row would become readable by whichever tenant carries that id. Probe the
  // plausible defaults explicitly rather than trusting the skip branch.
  const store = storeWith([legacyRow('m3')]);

  for (const probe of ['default', 'local', 'unknown', 'undefined', 'null']) {
    assert.deepEqual(
      await store.recall(probe, USER, {}),
      [],
      `legacy row must not be readable under a '${probe}' tenant`,
    );
  }
});

test('§8.5::1: a tenant-scoped row alongside a legacy row still hydrates', async () => {
  // The skip must drop ONLY the unscoped row — a migration that also discarded
  // valid neighbours would be a far worse loss than the one it prevents.
  const scoped = { ...legacyRow('m4'), tenantId: TENANT };
  const store = storeWith([legacyRow('m5'), scoped]);

  const rows = await store.recall(TENANT, USER, {});
  assert.equal(rows.length, 1, 'the tenant-scoped row survives hydrate');
  assert.equal(rows[0]?.id, 'm4');
});
