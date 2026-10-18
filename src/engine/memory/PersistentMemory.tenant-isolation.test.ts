/**
 * Prove-on-revert for CHARIOT §8.5::1 — memory is scoped by (tenantId, userId).
 *
 * the cross-tenant memory isolation fix: the memory API was user-scoped end to end. RedisMongoAdapter filtered
 * Mongo on `{ userId, isDeleted:false }`, cached under `${keyPrefix}${userId}:…`
 * and tracked/invalidated under `${keyPrefix}keys:${userId}` — no tenantId
 * anywhere. IAM identity is tenant-scoped (iam/indexes.ts), so nothing
 * guarantees a userId is unique across tenants: two tenants sharing a userId
 * read, overwrote and invalidated each other's memory.
 *
 * Every assertion below uses the SAME userId in two different tenants. Revert
 * the tenant threading and each one fails.
 *
 * Run (after tsc): node --test dist/engine/memory/PersistentMemory.tenant-isolation.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { PersistentMemory } from './PersistentMemory.js';
import { InMemoryStore } from './adapters/InMemoryStore.js';
import type { MemoryEntry } from '../types/index.js';

const USER = 'same-user';
const A = 'tenant-a';
const B = 'tenant-b';

const entry = (content: string): MemoryEntry => ({
  type: 'secret',
  content,
  importance: 'normal',
});

function fresh(): PersistentMemory {
  return new PersistentMemory({ store: new InMemoryStore(), cacheTTLMs: 0 });
}

test('§8.5::1: recall is isolated per tenant for the same userId', async () => {
  const memory = fresh();
  await memory.etch(A, USER, entry('A'));
  await memory.etch(B, USER, entry('B'));

  assert.deepEqual(
    (await memory.recall(A, USER, {})).map(m => m.content),
    ['A'],
    'tenant A must see only its own memory',
  );
  assert.deepEqual(
    (await memory.recall(B, USER, {})).map(m => m.content),
    ['B'],
    'tenant B must see only its own memory',
  );
});

test('§8.5::1: context aggregates are isolated per tenant', async () => {
  const memory = fresh();
  await memory.etch(A, USER, entry('A'));
  await memory.etch(B, USER, entry('B'));

  assert.equal((await memory.context(A, USER)).totalMemories, 1);
  assert.equal((await memory.context(B, USER)).totalMemories, 1);
});

test('§8.5::1: one tenant cannot forget another tenant memory by id', async () => {
  const memory = fresh();
  const a = await memory.etch(A, USER, entry('A'));
  const b = await memory.etch(B, USER, entry('B'));

  // Tenant A holds tenant B's memory id and tries to delete it.
  assert.equal(
    await memory.forget(A, USER, b.id),
    false,
    'cross-tenant forget must be a truthful no-op',
  );
  assert.deepEqual(
    (await memory.recall(B, USER, {})).map(m => m.content),
    ['B'],
    "tenant B's memory must survive tenant A's delete attempt",
  );

  // A deleting its OWN id still works.
  assert.equal(await memory.forget(A, USER, a.id), true);
  assert.deepEqual((await memory.recall(A, USER, {})).map(m => m.content), []);
  assert.deepEqual(
    (await memory.recall(B, USER, {})).map(m => m.content),
    ['B'],
    "tenant B is untouched by tenant A's own delete",
  );
});

test('§8.5::1: a memory id from one tenant does not resolve in another', async () => {
  const store = new InMemoryStore();
  const memory = new PersistentMemory({ store, cacheTTLMs: 0 });
  const b = await memory.etch(B, USER, entry('B'));

  // recordAccess/promoteImportance are tenant-keyed: A's call must not touch B.
  await store.recordAccess(A, b.id);
  await store.promoteImportance(A, b.id, 'high');

  const [stored] = await memory.recall(B, USER, {});
  assert.equal(stored?.accessCount, 0, 'cross-tenant recordAccess must be a no-op');
  assert.equal(stored?.importance, 'normal', 'cross-tenant promoteImportance must be a no-op');
});

test('§8.5::1: capacity/high-importance caps are charged per tenant, not per user', async () => {
  const store = new InMemoryStore({ maxHighImportancePerScope: 1 });
  const memory = new PersistentMemory({ store, cacheTTLMs: 0 });

  await memory.etch(A, USER, { type: 'x', content: 'A-high', importance: 'high' });
  // The same userId in a DIFFERENT tenant must still have its own cap budget.
  await memory.etch(B, USER, { type: 'x', content: 'B-high', importance: 'high' });

  assert.deepEqual((await memory.recall(A, USER, {})).map(m => m.content), ['A-high']);
  assert.deepEqual((await memory.recall(B, USER, {})).map(m => m.content), ['B-high']);
});
