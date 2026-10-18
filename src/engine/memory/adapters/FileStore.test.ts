/**
 * durable memory across serve restarts — durable memory across `serve` restarts.
 *
 * CHARIOT::§8.5::7 ("durable, restart-surviving store (not InMemoryStore) by
 * default") + CHARIOT::§23.2::44-45. The OSS build
 * previously backed chariot_remember with the volatile InMemoryStore, so
 * remembered data was lost on every serve restart while the tool surface
 * advertised PERSISTENT memory. FileStore backs the default store with a JSON
 * file so a fresh process (simulated here by a second FileStore over the same
 * path) recalls what a prior process stored.
 *
 * No mocks — real FileStore over a real temp file.
 *
 * Run: node --test dist/engine/memory/adapters/FileStore.test.js
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { FileStore } from './FileStore.js';
import type { MemoryEntry } from '../../types/index.js';

function tmpFile(): { dir: string; path: string } {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-mem-'));
  return { dir, path: join(dir, 'memory.json') };
}

const entry = (content: string, importance: MemoryEntry['importance'] = 'normal'): MemoryEntry => ({
  type: 'preference',
  content,
  importance,
});

describe('FileStore — durable memory (durable memory across serve restarts)', () => {
  test('remembered entry survives a restart (new store, same file)', async () => {
    const { dir, path } = tmpFile();
    try {
      const first = new FileStore(path);
      const saved = await first.save('local-tenant', 'local', entry('favorite color is teal', 'high'));
      assert.ok(existsSync(path), 'memory file written on save');

      // Simulate a serve restart: a brand-new store hydrating from the file.
      const second = new FileStore(path);
      const recalled = await second.recall('local-tenant', 'local', { type: 'preference' });
      assert.equal(recalled.length, 1, 'entry recalled after restart');
      assert.equal(recalled[0]?.id, saved.id, 'same id survives round-trip');
      assert.equal(recalled[0]?.content, 'favorite color is teal');
      assert.equal(recalled[0]?.importance, 'high');
      assert.ok(recalled[0]?.createdAt instanceof Date, 'createdAt revived as Date');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('forget tombstone survives a restart (stays gone)', async () => {
    const { dir, path } = tmpFile();
    try {
      const first = new FileStore(path);
      const saved = await first.save('local-tenant', 'local', entry('ephemeral note'));
      const deleted = await first.delete('local-tenant', 'local', saved.id);
      assert.equal(deleted, true, 'delete reports success');

      const second = new FileStore(path);
      const recalled = await second.recall('local-tenant', 'local', {});
      assert.equal(recalled.length, 0, 'forgotten entry does not resurrect after restart');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('tenant scoping preserved across restart (no cross-tenant leak)', async () => {
    const { dir, path } = tmpFile();
    try {
      const first = new FileStore(path);
      // §8.5::1 — cross-tenant memory isolation — the SAME userId in two different tenants. Before the
      // fix the scope was userId alone, so these two writes shared one bucket
      // and each tenant read the other's memory back.
      await first.save('tenant-a', 'same-user', entry('secret A'));
      await first.save('tenant-b', 'same-user', entry('secret B'));

      const second = new FileStore(path);
      const a = await second.recall('tenant-a', 'same-user', {});
      const b = await second.recall('tenant-b', 'same-user', {});
      const other = await second.recall('tenant-c', 'same-user', {});

      assert.equal(a.length, 1);
      assert.equal(a[0]?.content, 'secret A');
      assert.equal(b.length, 1);
      assert.equal(b[0]?.content, 'secret B');
      assert.equal(other.length, 0, 'unrelated tenant sees nothing');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('high-importance count is rebuilt on hydrate (cap enforced across restart)', async () => {
    const { dir, path } = tmpFile();
    try {
      const first = new FileStore(path, { maxHighImportancePerScope: 1 });
      await first.save('local-tenant', 'local', entry('first high', 'high'));

      // A fresh store must re-derive the high-count from disk, so the cap still
      // rejects a second 'high' after restart.
      const second = new FileStore(path, { maxHighImportancePerScope: 1 });
      await assert.rejects(
        () => second.save('local-tenant', 'local', entry('second high', 'high')),
        (err: { code?: string }) => err.code === 'HIGH_IMPORTANCE_CAP_EXCEEDED',
        'high cap enforced after hydrate',
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('corrupt memory file does not brick the store', async () => {
    const { dir, path } = tmpFile();
    try {
      const { writeFileSync } = await import('node:fs');
      writeFileSync(path, '{ this is not valid json', 'utf8');
      const store = new FileStore(path); // must not throw
      const saved = await store.save('local-tenant', 'local', entry('recovered'));
      const recalled = await store.recall('local-tenant', 'local', {});
      assert.equal(recalled.length, 1);
      assert.equal(recalled[0]?.id, saved.id);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
