/**
 * @epicai/chariot — File-Backed Memory Store
 * Durable local memory store for the OSS single-user build.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * durable memory across serve restarts (CHARIOT::§8.5::7 "durable,
 * restart-surviving store (not InMemoryStore) by default" + CHARIOT::§23.2::44-45):
 *   The chariot_remember / chariot_recall / chariot_forget tool surface
 *   advertises PERSISTENT, tenant-scoped memory. The OSS build has no
 *   Redis/Mongo, so the durable default is this file-backed store rather than
 *   the volatile InMemoryStore. It reuses ALL of InMemoryStore's capacity,
 *   high-importance-cap, eviction, and tenant-scoping logic (via inheritance)
 *   and adds only durability: hydrate from a JSON file on construction, and
 *   atomically rewrite that file after every mutation. Enterprise deployments
 *   that inject a RedisMongoAdapter-backed PersistentMemory never use this.
 *
 * Isolation: persistence is layered on top of the inherited per-userId scoping,
 *   so cross-tenant recall isolation is exactly InMemoryStore's — the file is a
 *   flat dump of already-scoped entries, keyed back to their userId on hydrate.
 *
 * Encryption: PersistentMemory encrypts entry content BEFORE calling save() and
 *   decrypts on recall(), so when an encryptionKey is configured the content on
 *   disk is ciphertext. The plaintext key is never written to this file.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { createLogger } from '../../logger.js';
import { InMemoryStore, type InMemoryStoreOptions } from './InMemoryStore.js';
import type {
  MemoryEntry,
  MemoryActor,
  MemoryImportance,
  StoredMemory,
} from '../../types/index.js';

const log = createLogger('memory.file-store');

/** On-disk shape: StoredMemory with Date fields serialised as ISO strings. */
interface SerializedMemory extends Omit<StoredMemory, 'createdAt' | 'lastAccessed' | 'deletedAt'> {
  createdAt: string;
  lastAccessed: string | null;
  deletedAt?: string;
}

/** Revive a serialised record's Date fields back into Date objects. */
function reviveEntry(o: SerializedMemory): StoredMemory {
  const entry: StoredMemory = {
    ...(o as unknown as StoredMemory),
    createdAt: new Date(o.createdAt),
    lastAccessed: o.lastAccessed != null ? new Date(o.lastAccessed) : null,
  };
  if (o.deletedAt != null) {
    entry.deletedAt = new Date(o.deletedAt);
  }
  return entry;
}

export class FileStore extends InMemoryStore {
  private readonly filePath: string;

  /**
   * @param filePath Absolute path to the JSON memory file (e.g.
   *   `${EPIC_AI_DIR}/memory.json`). Its parent dir is created on first write.
   */
  constructor(filePath: string, options: InMemoryStoreOptions = {}) {
    super(options);
    this.filePath = filePath;
    // Synchronous hydrate in the constructor guarantees prior memories are
    // present before any save/recall/forget can run — no async race window.
    this.hydrate();
  }

  private hydrate(): void {
    try {
      if (!existsSync(this.filePath)) return;
      const raw = readFileSync(this.filePath, 'utf8');
      if (raw.trim().length === 0) return;
      const parsed = JSON.parse(raw) as SerializedMemory[];
      if (!Array.isArray(parsed)) {
        log.warn('memory file is not an array; starting empty', { path: this.filePath });
        return;
      }
      this.importEntries(parsed.map(reviveEntry));
      log.debug('memory hydrated from disk', { path: this.filePath, entries: parsed.length });
    } catch (err) {
      // A corrupt file must not brick the server. Start empty; the next
      // successful mutation rewrites a clean file.
      log.warn('memory hydrate failed; starting empty', {
        path: this.filePath,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * Atomically rewrite the whole memory file (temp file + rename). Includes
   * soft-deleted tombstones so forget() survives a restart. Best-effort: a
   * persist failure is logged but never thrown, so an fs error can't turn a
   * successful in-memory op into a caller-visible error.
   */
  private persist(): void {
    try {
      const dir = dirname(this.filePath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      const data = JSON.stringify(this.exportEntries());
      const tmp = `${this.filePath}.tmp`;
      writeFileSync(tmp, data, { mode: 0o600 });
      renameSync(tmp, this.filePath);
    } catch (err) {
      log.warn('memory persist failed; in-memory state is ahead of disk', {
        path: this.filePath,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  override async save(tenantId: string, userId: string, entry: MemoryEntry, actor?: MemoryActor): Promise<StoredMemory> {
    const stored = await super.save(tenantId, userId, entry, actor);
    // super.save may also have soft-evicted an entry at capacity; persist()
    // dumps the full set, so the eviction tombstone is captured too.
    this.persist();
    return stored;
  }

  override async delete(tenantId: string, userId: string, memoryId: string): Promise<boolean> {
    const deleted = await super.delete(tenantId, userId, memoryId);
    if (deleted) this.persist();
    return deleted;
  }

  override async recordAccess(tenantId: string, memoryId: string): Promise<void> {
    await super.recordAccess(tenantId, memoryId);
    this.persist();
  }

  override async promoteImportance(tenantId: string, memoryId: string, newImportance: MemoryImportance): Promise<void> {
    await super.promoteImportance(tenantId, memoryId, newImportance);
    this.persist();
  }
}
