/**
 * @epicai/chariot — In-Memory Store
 * For development and testing. Not for production use.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * (capacity cap): Scopes are capped at MAX_ENTRIES_PER_SCOPE. On
 *   insert when at cap, the lowest-importance / oldest entry is evicted.
 *   Evictions emit a structured audit warn via the engine logger.
 *   getCapacityStatus(userId) exposes live metrics for ops visibility.
 *
 * (recall mutation removal): recall() is now read-only. Access
 *   metadata (accessCount, lastAccessed) is updated ONLY via recordAccess().
 *   Importance is promoted ONLY via promoteImportance(). The old implicit
 *   side-effects inside recall() are removed.
 *
 * (importance-tier guard): Per-scope cap on 'high' entries
 *   (MAX_HIGH_IMPORTANCE_PER_SCOPE). save() with an actor that lacks the
 *   'memory:high' capability or isAdmin flag silently downgrades 'high' to
 *   'medium'. promoteImportance() to 'high' is also capped.
 */

import { randomUUID } from 'node:crypto';
import { createLogger } from '../../logger.js';
import type {
  MemoryStoreAdapter,
  MemoryEntry,
  MemoryActor,
  MemoryImportance,
  StoredMemory,
  RecallOptions,
  ContextSummary,
  CapacityStatus,
  ChariotErrorCode,
} from '../../types/index.js';
import { importanceRank, CHARIOT_ERROR_CODES } from '../../types/index.js';

const log = createLogger('memory.in-memory-store');

// ---------------------------------------------------------------------------
// Constants — configurable via constructor options
// ---------------------------------------------------------------------------

export const DEFAULT_MAX_ENTRIES_PER_SCOPE = 10_000;
export const DEFAULT_MAX_HIGH_IMPORTANCE_PER_SCOPE = 100;

export interface InMemoryStoreOptions {
  maxEntriesPerScope?: number;
  maxHighImportancePerScope?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Determine whether an actor has the capability to save/promote at
 * importance:'high'. Returns true when:
 *   - actor is undefined (legacy caller — backwards-compatible permissive)
 *   - actor.isAdmin === true
 *   - actor.capabilities includes 'memory:high'
 */
export function canSetHighImportance(actor: MemoryActor | undefined): boolean {
  if (actor === undefined) return true; // legacy caller — permissive
  if (actor.isAdmin === true) return true;
  return (actor.capabilities ?? []).includes('memory:high');
}

// ---------------------------------------------------------------------------
// InMemoryStore
// ---------------------------------------------------------------------------

export class InMemoryStore implements MemoryStoreAdapter {
  private readonly store = new Map<string, StoredMemory[]>();

  /** userId → memoryId index for O(1) lookup in recordAccess/promoteImportance */
  private readonly idIndex = new Map<string, { userId: string; entry: StoredMemory }>();

  /** Per-scope high-importance count cache — updated incrementally on save/promote/soft-delete. */
  private readonly highCount = new Map<string, number>();

  private readonly maxEntriesPerScope: number;
  private readonly maxHighImportancePerScope: number;

  constructor(options: InMemoryStoreOptions = {}) {
    this.maxEntriesPerScope      = options.maxEntriesPerScope      ?? DEFAULT_MAX_ENTRIES_PER_SCOPE;
    this.maxHighImportancePerScope = options.maxHighImportancePerScope ?? DEFAULT_MAX_HIGH_IMPORTANCE_PER_SCOPE;
  }

  // -------------------------------------------------------------------------
  // save()
  // -------------------------------------------------------------------------

  /**
   * Persist a new memory entry.
   *
 * Actor capability check:
   *   When actor is provided and lacks 'memory:high' capability, importance:'high'
   *   is downgraded to 'medium' and a warning is logged. Legacy callers (no actor)
   *   are accepted without restriction.
   *
 * High-importance cap:
   *   If the effective importance is 'high' and the scope already holds
   *   MAX_HIGH_IMPORTANCE_PER_SCOPE non-deleted high-importance entries, save()
   *   throws a structured error rather than violating the cap.
   *
 * Capacity cap:
   *   If the scope is at MAX_ENTRIES_PER_SCOPE non-deleted entries, the
   *   lowest-importance / oldest entry is evicted (soft-deleted) before insert.
   */
  save(userId: string, entry: MemoryEntry, actor?: MemoryActor): Promise<StoredMemory> {
    // Actor capability check
    let effectiveImportance: MemoryImportance = entry.importance;
    if (effectiveImportance === 'high' && !canSetHighImportance(actor)) {
      log.warn('importance downgrade: actor lacks memory:high capability', {
        userId,
        from: 'high',
        to: 'medium',
      });
      effectiveImportance = 'medium';
    }

    // Single-pass: collect live count + high count simultaneously
    const all = this.store.get(userId) ?? [];
    let liveCount = 0;
    const live: StoredMemory[] = [];
    for (const m of all) {
      if (!m.isDeleted) {
        live.push(m);
        liveCount++;
      }
    }

    // Per-scope high-importance cap check (use incremental cache)
    if (effectiveImportance === 'high') {
      const currentHigh = this.highCount.get(userId) ?? 0;
      if (currentHigh >= this.maxHighImportancePerScope) {
        const err = Object.assign(
          new Error(
            `[InMemoryStore] high-importance cap exceeded: scope "${userId}" already holds ` +
            `${currentHigh} high-importance entries (cap: ${this.maxHighImportancePerScope})`,
          ),
          {
            code: CHARIOT_ERROR_CODES.HIGH_IMPORTANCE_CAP_EXCEEDED as ChariotErrorCode,
            userId,
            cap: this.maxHighImportancePerScope,
          },
        );
        return Promise.reject(err);
      }
    }

    // Capacity cap + eviction
    if (liveCount >= this.maxEntriesPerScope) {
      this._evictOne(userId, live);
    }

    // Insert
    const memory: StoredMemory = {
      ...entry,
      importance: effectiveImportance,
      id: randomUUID(),
      userId,
      createdAt: new Date(),
      accessCount: 0,
      lastAccessed: null,
      isDeleted: false,
    };

    all.push(memory);
    this.store.set(userId, all);

    // Index for O(1) lookup
    this.idIndex.set(memory.id, { userId, entry: memory });

    // Update high-count cache
    if (effectiveImportance === 'high') {
      this.highCount.set(userId, (this.highCount.get(userId) ?? 0) + 1);
    }

    return Promise.resolve(memory);
  }

  // -------------------------------------------------------------------------
 // recall() — READ-ONLY
  // -------------------------------------------------------------------------

  /**
   * Retrieve stored memories.
   *
 * This method is purely read-only. It does NOT mutate accessCount,
   * lastAccessed, or importance. Callers that want access tracking must call
   * recordAccess() explicitly. Importance promotion must go through
   * promoteImportance().
   */
  recall(userId: string, options: RecallOptions): Promise<StoredMemory[]> {
    let memories = this._liveEntries(userId);

    // Filter by type
    if (options.type) {
      memories = memories.filter(m => m.type === options.type);
    }

    // Filter by importance
    if (options.importance) {
      memories = memories.filter(m => m.importance === options.importance);
    }

    // Filter by date
    if (options.since) {
      const since = options.since instanceof Date ? options.since : new Date(options.since);
      memories = memories.filter(m => m.createdAt >= since);
    }

    // Sort — operates on a shallow copy to avoid mutating store order
    const sorted = memories.slice();
    switch (options.sortBy) {
      case 'importance':
        sorted.sort((a, b) => importanceRank(b.importance) - importanceRank(a.importance));
        break;
      case 'recency':
        sorted.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
        break;
      case 'frequency':
        sorted.sort((a, b) => b.accessCount - a.accessCount);
        break;
      default:
        sorted.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    }

    const limit = options.limit ?? 10;
    const result = sorted.slice(0, limit);

    // Return shallow copies so callers cannot mutate stored state by accident
    return Promise.resolve(result.map(m => ({ ...m })));
  }

  // -------------------------------------------------------------------------
 // recordAccess() — explicit access tracking
  // -------------------------------------------------------------------------

  /**
   * Increment accessCount and set lastAccessed on the stored entry.
   * No-op when the entry does not exist or is soft-deleted.
   *
 * This is the ONLY path that may mutate accessCount / lastAccessed.
   */
  recordAccess(memoryId: string): Promise<void> {
    const ref = this.idIndex.get(memoryId);
    if (!ref || ref.entry.isDeleted) return Promise.resolve();

    ref.entry.accessCount++;
    ref.entry.lastAccessed = new Date();
    return Promise.resolve();
  }

  // -------------------------------------------------------------------------
 // promoteImportance() — explicit tier mutation (/ )
  // -------------------------------------------------------------------------

  /**
   * Explicitly change the importance tier of a stored memory.
   *
 * The ONLY path that may mutate importance.
 * Promotion to 'high' is subject to MAX_HIGH_IMPORTANCE_PER_SCOPE.
   *   If the scope is at cap, rejects with { code: 'HIGH_IMPORTANCE_CAP_EXCEEDED' }.
   */
  promoteImportance(memoryId: string, newImportance: MemoryImportance): Promise<void> {
    const ref = this.idIndex.get(memoryId);
    if (!ref || ref.entry.isDeleted) return Promise.resolve();

    const prevImportance = ref.entry.importance;

    if (newImportance === 'high' && prevImportance !== 'high') {
      const userId = ref.userId;
      const currentHigh = this.highCount.get(userId) ?? 0;
      if (currentHigh >= this.maxHighImportancePerScope) {
        const err = Object.assign(
          new Error(
            `[InMemoryStore] high-importance cap exceeded on promoteImportance: ` +
            `scope "${userId}" already holds ${currentHigh} high-importance entries ` +
            `(cap: ${this.maxHighImportancePerScope})`,
          ),
          {
            code: CHARIOT_ERROR_CODES.HIGH_IMPORTANCE_CAP_EXCEEDED as ChariotErrorCode,
            userId,
            cap: this.maxHighImportancePerScope,
          },
        );
        return Promise.reject(err);
      }
    }

    ref.entry.importance = newImportance;

    // Update high-count cache incrementally
    const userId = ref.userId;
    if (prevImportance === 'high' && newImportance !== 'high') {
      this.highCount.set(userId, Math.max(0, (this.highCount.get(userId) ?? 0) - 1));
    } else if (prevImportance !== 'high' && newImportance === 'high') {
      this.highCount.set(userId, (this.highCount.get(userId) ?? 0) + 1);
    }

    return Promise.resolve();
  }

  // -------------------------------------------------------------------------
 // getCapacityStatus() — ops visibility
  // -------------------------------------------------------------------------

  /**
   * Returns live capacity metrics for a userId scope.
   * nearCap = true when entries >= 90% of cap.
   */
  getCapacityStatus(userId: string): Promise<CapacityStatus> {
    const entries = this._liveEntries(userId).length;
    const cap     = this.maxEntriesPerScope;
    return Promise.resolve({
      entries,
      cap,
      nearCap: entries >= Math.floor(cap * 0.9),
    });
  }

  // -------------------------------------------------------------------------
  // context()
  // -------------------------------------------------------------------------

  context(userId: string): Promise<ContextSummary> {
    const memories = this._liveEntries(userId);

    const memoryTypes = new Map<string, number>();
    let lastInteraction: Date | null = null;
    let importantMemories = 0;
    let oldestMemory: Date | null = null;
    let newestMemory: Date | null = null;

    for (const memory of memories) {
      memoryTypes.set(memory.type, (memoryTypes.get(memory.type) ?? 0) + 1);

      if (memory.importance === 'high') importantMemories++;

      if (!lastInteraction || memory.createdAt > lastInteraction) {
        lastInteraction = memory.createdAt;
      }
      if (!oldestMemory || memory.createdAt < oldestMemory) {
        oldestMemory = memory.createdAt;
      }
      if (!newestMemory || memory.createdAt > newestMemory) {
        newestMemory = memory.createdAt;
      }
    }

    return Promise.resolve({
      totalMemories: memories.length,
      memoryTypes,
      lastInteraction,
      importantMemories,
      oldestMemory,
      newestMemory,
    });
  }

  // -------------------------------------------------------------------------
  // delete()
  // -------------------------------------------------------------------------

  delete(userId: string, memoryId: string): Promise<void> {
    const memories = this.store.get(userId);
    if (!memories) return Promise.resolve();

    const memory = memories.find(m => m.id === memoryId);
    if (memory && !memory.isDeleted) {
      memory.isDeleted = true;
      memory.deletedAt = new Date();
      // Update high-count cache if we just soft-deleted a high entry
      if (memory.importance === 'high') {
        this.highCount.set(userId, Math.max(0, (this.highCount.get(userId) ?? 0) - 1));
      }
    }
    return Promise.resolve();
  }

  // -------------------------------------------------------------------------
  // clear() — for testing
  // -------------------------------------------------------------------------

  /**
   * Clear all stored memories and the id index. For testing only.
   */
  clear(): void {
    this.store.clear();
    this.idIndex.clear();
    this.highCount.clear();
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /** Return all non-deleted entries for a userId scope. */
  private _liveEntries(userId: string): StoredMemory[] {
    return (this.store.get(userId) ?? []).filter(m => !m.isDeleted);
  }

  /**
   * Evict the single entry with the lowest importance-then-oldest createdAt.
 * Emits a structured audit warning on every eviction.
   *
   * Importance eviction order: normal (or lower) → medium → high (last resort).
   * Within a tier, the oldest entry (smallest createdAt) is evicted first.
   *
   * Linear scan O(n) — no sort.
   */
  private _evictOne(userId: string, live: StoredMemory[]): void {
    if (live.length === 0) return;

    // Linear scan for the entry with the lowest (importanceRank, createdAt)
    let victim = live[0];
    let victimRank = importanceRank(victim.importance);
    let victimTime = victim.createdAt.getTime();

    for (let i = 1; i < live.length; i++) {
      const m = live[i];
      const rank = importanceRank(m.importance);
      const time = m.createdAt.getTime();
      if (rank < victimRank || (rank === victimRank && time < victimTime)) {
        victim = m;
        victimRank = rank;
        victimTime = time;
      }
    }

    victim.isDeleted = true;
    victim.deletedAt = new Date();

    // Update high-count cache if a high-importance entry was evicted
    if (victim.importance === 'high') {
      this.highCount.set(userId, Math.max(0, (this.highCount.get(userId) ?? 0) - 1));
    }

    log.warn('eviction: scope reached cap', {
      userId,
      cap: this.maxEntriesPerScope,
      evictedId: victim.id,
      evictedImportance: victim.importance,
      evictedCreatedAt: victim.createdAt.toISOString(),
    });
  }
}
