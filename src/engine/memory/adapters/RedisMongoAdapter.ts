/**
 * @epicai/chariot — Redis + MongoDB Memory Adapter
 * Redis as read-through cache, MongoDB as durable persistent store.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { randomUUID } from 'node:crypto';
import type { RedisClientType } from 'redis';
import type { MongoClient, Db, Collection } from 'mongodb';
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
import { CHARIOT_ERROR_CODES } from '../../types/index.js';
import { canSetHighImportance } from './InMemoryStore.js';

const log = createLogger('memory.redis-mongo-adapter');

interface RedisMongoConfig {
  redis: {
    host: string;
    port: number;
    password?: string;
    keyPrefix?: string;
  };
  mongo: {
    uri: string;
    db: string;
    collection?: string;
  };
  cacheTTLSeconds?: number;
  maxHighImportancePerScope?: number;
}

/*
 * eslint-disable @typescript-eslint/no-explicit-any —
 * `any` is used for redis, mongo, and db fields because these are optional
 * peer dependencies loaded via dynamic import(). Their types are not
 * available at compile time when the peer dependency is not installed.
 */

/**
 * Production memory adapter using Redis (cache) + MongoDB (durable store).
 *
 * Requires optional peer dependencies:
 *   npm install redis mongodb
 */
export class RedisMongoAdapter implements MemoryStoreAdapter {
  private readonly config: RedisMongoConfig;
  private readonly keyPrefix: string;
  private readonly cacheTTL: number;
  private readonly collectionName: string;
  private readonly maxHighImportancePerScope: number;
  private redis: RedisClientType | null = null;
  private mongo: MongoClient | null = null;
  private db: Db | null = null;
  private connected = false;

  constructor(config: RedisMongoConfig) {
    this.config = config;
    this.keyPrefix = config.redis.keyPrefix ?? 'eai:mem:';
    this.cacheTTL = config.cacheTTLSeconds ?? 3600;
    this.collectionName = config.mongo.collection ?? 'epic_ai_memories';
    this.maxHighImportancePerScope = config.maxHighImportancePerScope ?? 100;
  }

  async connect(): Promise<void> {
    if (this.connected) return;

    try {
      const redisModule = await import('redis');
      this.redis = redisModule.createClient({
        socket: { host: this.config.redis.host, port: this.config.redis.port },
        password: this.config.redis.password,
      }) as RedisClientType;
      await this.redis.connect();
    } catch (err) {
      throw new Error(`Redis connection failed: ${err instanceof Error ? err.message : String(err)}. npm install redis`, { cause: err });
    }

    try {
      const mongoModule = await import('mongodb');
      this.mongo = new mongoModule.MongoClient(this.config.mongo.uri);
      await this.mongo.connect();
      this.db = this.mongo.db(this.config.mongo.db);
    } catch (err) {
      throw new Error(`MongoDB connection failed: ${err instanceof Error ? err.message : String(err)}. npm install mongodb`, { cause: err });
    }

    this.connected = true;
  }

  async save(tenantId: string, userId: string, entry: MemoryEntry, actor?: MemoryActor): Promise<StoredMemory> {
    await this.ensureConnected();

 // Actor capability check (parity with InMemoryStore)
    let effectiveImportance: MemoryImportance = entry.importance;
    if (effectiveImportance === 'high' && !canSetHighImportance(actor)) {
      log.warn('importance downgrade: actor lacks memory:high capability', {
        tenantId,
        userId,
        from: 'high',
        to: 'medium',
      });
      effectiveImportance = 'medium';
    }

 // Per-scope high-importance cap (parity with InMemoryStore).
 // §8.5::1 — the scope is (tenantId, userId); a userId-only count would
 // charge one tenant's cap against another tenant's entries.
    if (effectiveImportance === 'high') {
      const highCount = await this.collection().countDocuments({
        tenantId,
        userId,
        isDeleted: false,
        importance: 'high',
      });
      if (highCount >= this.maxHighImportancePerScope) {
        const err = Object.assign(
          new Error(
            `[RedisMongoAdapter] high-importance cap exceeded: scope "${tenantId}/${userId}" already holds ` +
            `${highCount} high-importance entries (cap: ${this.maxHighImportancePerScope})`,
          ),
          {
            code: CHARIOT_ERROR_CODES.HIGH_IMPORTANCE_CAP_EXCEEDED as ChariotErrorCode,
            tenantId,
            userId,
            cap: this.maxHighImportancePerScope,
          },
        );
        throw err;
      }
    }

    const memory: StoredMemory = {
      ...entry,
      importance: effectiveImportance,
      id: randomUUID(),
      tenantId,
      userId,
      createdAt: new Date(),
      accessCount: 0,
      lastAccessed: null,
      isDeleted: false,
    };

    await this.collection().insertOne(memory);
    await this.invalidateCache(tenantId, userId);
    return memory;
  }

  async recall(tenantId: string, userId: string, options: RecallOptions): Promise<StoredMemory[]> {
    await this.ensureConnected();

    const cacheKey = this.cacheKey(tenantId, userId, options);
    const cached = await this.getCache(cacheKey);
    if (cached) return cached;

    const filter: Record<string, unknown> = { tenantId, userId, isDeleted: false };
    if (options.type) filter['type'] = options.type;
    if (options.importance) filter['importance'] = options.importance;
    if (options.since) filter['createdAt'] = { $gte: options.since };

    let sortField = 'createdAt';
    if (options.sortBy === 'importance') sortField = 'importance';
    if (options.sortBy === 'frequency') sortField = 'accessCount';

    const results: StoredMemory[] = await this.collection()
      .find(filter)
      .sort({ [sortField]: -1 })
      .limit(options.limit ?? 10)
      .toArray();

 // recall() is now read-only. Access tracking must go through
    // recordAccess() and importance promotion through promoteImportance().
    await this.setCache(cacheKey, results, tenantId);
    return results;
  }

  async context(tenantId: string, userId: string): Promise<ContextSummary> {
    await this.ensureConnected();

    const memories: StoredMemory[] = await this.collection()
      .find({ tenantId, userId, isDeleted: false })
      .toArray();

    const memoryTypes = new Map<string, number>();
    let lastInteraction: Date | null = null;
    let importantMemories = 0;
    let oldestMemory: Date | null = null;
    let newestMemory: Date | null = null;

    for (const m of memories) {
      memoryTypes.set(m.type, (memoryTypes.get(m.type) ?? 0) + 1);
      if (m.importance === 'high') importantMemories++;
      const d = m.createdAt instanceof Date ? m.createdAt : new Date(m.createdAt);
      if (!lastInteraction || d > lastInteraction) lastInteraction = d;
      if (!oldestMemory || d < oldestMemory) oldestMemory = d;
      if (!newestMemory || d > newestMemory) newestMemory = d;
    }

    return { totalMemories: memories.length, memoryTypes, lastInteraction, importantMemories, oldestMemory, newestMemory };
  }

  async delete(tenantId: string, userId: string, memoryId: string): Promise<boolean> {
    await this.ensureConnected();
    // Only match live (non-deleted) entries so a bogus id or an
    // already-deleted id truthfully reports no-op, per CH-31
    // (CHARIOT::§23.2::44-45; ::134 names `forget` as a covered surface).
    // CHARIOT::§8.5::1 — tenantId is part of the match so one tenant can never
    // soft-delete another tenant's row by guessing/reusing a memoryId.
    const result = await this.collection().updateOne(
      { id: memoryId, tenantId, userId, isDeleted: false },
      { $set: { isDeleted: true, deletedAt: new Date() } },
    );
    const deleted = result.modifiedCount > 0;
    if (deleted) {
      await this.invalidateCache(tenantId, userId);
    }
    return deleted;
  }

  /**
   * Increment accessCount for the given memoryId in MongoDB.
 * explicit access tracking mutator — recall() must not call this.
   */
  async recordAccess(tenantId: string, memoryId: string): Promise<void> {
    await this.ensureConnected();
    // Fetch the owning userId before the write so we can invalidate the
    // correct per-scope cache slice after the Mongo update commits.
    // §8.5::1 — both the read and the write are tenant-scoped, so a memoryId
    // from one tenant cannot bump access metadata on another tenant's row.
    const entry = await this.collection().findOne(
      { id: memoryId, tenantId, isDeleted: false },
      { projection: { tenantId: 1, userId: 1 } },
    );
    await this.collection().updateOne(
      { id: memoryId, tenantId, isDeleted: false },
      { $inc: { accessCount: 1 }, $set: { lastAccessed: new Date() } },
    );
 // cache invalidation: after mutating accessCount the per-scope
    // recall cache must be dropped so the next recall() returns fresh data.
    if (entry?.userId) {
      await this.invalidateCache(tenantId, entry.userId as string);
    }
  }

  /**
   * Explicitly promote (or demote) the importance tier of a stored memory.
 * / the only path that may mutate importance in this adapter.
   *
 * Promotion to 'high' is subject to MAX_HIGH_IMPORTANCE_PER_SCOPE cap.
   * If the scope is already at capacity for high-importance entries, rejects with
   * { code: 'HIGH_IMPORTANCE_CAP_EXCEEDED' }.
   */
  async promoteImportance(tenantId: string, memoryId: string, newImportance: MemoryImportance): Promise<void> {
    await this.ensureConnected();

    // Get the current entry to check its scope. §8.5::1 — tenant-scoped read.
    const entry = await this.collection().findOne({ id: memoryId, tenantId, isDeleted: false });
    if (!entry) return; // No-op if entry not found, is deleted, or is another tenant's

    // If promoting to 'high' and entry is not already high, check cap
    if (newImportance === 'high' && entry.importance !== 'high') {
      const userId = entry.userId;
      const highCount = await this.collection().countDocuments({
        tenantId,
        userId,
        isDeleted: false,
        importance: 'high',
      });
      if (highCount >= this.maxHighImportancePerScope) {
        const err = Object.assign(
          new Error(
            `[RedisMongoAdapter] high-importance cap exceeded: ` +
            `scope "${tenantId}/${userId}" already holds ${highCount} high-importance entries ` +
            `(cap: ${this.maxHighImportancePerScope})`,
          ),
          {
            code: CHARIOT_ERROR_CODES.HIGH_IMPORTANCE_CAP_EXCEEDED as ChariotErrorCode,
            tenantId,
            userId,
            cap: this.maxHighImportancePerScope,
          },
        );
        throw err;
      }
    }

    await this.collection().updateOne(
      { id: memoryId, tenantId, isDeleted: false },
      { $set: { importance: newImportance } },
    );
 // cache invalidation: after mutating importance the per-scope
    // recall cache must be dropped so the next recall() returns fresh data.
    if (entry?.userId) {
      await this.invalidateCache(tenantId, entry.userId as string);
    }
  }

  /**
   * Return capacity metrics for a (tenantId, userId) scope.
   * MongoDB has no fixed cap — entries and cap are reported as live counts
   * and Infinity respectively. nearCap is always false.
   */
  async getCapacityStatus(tenantId: string, userId: string): Promise<CapacityStatus> {
    await this.ensureConnected();
    const entries = await this.collection().countDocuments({ tenantId, userId, isDeleted: false });
    return { entries, cap: Infinity, nearCap: false };
  }

  async disconnect(): Promise<void> {
    if (this.redis) { await this.redis.disconnect(); this.redis = null; }
    if (this.mongo) { await this.mongo.close(); this.mongo = null; this.db = null; }
    this.connected = false;
  }

  private async ensureConnected(): Promise<void> {
    if (!this.connected) await this.connect();
  }

  private collection(): Collection<StoredMemory> {
    if (!this.db) throw new Error('MongoDB not connected');
    return this.db.collection<StoredMemory>(this.collectionName);
  }

  /**
   * §8.5::1 — the recall cache key is scoped by tenant AND user. A userId-only
   * key let two tenants sharing a userId serve each other's cached rows.
   */
  private cacheKey(tenantId: string, userId: string, options: RecallOptions): string {
    return `${this.keyPrefix}mem:${tenantId}:${userId}:${JSON.stringify(options)}`;
  }

  private async getCache(key: string): Promise<StoredMemory[] | null> {
    if (!this.redis) return null;
    try {
      const data = await this.redis.get(key);
      return data ? JSON.parse(data) as StoredMemory[] : null;
    } catch { return null; }
  }

  private async setCache(key: string, data: StoredMemory[], tenantId: string): Promise<void> {
    if (!this.redis) return;
    try {
      await this.redis.set(key, JSON.stringify(data), { EX: this.cacheTTL });
      // §8.5::1 — track the key in a PER-TENANT set (`mem:keys:{tenantId}`, with
      // the configured keyPrefix) so invalidation never needs a KEYS scan and
      // never spans tenants. The tenant is passed in rather than parsed back out
      // of the key, so the tracking set cannot drift from the key that was set.
      const setKey = `${this.keyPrefix}mem:keys:${tenantId}`;
      await this.redis.sAdd(setKey, key);
      await this.redis.expire(setKey, this.cacheTTL * 2);
    } catch { /* non-fatal */ }
  }

  /**
   * §8.5::1 — invalidate only the (tenantId, userId) slice. The tracking set is
   * per-tenant, so members are filtered down to this user's key prefix before
   * deletion: invalidating one user MUST NOT flush another user's cache, and
   * MUST NOT touch any other tenant at all. Deleted members are removed from
   * the set so it cannot grow unbounded with dead keys.
   */
  private async invalidateCache(tenantId: string, userId: string): Promise<void> {
    if (!this.redis) return;
    try {
      const setKey = `${this.keyPrefix}mem:keys:${tenantId}`;
      const keys: string[] = await this.redis.sMembers(setKey);
      const scopedPrefix = `${this.keyPrefix}mem:${tenantId}:${userId}:`;
      const scopedKeys = keys.filter(k => k.startsWith(scopedPrefix));
      if (scopedKeys.length > 0) {
        await this.redis.del(scopedKeys);
        await this.redis.sRem(setKey, scopedKeys);
      }
    } catch { /* non-fatal */ }
  }
}
