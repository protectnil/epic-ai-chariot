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

  async save(userId: string, entry: MemoryEntry, actor?: MemoryActor): Promise<StoredMemory> {
    await this.ensureConnected();

 // Actor capability check (parity with InMemoryStore)
    let effectiveImportance: MemoryImportance = entry.importance;
    if (effectiveImportance === 'high' && !canSetHighImportance(actor)) {
      log.warn('importance downgrade: actor lacks memory:high capability', {
        userId,
        from: 'high',
        to: 'medium',
      });
      effectiveImportance = 'medium';
    }

 // Per-scope high-importance cap (parity with InMemoryStore)
    if (effectiveImportance === 'high') {
      const highCount = await this.collection().countDocuments({
        userId,
        isDeleted: false,
        importance: 'high',
      });
      if (highCount >= this.maxHighImportancePerScope) {
        const err = Object.assign(
          new Error(
            `[RedisMongoAdapter] high-importance cap exceeded: scope "${userId}" already holds ` +
            `${highCount} high-importance entries (cap: ${this.maxHighImportancePerScope})`,
          ),
          {
            code: CHARIOT_ERROR_CODES.HIGH_IMPORTANCE_CAP_EXCEEDED as ChariotErrorCode,
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
      userId,
      createdAt: new Date(),
      accessCount: 0,
      lastAccessed: null,
      isDeleted: false,
    };

    await this.collection().insertOne(memory);
    await this.invalidateCache(userId);
    return memory;
  }

  async recall(userId: string, options: RecallOptions): Promise<StoredMemory[]> {
    await this.ensureConnected();

    const cacheKey = this.cacheKey(userId, options);
    const cached = await this.getCache(cacheKey);
    if (cached) return cached;

    const filter: Record<string, unknown> = { userId, isDeleted: false };
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
    await this.setCache(cacheKey, results);
    return results;
  }

  async context(userId: string): Promise<ContextSummary> {
    await this.ensureConnected();

    const memories: StoredMemory[] = await this.collection()
      .find({ userId, isDeleted: false })
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

  async delete(userId: string, memoryId: string): Promise<void> {
    await this.ensureConnected();
    await this.collection().updateOne({ id: memoryId, userId }, { $set: { isDeleted: true, deletedAt: new Date() } });
    await this.invalidateCache(userId);
  }

  /**
   * Increment accessCount for the given memoryId in MongoDB.
 * explicit access tracking mutator — recall() must not call this.
   */
  async recordAccess(memoryId: string): Promise<void> {
    await this.ensureConnected();
    // Fetch the owning userId before the write so we can invalidate the
    // correct per-user cache slice after the Mongo update commits.
    const entry = await this.collection().findOne(
      { id: memoryId, isDeleted: false },
      { projection: { userId: 1 } },
    );
    await this.collection().updateOne(
      { id: memoryId, isDeleted: false },
      { $inc: { accessCount: 1 }, $set: { lastAccessed: new Date() } },
    );
 // cache invalidation: after mutating accessCount the per-user
    // recall cache must be dropped so the next recall() returns fresh data.
    if (entry?.userId) {
      await this.invalidateCache(entry.userId as string);
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
  async promoteImportance(memoryId: string, newImportance: MemoryImportance): Promise<void> {
    await this.ensureConnected();

    // Get the current entry to check its scope (userId)
    const entry = await this.collection().findOne({ id: memoryId, isDeleted: false });
    if (!entry) return; // No-op if entry not found or is deleted

    // If promoting to 'high' and entry is not already high, check cap
    if (newImportance === 'high' && entry.importance !== 'high') {
      const userId = entry.userId;
      const highCount = await this.collection().countDocuments({
        userId,
        isDeleted: false,
        importance: 'high',
      });
      if (highCount >= this.maxHighImportancePerScope) {
        const err = Object.assign(
          new Error(
            `[RedisMongoAdapter] high-importance cap exceeded: ` +
            `scope "${userId}" already holds ${highCount} high-importance entries ` +
            `(cap: ${this.maxHighImportancePerScope})`,
          ),
          {
            code: CHARIOT_ERROR_CODES.HIGH_IMPORTANCE_CAP_EXCEEDED as ChariotErrorCode,
            userId,
            cap: this.maxHighImportancePerScope,
          },
        );
        throw err;
      }
    }

    await this.collection().updateOne(
      { id: memoryId, isDeleted: false },
      { $set: { importance: newImportance } },
    );
 // cache invalidation: after mutating importance the per-user
    // recall cache must be dropped so the next recall() returns fresh data.
    if (entry?.userId) {
      await this.invalidateCache(entry.userId as string);
    }
  }

  /**
   * Return capacity metrics for a userId scope.
   * MongoDB has no fixed cap — entries and cap are reported as live counts
   * and Infinity respectively. nearCap is always false.
   */
  async getCapacityStatus(userId: string): Promise<CapacityStatus> {
    await this.ensureConnected();
    const entries = await this.collection().countDocuments({ userId, isDeleted: false });
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

  private cacheKey(userId: string, options: RecallOptions): string {
    return `${this.keyPrefix}${userId}:${JSON.stringify(options)}`;
  }

  private async getCache(key: string): Promise<StoredMemory[] | null> {
    if (!this.redis) return null;
    try {
      const data = await this.redis.get(key);
      return data ? JSON.parse(data) as StoredMemory[] : null;
    } catch { return null; }
  }

  private async setCache(key: string, data: StoredMemory[]): Promise<void> {
    if (!this.redis) return;
    try {
      await this.redis.set(key, JSON.stringify(data), { EX: this.cacheTTL });
      // Track the key in a per-user set so we can invalidate without KEYS scan
      const userId = this.userIdFromKey(key);
      if (userId) {
        const setKey = `${this.keyPrefix}keys:${userId}`;
        await this.redis.sAdd(setKey, key);
        await this.redis.expire(setKey, this.cacheTTL * 2);
      }
    } catch { /* non-fatal */ }
  }

  private async invalidateCache(userId: string): Promise<void> {
    if (!this.redis) return;
    try {
      // Use the per-user tracking set instead of KEYS scan
      const setKey = `${this.keyPrefix}keys:${userId}`;
      const keys: string[] = await this.redis.sMembers(setKey);
      if (keys.length > 0) await this.redis.del(keys);
      await this.redis.del(setKey);
    } catch { /* non-fatal */ }
  }

  /**
   * Extract userId from a cache key of the form `{keyPrefix}{userId}:{options}`.
   */
  private userIdFromKey(key: string): string | null {
    const withoutPrefix = key.slice(this.keyPrefix.length);
    const colonIdx = withoutPrefix.indexOf(':');
    return colonIdx !== -1 ? withoutPrefix.slice(0, colonIdx) : null;
  }
}
