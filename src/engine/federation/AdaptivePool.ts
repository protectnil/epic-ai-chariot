/**
 * @epicai/chariot — Adaptive Connection Pool
 * Per-tenant, burst-aware connection pool for lazy adapter connections.
 * Replaces flat maxConnections with tenant-scoped, load-adaptive limits.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createLogger } from '../logger.js';
import type { MCPAdapter } from './adapters/base.js';

const log = createLogger('federation.pool');

// =============================================================================
// Types
// =============================================================================

export interface AdaptivePoolConfig {
  globalMaxConnections: number;
  perTenantBaseConnections: number;
  perTenantMaxConnections: number;
  burstMultiplier: number;
  burstWindowMs: number;
  evictionPolicy: 'lru' | 'lfu';
  scaleUpThresholdMs: number;
  scaleDownIdleMs: number;
}

export const DEFAULT_POOL_CONFIG: AdaptivePoolConfig = {
  globalMaxConnections: 500,
  perTenantBaseConnections: 20,
  perTenantMaxConnections: 50,
  // §7.3::3 compiled-in defaults: burstMultiplier=2.0, burstWindowMs=60000,
  // scaleUpThresholdMs=250, scaleDownIdleMs=300000.
  burstMultiplier: 2.0,
  burstWindowMs: 60_000,
  evictionPolicy: 'lru',
  scaleUpThresholdMs: 250,
  scaleDownIdleMs: 300_000,
};

export interface PoolStats {
  globalActive: number;
  globalMax: number;
  tenants: Map<string, TenantPoolStats>;
}

export interface TenantPoolStats {
  active: number;
  base: number;
  max: number;
  bursting: boolean;
}

interface PoolEntry {
  adapter: MCPAdapter;
  tenantId: string;
  adapterName: string;
  lastUsedAt: number;
  useCount: number;
  createdAt: number;
}

// =============================================================================
// Pool
// =============================================================================

export class AdaptivePool {
  private readonly config: AdaptivePoolConfig;
  private readonly connections = new Map<string, PoolEntry>();
  private readonly tenantCounts = new Map<string, number>();
  private readonly burstTimers = new Map<string, ReturnType<typeof setTimeout>>();
  /**
   * §7.3::2 — rolling per-tenant connection-wait samples backing the
   * `p95(connectionWait) > scaleUpThresholdMs` scale-up trigger. Retained for
   * exactly one `burstWindowMs`, so the p95 reflects current pressure and a
   * long-past spike cannot keep a tenant in burst forever.
   */
  private readonly connectionWaitSamples = new Map<string, Array<{ at: number; durationMs: number }>>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config?: Partial<AdaptivePoolConfig>) {
    this.config = { ...DEFAULT_POOL_CONFIG, ...config };
    this.startCleanup();
  }

  // ---------------------------------------------------------------------------
  // Acquire / Release
  // ---------------------------------------------------------------------------

  private key(tenantId: string, adapterName: string): string {
    return `${tenantId}:${adapterName}`;
  }

  /**
   * Acquire an adapter connection. If already connected, returns existing.
   * If not, calls the factory to create one.
   * Throws if tenant or global limits are exceeded.
   */
  async acquire(
    tenantId: string,
    adapterName: string,
    factory: () => Promise<MCPAdapter>,
  ): Promise<MCPAdapter> {
    const k = this.key(tenantId, adapterName);
    // §7.3::2 — wall-clock wait this caller experienced to obtain a connection.
    // Sampled on BOTH paths: a pool under pressure spends its time in eviction
    // and factory construction, and measuring only the slow path would bias the
    // p95 upward and burst a pool that is actually healthy.
    const waitStart = Date.now();

    // Already connected — return existing
    const existing = this.connections.get(k);
    if (existing) {
      existing.lastUsedAt = Date.now();
      existing.useCount++;
      this.recordConnectionWait(tenantId, Date.now() - waitStart);
      return existing.adapter;
    }

    // Check global limit
    if (this.connections.size >= this.config.globalMaxConnections) {
      // Try to evict an idle connection globally
      const evicted = this.evictOne();
      if (!evicted) {
        throw new Error(`Global connection limit reached (${this.config.globalMaxConnections})`);
      }
    }

    // Check per-tenant limit
    const tenantCount = this.tenantCounts.get(tenantId) ?? 0;
    const tenantMax = this.effectiveTenantMax(tenantId);
    if (tenantCount >= tenantMax) {
      // Try to evict within this tenant
      const evicted = this.evictOneForTenant(tenantId);
      if (!evicted) {
        throw new Error(`Tenant ${tenantId} connection limit reached (${tenantMax})`);
      }
    }

    // Create new connection
    const adapter = await factory();
    const entry: PoolEntry = {
      adapter,
      tenantId,
      adapterName,
      lastUsedAt: Date.now(),
      useCount: 1,
      createdAt: Date.now(),
    };

    this.connections.set(k, entry);
    this.tenantCounts.set(tenantId, (this.tenantCounts.get(tenantId) ?? 0) + 1);

    this.recordConnectionWait(tenantId, Date.now() - waitStart);
    log.debug('connection acquired', { tenantId, adapterName, globalActive: this.connections.size });
    return adapter;
  }

  /**
   * §7.3::2 — append a connection-wait sample and drop everything older than
   * one burst window.
   */
  private recordConnectionWait(tenantId: string, durationMs: number): void {
    const now = Date.now();
    const samples = this.connectionWaitSamples.get(tenantId) ?? [];
    samples.push({ at: now, durationMs });

    const cutoff = now - this.config.burstWindowMs;
    while (samples.length > 0 && samples[0].at < cutoff) {
      samples.shift();
    }

    this.connectionWaitSamples.set(tenantId, samples);
  }

  /**
   * §7.3::2 — p95 of the in-window connection waits for a tenant. Returns 0
   * when there is no traffic, so an idle tenant never trips the scale-up
   * threshold.
   */
  connectionWaitP95(tenantId: string): number {
    const samples = this.connectionWaitSamples.get(tenantId) ?? [];
    if (samples.length === 0) return 0;

    const values = samples.map((s) => s.durationMs).sort((a, b) => a - b);
    const index = Math.min(values.length - 1, Math.ceil(values.length * 0.95) - 1);
    return values[Math.max(0, index)];
  }

  /**
   * Release a connection back to the pool. Does not disconnect —
   * connection stays in pool for reuse until evicted or idle-cleaned.
   */
  release(tenantId: string, adapterName: string): void {
    const k = this.key(tenantId, adapterName);
    const entry = this.connections.get(k);
    if (entry) {
      entry.lastUsedAt = Date.now();
    }
  }

  /**
   * Force-disconnect and remove a specific connection.
   */
  async remove(tenantId: string, adapterName: string): Promise<void> {
    const k = this.key(tenantId, adapterName);
    const entry = this.connections.get(k);
    if (!entry) return;

    try {
      await entry.adapter.disconnect();
    } catch {
      // Ignore disconnect errors
    }

    this.connections.delete(k);
    const count = (this.tenantCounts.get(tenantId) ?? 1) - 1;
    if (count <= 0) {
      this.tenantCounts.delete(tenantId);
    } else {
      this.tenantCounts.set(tenantId, count);
    }
  }

  // ---------------------------------------------------------------------------
  // Burst
  // ---------------------------------------------------------------------------

  /**
   * Enable burst mode for a tenant. Allows up to burstMultiplier × base
   * connections for the burst window duration.
   */
  enableBurst(tenantId: string): void {
    if (this.burstTimers.has(tenantId)) return; // Already bursting

    log.debug('burst enabled', { tenantId, window: this.config.burstWindowMs });

    const timer = setTimeout(() => {
      this.burstTimers.delete(tenantId);
      log.debug('burst window expired', { tenantId });
    }, this.config.burstWindowMs);

    if (typeof timer === 'object' && 'unref' in timer) {
      timer.unref();
    }
    this.burstTimers.set(tenantId, timer);
  }

  private effectiveTenantMax(tenantId: string): number {
    if (this.burstTimers.has(tenantId)) {
      return Math.min(
        Math.floor(this.config.perTenantBaseConnections * this.config.burstMultiplier),
        this.config.perTenantMaxConnections,
      );
    }
    return this.config.perTenantBaseConnections;
  }

  // ---------------------------------------------------------------------------
  // Eviction
  // ---------------------------------------------------------------------------

  private evictOne(): boolean {
    const target = this.findEvictionTarget();
    if (!target) return false;

    const entry = this.connections.get(target);
    if (!entry) return false;
    log.debug('evicting connection', { key: target, tenant: entry.tenantId, adapter: entry.adapterName });

    // Fire-and-forget disconnect
    entry.adapter.disconnect().catch(() => { /* intentionally empty */ });
    this.connections.delete(target);
    const count = (this.tenantCounts.get(entry.tenantId) ?? 1) - 1;
    if (count <= 0) {
      this.tenantCounts.delete(entry.tenantId);
    } else {
      this.tenantCounts.set(entry.tenantId, count);
    }

    return true;
  }

  private evictOneForTenant(tenantId: string): boolean {
    const target = this.findEvictionTargetForTenant(tenantId);
    if (!target) return false;

    const entry = this.connections.get(target);
    if (!entry) return false;
    entry.adapter.disconnect().catch(() => { /* intentionally empty */ });
    this.connections.delete(target);
    const count = (this.tenantCounts.get(tenantId) ?? 1) - 1;
    if (count <= 0) {
      this.tenantCounts.delete(tenantId);
    } else {
      this.tenantCounts.set(tenantId, count);
    }

    return true;
  }

  private findEvictionTarget(): string | null {
    if (this.config.evictionPolicy === 'lfu') {
      return this.findLFU();
    }
    return this.findLRU();
  }

  private findEvictionTargetForTenant(tenantId: string): string | null {
    let oldest: { key: string; value: number } | null = null;

    for (const [key, entry] of this.connections) {
      if (entry.tenantId !== tenantId) continue;

      const metric = this.config.evictionPolicy === 'lfu' ? entry.useCount : entry.lastUsedAt;
      if (!oldest || metric < oldest.value) {
        oldest = { key, value: metric };
      }
    }

    return oldest?.key ?? null;
  }

  // TODO REUSE #10: this O(n) sweep duplicates the LRU eviction pattern in
  // toolHandlers.ts (now unified through PromptCache<T>) and a third copy in
  // AdapterCatalog's eviction path. Migrate this.connections to
  // PromptCache<ConnectionEntry> from src/engine/resilience/PromptCache.ts
  // so the eviction logic lives in one place. The `evictLRU()` method on
  // PromptCache is a direct replacement for findLRU() + the delete call.
  private findLRU(): string | null {
    let oldest: { key: string; lastUsed: number } | null = null;
    for (const [key, entry] of this.connections) {
      if (!oldest || entry.lastUsedAt < oldest.lastUsed) {
        oldest = { key, lastUsed: entry.lastUsedAt };
      }
    }
    return oldest?.key ?? null;
  }

  private findLFU(): string | null {
    let least: { key: string; count: number } | null = null;
    for (const [key, entry] of this.connections) {
      if (!least || entry.useCount < least.count) {
        least = { key, count: entry.useCount };
      }
    }
    return least?.key ?? null;
  }

  // ---------------------------------------------------------------------------
  // Idle Cleanup
  // ---------------------------------------------------------------------------

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();

      // §7.3::2 — scale UP on p95(connectionWait) > scaleUpThresholdMs, before
      // the idle scale-down below. Scaling up means entering burst: the tenant
      // ceiling rises from perTenantBaseConnections to
      // min(base * burstMultiplier, perTenantMaxConnections) for one
      // burstWindowMs (enableBurst re-arms its own expiry timer).
      for (const tenantId of this.tenantCounts.keys()) {
        const p95 = this.connectionWaitP95(tenantId);
        if (p95 > this.config.scaleUpThresholdMs) {
          this.enableBurst(tenantId);
          log.debug('pool scaled up on connection-wait p95', {
            tenantId,
            p95ConnectionWaitMs: p95,
            thresholdMs: this.config.scaleUpThresholdMs,
          });
        }
      }

      const toRemove: string[] = [];

      for (const [key, entry] of this.connections) {
        if (now - entry.lastUsedAt > this.config.scaleDownIdleMs) {
          toRemove.push(key);
        }
      }

      for (const key of toRemove) {
        const entry = this.connections.get(key);
        if (!entry) continue;
        log.debug('idle cleanup', { key, tenant: entry.tenantId, adapter: entry.adapterName });
        entry.adapter.disconnect().catch(() => { /* intentionally empty */ });
        this.connections.delete(key);
        const count = (this.tenantCounts.get(entry.tenantId) ?? 1) - 1;
        if (count <= 0) {
          this.tenantCounts.delete(entry.tenantId);
          // §7.3::2 — the tenant has no connections left; drop its wait-sample
          // window so an idle tenant's samples cannot accumulate unbounded.
          this.connectionWaitSamples.delete(entry.tenantId);
        } else {
          this.tenantCounts.set(entry.tenantId, count);
        }
      }
    }, 30_000);

    if (this.cleanupTimer && typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
      this.cleanupTimer.unref();
    }
  }

  // ---------------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------------

  stats(): PoolStats {
    const tenants = new Map<string, TenantPoolStats>();

    for (const [tenantId, count] of this.tenantCounts) {
      tenants.set(tenantId, {
        active: count,
        base: this.config.perTenantBaseConnections,
        max: this.effectiveTenantMax(tenantId),
        bursting: this.burstTimers.has(tenantId),
      });
    }

    return {
      globalActive: this.connections.size,
      globalMax: this.config.globalMaxConnections,
      tenants,
    };
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  async shutdown(): Promise<void> {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    for (const timer of this.burstTimers.values()) {
      clearTimeout(timer);
    }
    this.burstTimers.clear();

    for (const [, entry] of this.connections) {
      try {
        await entry.adapter.disconnect();
      } catch {
        // Ignore
      }
    }

    this.connections.clear();
    this.tenantCounts.clear();
  }
}
