/**
 * @epicai/chariot — Per-Tenant Token-Bucket Rate Limiter
 * Standalone guard module.
 * Re-exposes the token-bucket primitives from toolHandlers as a class so
 * eval-30 and eval-31 (and any future module that needs a self-contained
 * PerTenantRateLimiter instance) can import from this path.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

interface Bucket {
  tokens: number;
  lastRefillMs: number;
  capacity: number;
  refillPerMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  status?: number;
  statusCode?: number;
  error?: string;
  retryAfterMs?: number;
}

export interface PerTenantRateLimiterOptions {
  /** Maximum requests allowed per window. */
  maxRequests: number;
  /** Window length in milliseconds (token-refill period). */
  windowMs: number;
}

/**
 * Per-tenant token-bucket rate limiter (in-memory).
 * Instantiate one per logical scope (server instance, test run, etc.).
 * Each call to allow() atomically refills and consumes one token.
 */
export class PerTenantRateLimiter {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private readonly buckets: Map<string, Bucket> = new Map();

  constructor(opts: PerTenantRateLimiterOptions) {
    this.maxRequests = Math.max(1, opts.maxRequests);
    this.windowMs = Math.max(1, opts.windowMs);
  }

  allow(tenantId: string): RateLimitResult {
    const now = Date.now();
    const capacity = this.maxRequests;
    const refillPerMs = capacity / this.windowMs;

    let bucket = this.buckets.get(tenantId);
    if (!bucket) {
      bucket = { tokens: capacity, lastRefillMs: now, capacity, refillPerMs };
      this.buckets.set(tenantId, bucket);
    } else {
      const elapsed = now - bucket.lastRefillMs;
      if (elapsed > 0) {
        bucket.tokens = Math.min(capacity, bucket.tokens + elapsed * refillPerMs);
        bucket.lastRefillMs = now;
      }
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true };
    }

    const deficit = 1 - bucket.tokens;
    const retryAfterMs = Math.ceil(deficit / refillPerMs);
    return {
      allowed: false,
      status: 429,
      statusCode: 429,
      error: `Rate limit exceeded for tenant "${tenantId}". Retry after ${retryAfterMs} ms.`,
      retryAfterMs,
    };
  }

  /** Test helper: reset all buckets. */
  reset(): void {
    this.buckets.clear();
  }
}
