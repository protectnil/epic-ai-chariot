/**
 * @epicai/chariot — Rate Limiter
 * Protects MCP servers from agent flooding and prevents runaway loops.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { ObservabilityInfoSink } from '../types/index.js';

export interface RateLimitConfig {
  /** Max requests per window */
  maxRequests: number;
  /** Window duration in milliseconds */
  windowMs: number;
  /** Per-server limits (overrides global) */
  perServer?: Record<string, { maxRequests: number; windowMs: number }>;
}

/**
 * §8.7 — token-bucket state. A fixed window cannot refill mid-window: it
 * grants `maxRequests` then nothing until the window flips. A token bucket
 * refills continuously at `maxRequests / windowMs` tokens per ms, so capacity
 * returns smoothly and a burst is absorbed up to the bucket's capacity.
 */
interface BucketState {
  tokens: number;
  lastRefillAt: number;
}

/**
 * Opt-in test seam. Refill arithmetic is a pure function of elapsed time, but
 * the clock it reads is not injectable through the public methods, so the
 * non-monotonic-clock behaviour §8.7 depends on cannot otherwise be exercised.
 * Omitting this leaves the production path on Date.now(), unchanged.
 */
export interface RateLimiterSeams {
  now?: () => number;
  /**
   * CHARIOT::§8.12::1 — optional ObservabilityEmitter (or any
   * ObservabilityInfoSink-structural equivalent) so the resilience layer
   * emits through it, per "the orchestrator, federation, autonomy, and
   * resilience layers all emit through it." Omitted: no emission (default-
   * disabled, matching the other layers' optional-emitter convention).
   */
  emitter?: ObservabilityInfoSink;
}

export class RateLimiter {
  private readonly global: { maxRequests: number; windowMs: number };
  private readonly perServer: Record<string, { maxRequests: number; windowMs: number }>;
  private readonly buckets = new Map<string, BucketState>();
  private readonly now: () => number;
  private readonly emitter?: ObservabilityInfoSink;

  constructor(config: RateLimitConfig, seams: RateLimiterSeams = {}) {
    this.global = { maxRequests: config.maxRequests, windowMs: config.windowMs };
    this.perServer = config.perServer ?? {};
    this.now = seams.now ?? (() => Date.now());
    this.emitter = seams.emitter;
  }

  /**
   * Bring a server's bucket up to date at `now`, capped at bucket capacity.
   * Returns the effective limits and the (mutable) bucket state.
   */
  private refill(server: string, now: number): {
    limits: { maxRequests: number; windowMs: number };
    state: BucketState;
  } {
    const limits = this.perServer[server] ?? this.global;
    const refillRate = limits.maxRequests / limits.windowMs;
    let state = this.buckets.get(server);

    if (!state) {
      state = { tokens: limits.maxRequests, lastRefillAt: now };
    } else {
      // A backward clock jump must never drain the bucket or rewind the refill
      // anchor: clamp elapsed at zero so regression is a no-op refill, and keep
      // the later of the two timestamps as the new anchor.
      const elapsedMs = Math.max(0, now - state.lastRefillAt);
      state = {
        tokens: Math.min(limits.maxRequests, state.tokens + elapsedMs * refillRate),
        lastRefillAt: Math.max(state.lastRefillAt, now),
      };
    }

    this.buckets.set(server, state);
    return { limits, state };
  }

  /**
   * Check if a request to the given server is allowed.
   * Returns true if allowed (consuming a token), false if rate limited.
   */
  allow(server: string): boolean {
    const { state } = this.refill(server, this.now());

    if (state.tokens < 1) {
      // CHARIOT::§8.12::1 emit site — resilience-layer back-pressure signal.
      this.emitter?.info('rate_limit_exceeded', { server, remaining: 0 }, 'resilience');
      return false;
    }

    state.tokens -= 1;
    return true;
  }

  /**
   * Wait until a token is available. Resolves once one has refilled.
   * Throws if the wait would exceed maxWaitMs.
   */
  async waitForAllowance(server: string, maxWaitMs: number = 30000): Promise<void> {
    if (this.allow(server)) return;

    const now = this.now();
    const { limits, state } = this.refill(server, now);
    const refillRate = limits.maxRequests / limits.windowMs;
    const waitMs = Math.ceil((1 - state.tokens) / refillRate);

    if (waitMs > maxWaitMs) {
      throw new Error(`Rate limit exceeded for server "${server}". Would need to wait ${waitMs}ms (max: ${maxWaitMs}ms)`);
    }

    await new Promise(resolve => setTimeout(resolve, waitMs));

    if (!this.allow(server)) {
      throw new Error(`Rate limiter failed to refill a token for server "${server}"`);
    }
  }

  /**
   * §8.7::5 — CHARIOT-SPEC.md:781: "`RateLimiter.ts` — per-server token
   * bucket. Used by federation to back-pressure adapter calls when an
   * upstream returns 429." Also CHARIOT-SPEC.md:728: "An LLM that generates
   * a high-volume tool-call loop is back-pressured by the token bucket."
   *
   * Called by FederationManager when a dispatch to `server` comes back
   * rate-limited. Brings the bucket up to date via the same refill() path
   * as allow()/waitForAllowance() (so the clock-injection seam still
   * governs it), then drains it to zero — the next allow() for `server`
   * fails and the next waitForAllowance() for `server` paces out a full
   * token's worth of refill time before dispatching again. Keyed to
   * `server` only: refill()/this.buckets are per-server, so no other
   * server's bucket is touched.
   */
  penalize(server: string): void {
    const { state } = this.refill(server, this.now());
    state.tokens = 0;
    this.buckets.set(server, state);
    // CHARIOT::§8.12::1 emit site — resilience-layer 429-triggered penalty.
    this.emitter?.info('rate_limiter_penalized', { server }, 'resilience');
  }

  /**
   * Whole tokens currently available for a server, and how long until at least
   * one token has refilled (0 when a request is allowed right now).
   */
  remaining(server: string): { remaining: number; resetsInMs: number } {
    const now = this.now();
    const { limits, state } = this.refill(server, now);
    const refillRate = limits.maxRequests / limits.windowMs;

    return {
      remaining: Math.floor(state.tokens),
      resetsInMs: state.tokens >= 1
        ? 0
        : Math.ceil((1 - state.tokens) / refillRate),
    };
  }

  /**
   * Reset all rate limit buckets.
   */
  reset(): void {
    this.buckets.clear();
  }
}
