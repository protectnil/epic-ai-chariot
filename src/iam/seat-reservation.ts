/**
 * Redis-backed seat reservation store.
 *
 * Closes the read-then-check race in seatLimitMiddleware: between the
 * activeUsers count and the downstream session-create persist, two
 * concurrent signups against a limit-of-K-1 capacity could both pass
 * the gate. The reservation slot, set atomically via Redis SET NX EX,
 * counts toward the seat tally until either the real session lands or
 * the 5s TTL expires.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { getRedisClient } from './redis.js';
import type { SeatReservationStore } from './middleware.js';

const RESERVATION_KEY_PREFIX = 'iam:seat-reservation:';

/**
 * Production SeatReservationStore that writes the reservation entry as
 * a Redis key with TTL. `reserve()` uses `SET ... NX EX` so two
 * concurrent calls with the same nonce cannot both win (cryptographic
 * collision aside). `count()` returns the number of live reservation
 * keys via `SCAN` so it is non-blocking even at thousands of slots.
 */
export const redisSeatReservationStore: SeatReservationStore = {
  async reserve(nonce: string, ttlSec: number): Promise<boolean> {
    try {
      const r = await getRedisClient();
      const key = RESERVATION_KEY_PREFIX + nonce;
      // node-redis v4 returns 'OK' on success, null on NX-miss.
      // Some test mocks supply a minimal client without NX support — when
      // set() doesn't accept the options object the call throws; treat
      // that as "no reservation backing" and let the caller proceed
      // without the atomic claim. Production redis ALWAYS supports NX.
      const result = await (r as unknown as {
        set(k: string, v: string, opts: { NX: true; EX: number }): Promise<string | null>;
      }).set(key, '1', { NX: true, EX: ttlSec });
      return result === 'OK';
    } catch {
      // Backend unavailable (or mock without NX) — fail-OPEN at this
      // ring so the middleware degrades to its legacy read-then-check
      // semantics. The seat-limit comparison ran fine; we just lose
      // the atomic-claim race-close on this call.
      return true;
    }
  },
  async count(): Promise<number> {
    try {
      const r = await getRedisClient();
      // Defensive: not every Redis client exposes scan() identically.
      // node-redis v4 returns `{ cursor, keys }`; some test mocks have
      // no scan() at all. In those cases the reservation count is
      // simply unknown — return 0 so seatLimitMiddleware uses the
      // legacy read-then-check behavior rather than throwing 500.
      const scanFn = (r as unknown as { scan?: (cursor: string, opts: { MATCH: string; COUNT: number }) => Promise<{ cursor: string; keys: string[] }> }).scan;
      if (typeof scanFn !== 'function') return 0;
      let cursor = 0;
      let total = 0;
      do {
        const reply = await scanFn.call(r, String(cursor), {
          MATCH: RESERVATION_KEY_PREFIX + '*',
          COUNT: 100,
        });
        cursor = Number(reply.cursor);
        total += reply.keys.length;
      } while (cursor !== 0);
      return total;
    } catch {
      return 0;
    }
  },
};
