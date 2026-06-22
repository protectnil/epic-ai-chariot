/**
 * IAM — ID-JAG JTI replay cache.
 *
 * Atomic JTI reservation backed by Redis SET key value NX EX ttl. Plan
 * §275, §114 + plan adversarial fix #8. The `NX` flag guarantees
 * atomicity — `reserve()` returns true on first sight and false on
 * replay collision, with no read-modify-write window between the check
 * and the write.
 *
 * The Redis client is the same one session.ts uses; injected at
 * enterprise bootstrap.
 */

import type { RedisClientType } from 'redis';
import type { JtiCachePort } from './id-jag-validator.js';

let _redis: RedisClientType | null = null;

/**
 * Bootstrap injection. Mirrors session.ts:setRedisClient. Called once
 * during enterprise bootstrap before any token-exchange request lands.
 */
export function setRedisClient(client: RedisClientType): void {
  _redis = client;
}

function getRedis(): RedisClientType {
  if (!_redis) {
    throw new Error(
      'JTI replay cache: Redis client not initialized. ' +
      'Call setRedisClient() during enterprise bootstrap before validating ID-JAG assertions.',
    );
  }
  return _redis;
}

// Namespace prefix keeps the JTI cache separate from session.ts's key
// space. Format: `id_jag:jti:<iss>:<jti>`. The `iss` segment prevents
// jti collisions between different IdPs that happen to mint the same
// uuid; jti uniqueness in the OAuth 2.0 spec is scoped per issuer.
const KEY_PREFIX = 'id_jag:jti:';

function keyFor(iss: string, jti: string): string {
  return `${KEY_PREFIX}${iss}:${jti}`;
}

export const jtiReplayCache: JtiCachePort = {
  async reserve(iss, jti, ttlSeconds) {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
      throw new Error(
        `jti reserve: ttlSeconds must be a positive integer, got ${ttlSeconds}`,
      );
    }
    const redis = getRedis();
    // Node redis v5 SET options: { NX: true, EX: seconds }. The return
    // value is 'OK' on first write and null when NX prevented the write.
    const result = await redis.set(keyFor(iss, jti), '1', { NX: true, EX: ttlSeconds });
    return result === 'OK';
  },
  async reserveOrMatch(iss, jti, assertionHash, ttlSeconds) {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
      throw new Error(
        `jti reserveOrMatch: ttlSeconds must be a positive integer, got ${ttlSeconds}`,
      );
    }
    if (typeof assertionHash !== 'string' || assertionHash.length === 0) {
      throw new Error('jti reserveOrMatch: assertionHash must be a non-empty string');
    }
    const redis = getRedis();
    const key = keyFor(iss, jti);
    // Atomic compare-and-set via Lua. The earlier two-command form
    // (SET NX + fallback GET) had a TOCTOU window: if the key expired
    // between the NX-fail and the GET, GET returned nil and we
    // returned 'replay' for a spec-conformant §4.4.3 re-submission.
    // The Lua script collapses both steps into one Redis-side
    // transaction so expiry can never race the read.
    //   - Key absent  → SET key hash EX ttl → return 'first-sight'.
    //   - Key present + same hash → return 'match' (no TTL extension).
    //   - Key present + different hash → return 'replay'.
    const result = await redis.eval(
      RESERVE_OR_MATCH_LUA,
      { keys: [key], arguments: [assertionHash, String(ttlSeconds)] },
    );
    if (result === 'first-sight' || result === 'match' || result === 'replay') {
      return result;
    }
    throw new Error(`jti reserveOrMatch: unexpected Lua reply ${JSON.stringify(result)}`);
  },
};

// Lua script — atomic on the Redis server. KEYS[1]=jti key,
// ARGV[1]=assertionHash, ARGV[2]=ttl seconds (as string).
const RESERVE_OR_MATCH_LUA = `
local existing = redis.call('GET', KEYS[1])
if not existing then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
  return 'first-sight'
end
if existing == ARGV[1] then
  return 'match'
end
return 'replay'
`;

/**
 * Test seam: a pure in-memory implementation suitable for unit tests
 * that exercise the validator's port contract without a live Redis.
 * Production code consumes `jtiReplayCache` above.
 */
export function buildInMemoryJtiCache(): JtiCachePort & { size(): number } {
  const seen = new Map<string, { expiresAt: number; assertionHash?: string }>();
  return {
    async reserve(iss, jti, ttlSeconds) {
      if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
        throw new Error(
          `jti reserve: ttlSeconds must be a positive integer, got ${ttlSeconds}`,
        );
      }
      const now = Date.now();
      const k = keyFor(iss, jti);
      const existing = seen.get(k);
      if (existing !== undefined && existing.expiresAt > now) {
        return false;
      }
      seen.set(k, { expiresAt: now + ttlSeconds * 1000 });
      return true;
    },
    async reserveOrMatch(iss, jti, assertionHash, ttlSeconds) {
      if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
        throw new Error(
          `jti reserveOrMatch: ttlSeconds must be a positive integer, got ${ttlSeconds}`,
        );
      }
      if (typeof assertionHash !== 'string' || assertionHash.length === 0) {
        throw new Error('jti reserveOrMatch: assertionHash must be a non-empty string');
      }
      const now = Date.now();
      const k = keyFor(iss, jti);
      const existing = seen.get(k);
      if (existing === undefined || existing.expiresAt <= now) {
        seen.set(k, { expiresAt: now + ttlSeconds * 1000, assertionHash });
        return 'first-sight';
      }
      if (existing.assertionHash === assertionHash) return 'match';
      return 'replay';
    },
    size() {
      return seen.size;
    },
  };
}
