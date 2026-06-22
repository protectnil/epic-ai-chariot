/**
 * IAM Module — Redis Helper
 *
 * The Redis client is injected from bootstrap (pre-validated).
 * No lazy-connect. No permissive defaults.
 */

import type { RedisClientType } from 'redis';

let _redisClient: RedisClientType | null = null;

/**
 * Inject the Redis client from bootstrap. Must be called before any
 * Redis operation in enterprise mode.
 */
export function setRedisClient(client: RedisClientType): void {
  _redisClient = client;
}

/**
 * Return the shared Redis client.
 * Throws (as a rejected Promise) if the client has not been injected via
 * setRedisClient(). Returned as `Promise<RedisClientType>` to let callers
 * continue using `await getRedisClient()` as the idiomatic pattern even
 * though there is no internal async work.
 */
export function getRedisClient(): Promise<RedisClientType> {
  if (!_redisClient) {
    return Promise.reject(new Error(
      'IAM Redis: client not initialized. ' +
      'Call setRedisClient() during enterprise bootstrap before accessing sessions.'
    ));
  }
  return Promise.resolve(_redisClient);
}
