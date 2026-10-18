/**
 * IAM Module — Enterprise Redis Resolution
 *
 * CHARIOT::§18.2::2 — "Enterprise mode ... optionally uses Redis (in-process
 * fallback if absent)." (CHARIOT-SPEC.md:1467-1469)
 *
 * CHARIOT::§18.3::4 — "Redis unreachable | ControlPlane degrades to
 * in-process; ApprovalQueue degrades to in-memory; sessions fall back to
 * JWT-signature-only revocation (8h max stale window)." (CHARIOT-SPEC.md:1480)
 * The row does not distinguish "REDIS_URL never set" from "REDIS_URL set but
 * unreachable at boot" — both are "Redis unreachable" and both degrade; only
 * an explicitly-set REDIS_URL that connects and then STOPS responding after
 * a successful boot is a runtime concern (node-redis's own reconnect
 * strategy + the 'error' handler each call site installs), not this
 * function's.
 *
 * Single implementation shared by src/iam/bootstrap.ts
 * (bootstrapEnterprise()) and src/engine/bin/setup.ts (`chariot serve
 * --http`'s enterprise IAM bootstrap) so the two enterprise-startup paths
 * cannot diverge on Redis-absent/unreachable semantics, and so this
 * decision is directly unit-testable without a native binary, MongoDB, or a
 * real Redis — the rest of bootstrapEnterprise() cannot run end-to-end in
 * this sandbox (see bootstrap.jwt-secret-floor.test.ts's documented
 * limitation); this seam has no such dependency.
 */
import { createClient, type RedisClientType } from 'redis';
import { createInProcessRedisShim } from './inProcessRedisShim.js';
import { redactConnectionString } from './redactConnectionString.js';
// CHARIOT::§16.1 Operational (rulings item 91/105) — direct import,
// matching this repo's established pattern.
import { chariotEmitter } from '../observability/emitter.js';

export interface ResolvedEnterpriseRedis {
  redisClient: RedisClientType;
  redisMode: 'external' | 'in-process-shim';
  /**
   * True ONLY when a CONFIGURED REDIS_URL was unreachable at boot/restart
   * and the in-process shim was substituted for it — i.e. exactly the
   * §18.3::4 "Redis unreachable" degrade. False both when a real Redis
   * connected AND when REDIS_URL was simply never configured: in the
   * latter case the shim is used consistently from process start (no
   * prior activity/revocation state to have lost), so session.ts's
   * fail-closed missing-activity-key check (§SOC2 idle-timeout) never
   * needs to be bypassed — only a genuine mid-lifecycle Redis loss does.
   * Callers thread this into session.ts's setSessionRedisDegraded() so
   * verifyToken() knows which mode it is in.
   */
  degraded: boolean;
  /** Present only when `degraded` is true — the (already redacted) reason, for logging/diagnostics. */
  reason?: string;
}

/**
 * Resolve the enterprise Redis client per §18.2::2 / §18.3::4:
 * - `redisUrl` unset/empty → in-process shim (no warning; this is the
 *   documented default, not a degrade from a failure). `degraded: false`.
 * - `redisUrl` set and reachable → the real client (`redisMode: 'external'`,
 *   `degraded: false`).
 * - `redisUrl` set but unreachable at boot → `warn()` once, naming the
 *   redacted URL, then the in-process shim (`redisMode: 'in-process-shim'`,
 *   `degraded: true`). Never throws for this case — that is precisely the
 *   §18.3::4 degrade.
 */
export async function resolveEnterpriseRedisClient(
  redisUrl: string | undefined,
  warn: (message: string, data?: Record<string, unknown>) => void,
): Promise<ResolvedEnterpriseRedis> {
  if (!redisUrl || redisUrl.trim() === '') {
    return {
      redisClient: createInProcessRedisShim() as unknown as RedisClientType,
      redisMode: 'in-process-shim',
      degraded: false,
    };
  }

  const client = createClient({
    url: redisUrl,
    // node-redis v4's default reconnectStrategy retries the INITIAL
    // connect() attempt indefinitely with backoff, not just post-connect
    // drops — verified live: against a refusing port, connect() hangs
    // rather than rejecting. That would turn "unreachable" into an
    // indefinite boot hang, defeating the §18.3::4 degrade below (the
    // catch block below is never reached). Disabling it here scopes the
    // no-retry behavior to boot-time resolution only; it does not affect
    // the 'error' handler's post-connect runtime-error handling (that
    // path never calls connect() again, so reconnectStrategy is moot
    // there either way). connectTimeout stays at node-redis's 5000ms
    // default, which bounds a silently-dropping host (firewall) the same
    // way MongoClient's serverSelectionTimeoutMS bounds Mongo above.
    socket: { reconnectStrategy: false },
  }) as RedisClientType;
  // Required so a post-connect runtime error (cluster failover, TLS hiccup,
  // auth expiry, network partition) does not crash the process via an
  // unhandled 'error' event — node-redis's own reconnect strategy handles
  // those. A boot-time connect FAILURE is caught explicitly below instead.
  client.on('error', (err: unknown) => {
    const reason = err instanceof Error ? err.message : String(err);
    warn('[iam] redis runtime error', { error: reason });
    // CHARIOT::§16.1 Operational (CHARIOT-SPEC.md:1353, rulings item
    // 91/105) — a post-connect runtime error (cluster failover, TLS
    // hiccup, auth expiry, network partition), distinct from the
    // boot-time unreachable case below (both are genuinely "Redis
    // unreachable" from the customer's perspective, so both emit).
    chariotEmitter.send('redis.unreachable', {
      severity: 'warning',
      data: { redisUrl: redactConnectionString(redisUrl), reason, phase: 'runtime' },
    });
  });

  try {
    await client.connect();
    await client.ping();
    return { redisClient: client, redisMode: 'external', degraded: false };
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    warn(
      'Redis unreachable at startup — degrading to in-process fallback ' +
      '(ControlPlane in-process, ApprovalQueue in-memory, sessions ' +
      'JWT-signature-only within the 8h token TTL)',
      { redisUrl: redactConnectionString(redisUrl), error: reason },
    );
    // CHARIOT::§16.1 Operational (CHARIOT-SPEC.md:1353, rulings item
    // 91/105) — the boot-time unreachable case (§18.3::4's own named
    // degrade), distinct from the runtime 'error' handler above.
    chariotEmitter.send('redis.unreachable', {
      severity: 'warning',
      data: { redisUrl: redactConnectionString(redisUrl), reason, phase: 'boot' },
    });
    return {
      redisClient: createInProcessRedisShim() as unknown as RedisClientType,
      redisMode: 'in-process-shim',
      degraded: true,
      reason,
    };
  }
}
