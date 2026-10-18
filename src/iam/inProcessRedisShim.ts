/**
 * IAM Module — In-Process Redis Shim
 *
 * CHARIOT::§18.2::2 — "Enterprise mode: `CHARIOT_ENTERPRISE=1 npx
 * @epicai/chariot`. Loads the IAM service, requires `ENTERPRISE_MASTER_KEY`,
 * requires MongoDB, optionally uses Redis (in-process fallback if absent)."
 * (CHARIOT-SPEC.md:1467-1469)
 *
 * CHARIOT::§18.3::4 — "IF Redis is unreachable THEN ControlPlane SHALL
 * degrade to in-process, ApprovalQueue to in-memory, and sessions fall back
 * to JWT-signature-only revocation (8h max stale window)." (CHARIOT-SPEC.md:1475)
 * This shim is the "in-process" fallback surface for the session/jti/redis
 * call sites that require a RedisClientType-shaped object — it does not
 * itself implement the 8h stale-window JWT-signature-only degrade (that is
 * session.ts's own responsibility when it detects no live Redis round trip);
 * it exists so enterprise mode never hard-fails startup solely because no
 * REDIS_URL was configured, matching "optionally uses Redis" above.
 *
 * Shared by src/iam/bootstrap.ts (bootstrapEnterprise()) and
 * src/engine/bin/setup.ts (`chariot serve --http` enterprise IAM bootstrap)
 * so the two enterprise-startup paths cannot drift on Redis-absent
 * semantics. Values live only for this process's lifetime — a restart wipes
 * every session and resets the replay cache, and it cannot be shared by a
 * second instance; that is the documented cost of running enterprise mode
 * without a real, shared Redis.
 */

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

interface KvEntry { value: string; expiresAtMs: number | null }
interface SetEntry { members: Set<string>; expiresAtMs: number | null }

export interface InProcessRedisShim {
  sAdd(key: string, ...members: unknown[]): Promise<number>;
  sMembers(key: string): Promise<string[]>;
  sRem(key: string, ...members: unknown[]): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  set(key: string, val: string, opts?: { NX?: boolean; KEEPTTL?: boolean; EX?: number; PX?: number }): Promise<string | null>;
  get(key: string): Promise<string | null>;
  del(...keys: unknown[]): Promise<number>;
  hGet(): Promise<string | null>;
  hSet(): Promise<number>;
  eval(script: string, opts: { keys: string[]; arguments: string[] }): Promise<string>;
  incr(key: string): Promise<number>;
  multi(): unknown;
  on?(event: string, handler: (...args: unknown[]) => void): unknown;
}

/**
 * Construct a fresh in-process Redis-shaped store. Each call returns an
 * independent shim (its own Maps + sweeper timer) — callers should create
 * exactly one per process and share it across all injection points
 * (session.ts, jti-replay-cache.ts, redis.ts) so state is consistent.
 */
export function createInProcessRedisShim(): InProcessRedisShim {
  const kv = new Map<string, KvEntry>();
  const sets = new Map<string, SetEntry>();
  const now = (): number => Date.now();
  const isExpired = (e: { expiresAtMs: number | null } | undefined): boolean =>
    e !== undefined && e.expiresAtMs !== null && e.expiresAtMs <= now();
  const kvGetLive = (k: string): KvEntry | undefined => {
    const e = kv.get(k);
    if (!e) return undefined;
    if (isExpired(e)) { kv.delete(k); return undefined; }
    return e;
  };
  const setGetLive = (k: string): SetEntry => {
    const e = sets.get(k);
    if (e && !isExpired(e)) return e;
    if (e) sets.delete(k);
    const fresh: SetEntry = { members: new Set<string>(), expiresAtMs: null };
    sets.set(k, fresh);
    return fresh;
  };
  const computeExpiry = (opts: { EX?: number; PX?: number } | undefined): number | null => {
    if (!opts) return null;
    if (typeof opts.PX === 'number' && opts.PX > 0) return now() + opts.PX;
    if (typeof opts.EX === 'number' && opts.EX > 0) return now() + opts.EX * 1000;
    return null;
  };
  // Background sweeper — evict expired entries every 30s so the in-memory
  // maps don't grow unbounded between accesses.
  const sweeper = setInterval((): void => {
    const t = now();
    for (const [k, e] of kv) if (e.expiresAtMs !== null && e.expiresAtMs <= t) kv.delete(k);
    for (const [k, e] of sets) if (e.expiresAtMs !== null && e.expiresAtMs <= t) sets.delete(k);
  }, 30_000);
  sweeper.unref();

  const shim: InProcessRedisShim = {
    async sAdd(key, ...members) {
      const s = setGetLive(key);
      let added = 0;
      for (const m of members.flat() as string[]) { if (!s.members.has(m)) { s.members.add(m); added++; } }
      return added;
    },
    async sMembers(key) { return [...setGetLive(key).members]; },
    async sRem(key, ...members) {
      const s = setGetLive(key);
      let removed = 0;
      for (const m of members.flat() as string[]) { if (s.members.delete(m)) removed++; }
      return removed;
    },
    async expire(key, seconds) {
      const kvE = kv.get(key);
      if (kvE) { kvE.expiresAtMs = now() + seconds * 1000; return 1; }
      const setE = sets.get(key);
      if (setE) { setE.expiresAtMs = now() + seconds * 1000; return 1; }
      return 0;
    },
    async set(key, val, opts) {
      const existing = kvGetLive(key);
      if (opts?.NX && existing) return null;
      // Real Redis KEEPTTL preserves the existing key's TTL on overwrite.
      const expiresAtMs = (opts?.KEEPTTL && existing) ? existing.expiresAtMs : computeExpiry(opts);
      kv.set(key, { value: val, expiresAtMs });
      return 'OK';
    },
    async get(key) { return kvGetLive(key)?.value ?? null; },
    async del(...keys) {
      let removed = 0;
      for (const key of keys.flat() as string[]) {
        if (kv.delete(key)) removed++;
        if (sets.delete(key)) removed++;
      }
      return removed;
    },
    async hGet() { return null; },
    async hSet() { return 1; },
    // jti-replay reserveOrMatch Lua semantics: keys[0] = replay key,
    // arguments[0] = assertion hash, arguments[1] = ttl seconds.
    async eval(_script, opts) {
      const key = opts.keys[0];
      const arg0 = opts.arguments[0];
      const ttlSecondsStr = opts.arguments[1];
      const ttlSeconds = ttlSecondsStr ? parseInt(ttlSecondsStr, 10) : 0;
      const existing = kvGetLive(key);
      if (!existing) {
        kv.set(key, { value: arg0, expiresAtMs: ttlSeconds > 0 ? now() + ttlSeconds * 1000 : null });
        return 'first-sight';
      }
      if (existing.value === arg0) return 'match';
      return 'replay';
    },
    async incr(key) {
      const existing = kvGetLive(key);
      const cur = existing ? parseInt(existing.value, 10) : 0;
      if (existing && !Number.isFinite(cur)) {
        throw new Error(`in-process redis shim: incr on non-integer value at key "${key}"`);
      }
      const next = cur + 1;
      kv.set(key, { value: String(next), expiresAtMs: existing?.expiresAtMs ?? null });
      return next;
    },
    multi(): unknown {
      const ops: Array<() => Promise<unknown>> = [];
      const chain = {
        set(k: string, v: string, o?: Parameters<InProcessRedisShim['set']>[2]) { ops.push(() => shim.set(k, v, o)); return chain; },
        del(...keys: unknown[]) { ops.push(() => shim.del(...keys)); return chain; },
        expire(k: string, s: number) { ops.push(() => shim.expire(k, s)); return chain; },
        incr(k: string) { ops.push(() => shim.incr(k)); return chain; },
        sAdd(k: string, ...m: unknown[]) { ops.push(() => shim.sAdd(k, ...m)); return chain; },
        sRem(k: string, ...m: unknown[]) { ops.push(() => shim.sRem(k, ...m)); return chain; },
        async exec(): Promise<unknown[]> {
          const out: unknown[] = [];
          for (const op of ops) out.push(await op());
          return out;
        },
      };
      return chain;
    },
    on() { return shim; },
  };
  return shim;
}
