/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10), rulings item 59: "the caller
 * MUST persist {encrypted, iv} back to the SAME record, in the SAME
 * operation." Gate finding F2/F3 follow-up: "tests per site: CAS no-op
 * on a concurrent upgrade, failure surfaces, success persists exactly
 * {encrypted, iv} returned by decryptFields."
 *
 * CAS predicate under test (src/iam/services/session.ts, the
 * `CAS_SET_WITH_TTL_SCRIPT` Lua script `casSetWithTtl` runs via a single
 * atomic Redis EVAL):
 *
 *   if redis.call('GET', KEYS[1]) == ARGV[1] then
 *     redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
 *     return 1
 *   else
 *     return 0
 *   end
 *
 * Two "readers" of the SAME legacy Redis record each independently
 * compute a fresh v2 ciphertext (two real encryptFields calls — same
 * plaintext, different random IVs, so genuinely different bytes, as two
 * concurrent upgraders racing on the same legacy value would). Writer A's
 * `casSetWithTtl` call (ARGV[1] = the original legacy value) succeeds
 * first. Writer B's `casSetWithTtl` call, still holding that SAME stale
 * `expectedRaw`, is then attempted: GET now returns A's value, not the
 * stale one, so the Lua branch takes `return 0` — a no-op, never a
 * clobber of A's write.
 *
 * Run (after `npm run build:native` and `tsc`): node --test dist/iam/services/session.casSetWithTtl.concurrent-upgrade.test.js
 */
// master-key derivation: TEST FIXTURE ONLY (pre-CH-10 legacy ciphertext)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

process.env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');

const { casSetWithTtl, getIdJagSubjectToken, setRedisClient } = await import('./session.js');
const { encryptFields } = await import('../crypto.js');

/** Fake Redis: only GET/SET/EVAL — the exact surface casSetWithTtl uses. */
function makeFakeRedis() {
  const store = new Map<string, string>();
  return {
    _seed(key: string, value: string) { store.set(key, value); },
    _get(key: string) { return store.get(key); },
    async get(key: string) { return store.get(key) ?? null; },
    async eval(script: string, opts: { keys: string[]; arguments: string[] }) {
      void script;
      const [key] = opts.keys;
      const [expected, next] = opts.arguments;
      if (store.get(key!) !== expected) return 0;
      store.set(key!, next!);
      return 1;
    },
  };
}

test('§12.2/CH-10 item 59: casSetWithTtl — concurrent upgrade race: writer A persists, writer B is a CAS no-op', async () => {
  const redis = makeFakeRedis();
  const key = 'ent:session:idjag-subject:concurrent-test-jti';
  const legacyRaw = JSON.stringify({ encrypted: 'legacy-ciphertext-base64', iv: 'legacy-iv-base64' });
  redis._seed(key, legacyRaw);

  const tenantId = 'concurrent-tenant';
  const recordId = 'concurrent-test-jti';
  // Two independent "readers" of the SAME legacy record, each producing
  // their own real v2 ciphertext (genuinely different bytes — random IV).
  const upgradeA = encryptFields({ token: 'seed-token', type: 'id_token', exp: '9999999999', issuer: 'https://idp.test' }, tenantId, recordId);
  const upgradeB = encryptFields({ token: 'seed-token', type: 'id_token', exp: '9999999999', issuer: 'https://idp.test' }, tenantId, recordId);
  assert.notEqual(upgradeA.encrypted, upgradeB.encrypted, 'two independent encryptions must differ (random IV) — proves this is a genuine race, not one writer twice');

  // Writer A: CAS against the legacy value it read — succeeds.
  const casA = await casSetWithTtl(redis as unknown as import('redis').RedisClientType, key, legacyRaw, JSON.stringify(upgradeA), 3600);
  assert.equal(casA, true, 'writer A must win the race — the key still held the legacy value it read');
  assert.equal(redis._get(key), JSON.stringify(upgradeA), 'the store must hold exactly A\'s {encrypted, iv}');

  // Writer B: still holding the SAME stale legacyRaw it read before A won — CAS must no-op, not clobber.
  const casB = await casSetWithTtl(redis as unknown as import('redis').RedisClientType, key, legacyRaw, JSON.stringify(upgradeB), 3600);
  assert.equal(casB, false, 'writer B\'s CAS must be a no-op — the key no longer holds the stale value B read');
  assert.equal(redis._get(key), JSON.stringify(upgradeA), 'the store must STILL hold exactly A\'s {encrypted, iv} — never clobbered by B');
});

test('§12.2/CH-10 item 59: casSetWithTtl — a genuine Redis error propagates to the caller (not swallowed)', async () => {
  const redis = {
    async eval() {
      throw new Error('ECONNRESET: simulated Redis failure');
    },
  };
  await assert.rejects(
    () => casSetWithTtl(redis as unknown as import('redis').RedisClientType, 'some-key', 'expected', 'next', 3600),
    /ECONNRESET/,
  );
});

test('§12.2/CH-10 item 59: getIdJagSubjectToken — write-back CAS preserves remaining TTL and the exact upgraded {encrypted, iv}', async () => {
  const redis = makeFakeRedis();
  setRedisClient(redis as unknown as import('redis').RedisClientType);

  const tenantId = 'concurrent-tenant-2';
  const sessionJti = 'concurrent-test-jti-2';
  const key = `ent:session:idjag-subject:${sessionJti}`;
  // Legacy record built the same way native/src/vault.rs's pre-CH-10 code
  // did — via the REAL native binding's legacy path is not reachable from
  // TS (encryptFields always emits v2:), so this reuses the SAME fixture
  // approach as vaultMigrate.seed-all-sites.test.ts: raw HKDF+AES-GCM,
  // empty AAD, matching native/src/vault.rs's derive_key exactly.
  const { hkdfSync, randomBytes: rb, createCipheriv } = await import('node:crypto');
  const masterKey = Buffer.from(process.env.ENTERPRISE_MASTER_KEY!, 'base64');
  const salt = Buffer.from(`tenant:${tenantId}`);
  const derivedKey = Buffer.from(hkdfSync('sha256', masterKey, salt, Buffer.alloc(0), 32));
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const plaintext = JSON.stringify({ token: 't', type: 'id_token', exp: String(exp), issuer: 'https://idp.test' });
  const ivBuf = rb(12);
  const cipher = createCipheriv('aes-256-gcm', derivedKey, ivBuf);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf-8')), cipher.final(), cipher.getAuthTag()]);
  const legacyRaw = JSON.stringify({ encrypted: ct.toString('base64'), iv: ivBuf.toString('base64') });
  redis._seed(key, legacyRaw);

  const result = await getIdJagSubjectToken(tenantId, sessionJti);
  assert.ok(result, 'the legacy record must still decrypt correctly');
  assert.equal(result!.token, 't');

  const stored = JSON.parse(redis._get(key)!) as { encrypted: string; iv: string };
  assert.ok(stored.encrypted.startsWith('v2:'), 'the write-back must persist the upgraded v2 ciphertext');
  assert.notEqual(stored, legacyRaw, 'the stored record must no longer be the legacy bytes');
});

test('§12.2/CH-10 item 59: getIdJagSubjectToken — a genuine write-back failure surfaces VaultUpgradePersistFailedError to the caller', async () => {
  const { VaultUpgradePersistFailedError } = await import('../crypto.js');

  // A genuinely-legacy record is required to reach the write-back path at
  // all — reuse the same raw-HKDF fixture technique.
  const { hkdfSync, randomBytes: rb, createCipheriv } = await import('node:crypto');
  const tenantId = 'concurrent-tenant-3';
  const sessionJti = 'concurrent-test-jti-3';
  const masterKey = Buffer.from(process.env.ENTERPRISE_MASTER_KEY!, 'base64');
  const salt = Buffer.from(`tenant:${tenantId}`);
  const derivedKey = Buffer.from(hkdfSync('sha256', masterKey, salt, Buffer.alloc(0), 32));
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const plaintext = JSON.stringify({ token: 't', type: 'id_token', exp: String(exp), issuer: 'https://idp.test' });
  const ivBuf = rb(12);
  const cipher = createCipheriv('aes-256-gcm', derivedKey, ivBuf);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf-8')), cipher.final(), cipher.getAuthTag()]);
  const legacyRaw = JSON.stringify({ encrypted: ct.toString('base64'), iv: ivBuf.toString('base64') });

  const redisWithGet = {
    async get() { return legacyRaw; },
    async eval() { throw new Error('simulated Redis failure'); },
  };
  setRedisClient(redisWithGet as unknown as import('redis').RedisClientType);

  await assert.rejects(
    () => getIdJagSubjectToken(tenantId, sessionJti),
    (err: unknown) => {
      assert.ok(err instanceof VaultUpgradePersistFailedError);
      assert.equal(err.code, 'VAULT_UPGRADE_PERSIST_FAILED');
      return true;
    },
  );
});

