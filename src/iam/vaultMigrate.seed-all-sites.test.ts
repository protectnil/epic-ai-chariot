/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10), rulings item 59. Gate finding
 * F1 (2026-09-04): "Add a test that seeds one legacy record in EACH site
 * (fakes/in-memory where the real store is unavailable) and proves
 * migrate upgrades all of them and refuses the marker while any remains."
 *
 * Seeds one genuinely-legacy (pre-CH-10, empty-AAD) ciphertext in every
 * site `src/iam/vaultMigrationSites.ts` registers:
 *   - iam_adapter_credentials, iam_tenants.settings.oidc, iam_id_jag_idp_clients
 *     — fake in-memory Mongo collections (no live MongoDB in this sandbox).
 *   - the SQLite checkpoint store — a REAL temp `node:sqlite` file (no
 *     fake needed; `node:sqlite` is a zero-dependency Node built-in).
 *   - session.ts's Redis subject_token — a fake in-memory Redis client
 *     implementing exactly the surface `walkLegacyIdJagSubjectTokens` and
 *     `casSetWithTtl` use (get/set/scanIterator/eval); no live Redis here.
 *   - chainSigner's sealed-store artifact — a REAL temp file under
 *     `EPIC_AI_DIR_OVERRIDE` (chainSigner reads real files; no fake).
 *
 * The legacy ciphertext fixture is built with RAW HKDF-SHA256 +
 * AES-256-GCM (empty AAD) via node:crypto — the exact algorithm
 * `native/src/vault.rs`'s pre-CH-10 code used (RFC 5869 HKDF is
 * interoperable across implementations given identical salt/info/ikm), so
 * the REAL native binary's legacy decrypt path decrypts it correctly.
 * There is no TypeScript-callable primitive that PRODUCES this shape
 * (`encryptFields` always emits `v2:`) — see crypto.ch10-cutover.test.ts's
 * documented reason — so this is the only way to seed a genuine fixture.
 *
 * Proves, in one run: every per-tenant site's legacy record is found
 * (6 total: adapter + oidc + id-jag + checkpoint input + checkpoint
 * output + redis subject-token), upgraded (re-encrypted to `v2:`), and
 * the marker is written once zero legacy remain. A follow-up run seeding
 * a FRESH legacy record after the marker exists proves the marker is
 * written again only once THAT run also finds and upgrades it — and a
 * separate test proves the marker is refused outright when an entire
 * registered site (Redis) could not be walked at all.
 *
 * Run (after `npm run build:native` and `tsc`): node --test dist/iam/vaultMigrate.seed-all-sites.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hkdfSync, randomBytes, createCipheriv } from 'node:crypto';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const MASTER_KEY = randomBytes(32);
process.env.ENTERPRISE_MASTER_KEY = MASTER_KEY.toString('base64');

// EPIC_AI_DIR (src/cli/paths.ts) is computed at import time — must be set
// BEFORE anything that transitively imports it (vaultMigrate.js ->
// chainSigner.js) is first loaded in this test file's process.
const epicAiDir = mkdtempSync(join(tmpdir(), 'ch10-seed-epic-ai-'));
process.env.EPIC_AI_DIR_OVERRIDE = epicAiDir;

const { migrateTenant } = await import('./vaultMigrate.js');
const { VAULT_MIGRATIONS_COLLECTION } = await import('./crypto.js');
const { SEALED_TENANT_ID } = await import('../engine/audit/chainSigner.js');

/**
 * Legacy (pre-CH-10) fixture: HKDF-SHA256(salt=`tenant:{tenantId}`, empty
 * info) -> AES-256-GCM with NO additional authenticated data, tag
 * appended to the ciphertext. Matches `native/src/vault.rs`'s
 * `derive_key` + the pre-CH-10 `.encrypt(nonce, plaintext)` call exactly
 * (RFC 5869 HKDF and AES-256-GCM are both standard, interoperable
 * algorithms — the adapter_id/recordId is irrelevant here because the
 * legacy path never binds one into the AAD).
 */
// master-key derivation: TEST FIXTURE ONLY (pre-CH-10 legacy ciphertext)
function legacyFixture(tenantId: string, plaintext: object): { encrypted: string; iv: string } {
  const salt = Buffer.from(`tenant:${tenantId}`);
  const key = Buffer.from(hkdfSync('sha256', MASTER_KEY, salt, Buffer.alloc(0), 32));
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(plaintext), 'utf-8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { encrypted: Buffer.concat([ct, tag]).toString('base64'), iv: iv.toString('base64') };
}

// ── Fake in-memory Mongo (find/findOne/updateOne/distinct only — the
//    exact surface migrateTenant's inline Mongo sweep uses). $set
//    supports MongoDB's dotted-path nested-field semantics, since the
//    OIDC site writes `settings.oidc.clientSecretEncrypted`. ────────────
type Doc = Record<string, unknown> & { _id: unknown };

function getPath(obj: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, k) => (acc as Record<string, unknown> | undefined)?.[k], obj);
}
function setPath(obj: Record<string, unknown>, path: string, value: unknown): void {
  const parts = path.split('.');
  let cur: Record<string, unknown> = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const k = parts[i]!;
    if (typeof cur[k] !== 'object' || cur[k] === null) cur[k] = {};
    cur = cur[k] as Record<string, unknown>;
  }
  cur[parts[parts.length - 1]!] = value;
}
function matches(doc: Doc, filter: Record<string, unknown>): boolean {
  return Object.entries(filter).every(([k, v]) => getPath(doc, k) === v);
}

function makeFakeDb() {
  const collections = new Map<string, Doc[]>();
  const col = (name: string) => {
    if (!collections.has(name)) collections.set(name, []);
    const docs = collections.get(name)!;
    return {
      find(filter: Record<string, unknown>) {
        return { toArray: async () => docs.filter((d) => matches(d, filter)) };
      },
      findOne: async (filter: Record<string, unknown>) => docs.find((d) => matches(d, filter)) ?? null,
      updateOne: async (
        filter: Record<string, unknown>,
        update: { $set: Record<string, unknown> },
        opts?: { upsert?: boolean },
      ) => {
        const existing = docs.find((d) => matches(d, filter));
        if (existing) {
          for (const [k, v] of Object.entries(update.$set)) setPath(existing, k, v);
          return { matchedCount: 1 };
        }
        if (opts?.upsert) {
          const created: Doc = { _id: (filter as { _id?: unknown })._id ?? randomBytes(6).toString('hex') } as Doc;
          for (const [k, v] of Object.entries(update.$set)) setPath(created, k, v);
          docs.push(created);
          return { matchedCount: 0, upsertedCount: 1 };
        }
        return { matchedCount: 0 };
      },
      distinct: async (field: string) => [...new Set(docs.map((d) => getPath(d, field)).filter((v) => v !== undefined))],
    };
  };
  return { collection: col, _collections: collections };
}

// ── Fake in-memory Redis (get/set/scanIterator/eval only). ──────────────
//
// CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10), rulings item 59, W59g
// follow-up (2026-09-04): node-redis v4's REAL `scanIterator` yields
// BATCHES — an array of matched keys per SCAN cursor step — never a
// single key at a time (read from
// node_modules/@redis/client/dist/lib/client/index.d.ts:341, cited in
// the W59f fix to src/iam/services/session.ts). An earlier version of
// THIS fake yielded one bare key per iteration, which is NOT the real
// contract — it let `walkLegacyIdJagSubjectTokens`'s batch-shaped bug
// (treating the yielded value as a single key) pass this very test while
// being broken against the real client, which is exactly how that bug
// reached tsc instead of being caught here first. `scanBatchSize`
// controls how many keys land in each yielded batch, so callers can
// exercise both a batch-of-1 (worst case: still an array, size 1) and a
// multi-key, unevenly-splitting batch size — see the dedicated batching
// test below.
function makeFakeRedis(scanBatchSize = 2) {
  const store = new Map<string, string>();
  return {
    async get(key: string) {
      return store.get(key) ?? null;
    },
    async set(key: string, value: string) {
      store.set(key, value);
      return 'OK';
    },
    async *scanIterator(_opts: { MATCH: string; COUNT: number }) {
      const keys = [...store.keys()];
      for (let i = 0; i < keys.length; i += scanBatchSize) {
        yield keys.slice(i, i + scanBatchSize); // ALWAYS an array — matches the real client's per-cursor-step batch shape.
      }
    },
    async eval(_script: string, opts: { keys: string[]; arguments: string[] }) {
      const [key] = opts.keys;
      const [expected, next] = opts.arguments;
      if (store.get(key!) !== expected) return 0;
      store.set(key!, next!);
      return 1;
    },
    async quit() { /* no-op */ },
    on() { /* no-op */ },
    _seed(key: string, value: string) { store.set(key, value); },
  } as unknown as import('redis').RedisClientType & { _seed(key: string, value: string): void };
}

test('§12.2/CH-10 item 59: migrate seeds+upgrades one legacy record in every per-tenant site, then refuses re-refusal once clean', async () => {
  const tenantId = 'seed-tenant-a';
  const db = makeFakeDb();
  const redis = makeFakeRedis();
  const checkpointDbPath = join(mkdtempSync(join(tmpdir(), 'ch10-seed-sqlite-')), 'chariot.db');

  // ── Seed one legacy record per per-tenant site ──────────────────────
  const adapterId = 'adapter-x';
  const adapterFixture = legacyFixture(tenantId, { apiKey: 'seed-secret-adapter' });
  db._collections.set('iam_adapter_credentials', [
    { _id: 'row-1', tenantId, adapterId, encrypted: adapterFixture.encrypted, iv: adapterFixture.iv, status: 'active' } as Doc,
  ]);

  const oidcFixture = legacyFixture(tenantId, { value: 'seed-secret-oidc' });
  db._collections.set('iam_tenants', [
    { _id: 'tenant-doc-1', tenantId, settings: { oidc: { clientSecretEncrypted: `${oidcFixture.encrypted}:${oidcFixture.iv}` } } } as Doc,
  ]);

  const idJagFixture = legacyFixture(tenantId, { value: 'seed-secret-idjag' });
  const issuer = 'https://idp.example.test';
  db._collections.set('iam_id_jag_idp_clients', [
    { _id: 'idp-1', tenantId, issuer, authMethod: 'client_secret_post', clientSecretEncrypted: `${idJagFixture.encrypted}:${idJagFixture.iv}` } as Doc,
  ]);

  // SQLite checkpoint row: legacy input AND output — real db file.
  {
    const sdb = new DatabaseSync(checkpointDbPath);
    sdb.exec(`CREATE TABLE checkpoints (
      step_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, input_ct TEXT NOT NULL, input_iv TEXT NOT NULL,
      output_ct TEXT NOT NULL, output_iv TEXT NOT NULL
    )`);
    const inputFixture = legacyFixture(tenantId, { a: 1 });
    const outputFixture = legacyFixture(tenantId, { b: 2 });
    sdb.prepare(`INSERT INTO checkpoints (step_id, tenant_id, input_ct, input_iv, output_ct, output_iv) VALUES (?, ?, ?, ?, ?, ?)`)
      .run('seed-step-1', tenantId, inputFixture.encrypted, inputFixture.iv, outputFixture.encrypted, outputFixture.iv);
    sdb.close();
  }

  // Redis subject_token: legacy record.
  const sessionJti = 'seed-session-jti-1';
  const nowSec = Math.floor(Date.now() / 1000);
  const subjectFixture = legacyFixture(tenantId, {
    token: 'seed-subject-token', type: 'id_token', exp: String(nowSec + 3600), issuer,
  });
  (redis as unknown as { _seed(key: string, value: string): void })._seed(
    `ent:session:idjag-subject:${sessionJti}`,
    JSON.stringify(subjectFixture),
  );

  // ── Run 1: real tenant sweep — 6 legacy records total, all upgrade ──
  const result1 = await migrateTenant(db as unknown as import('mongodb').Db, tenantId, false, redis, checkpointDbPath);
  assert.equal(result1.legacy, 6, 'adapter(1) + oidc(1) + id-jag(1) + checkpoint input+output(2) + redis(1)');
  assert.equal(result1.failed, 0);
  assert.equal(result1.upgraded, 6);
  assert.equal(result1.markerWritten, true, 'zero legacy remain across every walked per-tenant site — marker written');

  // Re-verify: the adapter row now carries a v2: ciphertext, and this is
  // read back through the SAME fake store — proves the upgrade actually
  // persisted, not just was counted.
  const upgradedRow = (await db.collection('iam_adapter_credentials').find({ tenantId }).toArray())[0] as Doc;
  assert.ok((upgradedRow.encrypted as string).startsWith('v2:'), 'adapter row must be re-encrypted under the v2 format');
  const upgradedTenantDoc = (await db.collection('iam_tenants').findOne({ tenantId })) as Doc;
  const oidcEncryptedNow = getPath(upgradedTenantDoc, 'settings.oidc.clientSecretEncrypted') as string;
  assert.ok(oidcEncryptedNow.startsWith('v2:'), 'oidc field must be re-encrypted under the v2 format (nested $set)');

  // ── Run 2: same tenant again — everything already v2 — legacy=0, still written (vacuously clean) ──
  const result2 = await migrateTenant(db as unknown as import('mongodb').Db, tenantId, false, redis, checkpointDbPath);
  assert.equal(result2.legacy, 0, 'nothing legacy left after run 1 — proves the run-1 upgrades were real, not just reported');
  assert.equal(result2.markerWritten, true);

  // ── Seed a FRESH legacy record after the marker exists; this run itself upgrades it and writes the marker again ──
  const freshFixture = legacyFixture(tenantId, { apiKey: 'seed-secret-adapter-2' });
  db._collections.get('iam_adapter_credentials')!.push(
    { _id: 'row-2', tenantId, adapterId: 'adapter-y', encrypted: freshFixture.encrypted, iv: freshFixture.iv, status: 'active' } as Doc,
  );

  const result3 = await migrateTenant(db as unknown as import('mongodb').Db, tenantId, false, redis, checkpointDbPath);
  assert.equal(result3.legacy, 1, 'the freshly-seeded record is the only legacy one this run finds');
  assert.equal(result3.upgraded, 1);
  assert.equal(result3.markerWritten, true, 'this run finds and upgrades it, so 0 remain by the end of THIS run');

  const markerRows = db._collections.get(VAULT_MIGRATIONS_COLLECTION);
  assert.ok(markerRows && markerRows.length >= 1, 'a migration marker document must actually be persisted');
});

test('§12.2/CH-10 item 59: the sealed-store (chainSigner pseudo-tenant) legacy artifact is walked, upgraded, and gates its own marker', async () => {
  const auditDir = join(epicAiDir, 'audit');
  mkdirSync(auditDir, { recursive: true });

  const fixture = legacyFixture(SEALED_TENANT_ID, { privateKeyPem: 'seed-fake-pem-not-a-real-key' });
  const kid = 'seed' + randomBytes(4).toString('hex');
  const artifact = { schemaVersion: 1, backend: 'sealed-store', kid, publicKeyPem: 'seed-fake-pub', encrypted: fixture.encrypted, iv: fixture.iv };
  writeFileSync(join(auditDir, `signing-key.${kid}.sealed.json`), JSON.stringify(artifact, null, 2) + '\n');

  const db = makeFakeDb();
  const redis = makeFakeRedis();
  const checkpointDbPath = join(mkdtempSync(join(tmpdir(), 'ch10-seed-sqlite2-')), 'chariot.db');

  const result = await migrateTenant(db as unknown as import('mongodb').Db, SEALED_TENANT_ID, false, redis, checkpointDbPath);
  assert.equal(result.legacy, 1, 'the seeded sealed-store artifact must be found');
  assert.equal(result.upgraded, 1);
  assert.equal(result.markerWritten, true);

  const updated = JSON.parse(readFileSync(join(auditDir, `signing-key.${kid}.sealed.json`), 'utf-8')) as { encrypted: string };
  assert.ok(updated.encrypted.startsWith('v2:'), 'sealed artifact file on disk must now carry the v2 ciphertext');
});

test('§12.2/CH-10 item 59: the marker is refused (not written) when Redis cannot be walked, even if every other site is clean', async () => {
  const tenantId = 'seed-tenant-no-redis';
  const db = makeFakeDb();
  const checkpointDbPath = join(mkdtempSync(join(tmpdir(), 'ch10-seed-sqlite3-')), 'chariot.db');

  const result = await migrateTenant(db as unknown as import('mongodb').Db, tenantId, false, null, checkpointDbPath);
  assert.equal(result.legacy, 0, 'nothing seeded — every walkable site is clean');
  assert.equal(result.markerWritten, false, 'Redis was not walked at all, so "zero remain" is unproven — marker MUST be refused');
  assert.match(result.markerRefusedReason ?? '', /Redis/);
});

test('§12.2/CH-10 item 59: dry-run never writes the marker even when everything is clean', async () => {
  const tenantId = 'seed-tenant-dry-run';
  const db = makeFakeDb();
  const redis = makeFakeRedis();
  const checkpointDbPath = join(mkdtempSync(join(tmpdir(), 'ch10-seed-sqlite4-')), 'chariot.db');

  const result = await migrateTenant(db as unknown as import('mongodb').Db, tenantId, true, redis, checkpointDbPath);
  assert.equal(result.markerWritten, false);
  assert.match(result.markerRefusedReason ?? '', /dry-run/);
});

test('§12.2/CH-10 item 59 (W59g): walkLegacyIdJagSubjectTokens visits every seeded key regardless of SCAN batch size', async () => {
  const { walkLegacyIdJagSubjectTokens, setRedisClient } = await import('./services/session.js');
  const tenantId = 'seed-tenant-batching';
  const seedCount = 4;

  const buildKeys = async (redis: ReturnType<typeof makeFakeRedis>, prefix: string) => {
    for (let i = 0; i < seedCount; i++) {
      const fixture = legacyFixture(tenantId, { token: `${prefix}-${i}`, type: 'id_token', exp: String(Math.floor(Date.now() / 1000) + 3600), issuer: 'https://idp.batch.test' });
      (redis as unknown as { _seed(key: string, value: string): void })._seed(
        `ent:session:idjag-subject:${prefix}-jti-${i}`,
        JSON.stringify(fixture),
      );
    }
  };

  // Batch size 1: every SCAN cursor step yields an array of exactly one
  // key (the degenerate case — still an array, never a bare string).
  const redisBatchOf1 = makeFakeRedis(1);
  await buildKeys(redisBatchOf1, 'batch1');
  setRedisClient(redisBatchOf1);
  const resultBatchOf1 = await walkLegacyIdJagSubjectTokens(tenantId, false);
  assert.equal(resultBatchOf1.legacy, seedCount, 'every key must be visited when SCAN yields one-key batches');
  assert.equal(resultBatchOf1.upgraded, seedCount);

  // Batch size 3 against 4 keys: an UNEVEN split (one batch of 3, one
  // batch of 1) — proves keys are not dropped or double-counted at a
  // batch boundary.
  const redisBatchOf3 = makeFakeRedis(3);
  await buildKeys(redisBatchOf3, 'batch3');
  setRedisClient(redisBatchOf3);
  const resultBatchOf3 = await walkLegacyIdJagSubjectTokens(tenantId, false);
  assert.equal(resultBatchOf3.legacy, seedCount, 'every key must be visited when SCAN yields multi-key, unevenly-splitting batches');
  assert.equal(resultBatchOf3.upgraded, seedCount);
});
