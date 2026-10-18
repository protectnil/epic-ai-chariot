/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10), rulings item 59: "the caller
 * MUST persist {encrypted, iv} back to the SAME record, in the SAME
 * operation." Gate finding F2/F3 follow-up: "tests per site: CAS no-op
 * on a concurrent upgrade, failure surfaces, success persists exactly
 * {encrypted, iv} returned by decryptFields."
 *
 * CAS predicate under test (src/iam/credential-loader.ts:145):
 *
 *   await col.updateOne(
 *     { _id: row._id, encrypted: row.encrypted },
 *     { $set: { encrypted: result.upgraded.encrypted, iv: result.upgraded.iv } },
 *   );
 *
 * Writer A is the REAL `loadIamCredentialsForTenant` entry point, run to
 * completion first (its CAS filter matches the seeded legacy row, so its
 * write succeeds). Writer B is simulated by directly re-running the
 * SAME decrypt (`decryptFields`, real crypto — this row is still legacy
 * from B's point of view, since B read it BEFORE A's write) and then
 * applying the IDENTICAL CAS predicate credential-loader.ts:145 uses,
 * against B's own real upgrade payload — proving that predicate, quoted
 * verbatim above, is what makes B's write a no-op rather than a clobber.
 *
 * Run (after `npm run build:native` and `tsc`): node --test dist/iam/credential-loader.concurrent-upgrade.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

process.env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');

const { loadIamCredentialsForTenant } = await import('./credential-loader.js');
const { decryptFields } = await import('./crypto.js');
const { setMongoClient } = await import('./db.js');
const { makeFakeCollection, makeFakeMongoClient } = await import('./testFakes/fakeMongoCollection.js');

const TENANT_ID = 'concurrent-tenant-adapter';
const ADAPTER_ID = 'adapter-x';
const FAKE_ADAPTERS = [
  { id: ADAPTER_ID, rest: { envKey: 'ADAPTER_X_API_KEY' } },
] as unknown as import('../engine/server/ChariotState.js').AdapterEntry[];

// master-key derivation: TEST FIXTURE ONLY (pre-CH-10 legacy ciphertext)
/** Legacy (pre-CH-10) fixture — see vaultMigrate.seed-all-sites.test.ts for the algorithm/rationale. */
async function legacyFixture(tenantId: string, plaintext: object): Promise<{ encrypted: string; iv: string }> {
  const { hkdfSync, randomBytes: rb, createCipheriv } = await import('node:crypto');
  const masterKey = Buffer.from(process.env.ENTERPRISE_MASTER_KEY!, 'base64');
  const salt = Buffer.from(`tenant:${tenantId}`);
  const key = Buffer.from(hkdfSync('sha256', masterKey, salt, Buffer.alloc(0), 32));
  const iv = rb(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(plaintext), 'utf-8')), cipher.final(), cipher.getAuthTag()]);
  return { encrypted: ct.toString('base64'), iv: iv.toString('base64') };
}

test('§12.2/CH-10 item 59: credential-loader — concurrent upgrade race: writer A persists, writer B\'s CAS is a no-op, B still returns correct plaintext', async () => {
  const fixture = await legacyFixture(TENANT_ID, { apiKey: 'concurrent-secret' });
  const col = makeFakeCollection([
    { _id: 'row-1', tenantId: TENANT_ID, adapterId: ADAPTER_ID, status: 'active', shared: true, encrypted: fixture.encrypted, iv: fixture.iv },
  ]);
  setMongoClient(makeFakeMongoClient({ iam_adapter_credentials: col }), 'chariot');

  // B reads the row BEFORE A's write — captured here, exactly as B would
  // have via its own col.find().toArray() call at that moment.
  const rowAsBReadIt = { ...col.docs[0]! };

  // Writer A: the REAL production entry point, run to completion. Its
  // internal CAS filter ({_id, encrypted: row.encrypted}) matches the
  // still-legacy row, so its write-back succeeds.
  const credsA = await loadIamCredentialsForTenant(TENANT_ID, FAKE_ADAPTERS);
  assert.equal(credsA.ADAPTER_X_API_KEY, 'concurrent-secret', 'writer A must return the correct plaintext');
  assert.ok((col.docs[0]!.encrypted as string).startsWith('v2:'), 'writer A\'s CAS write must have persisted the v2 ciphertext');
  const afterA = col.docs[0]!.encrypted;

  // Writer B: decrypts the SAME (now-stale, from B's perspective) legacy
  // row it read before A won, producing its own real v2 upgrade payload,
  // then applies the EXACT CAS predicate credential-loader.ts:145 uses.
  const resultB = await decryptFields(rowAsBReadIt.encrypted as string, rowAsBReadIt.iv as string, TENANT_ID, ADAPTER_ID);
  assert.equal(resultB.fields.apiKey, 'concurrent-secret', 'B\'s own decrypt must also return the correct plaintext');
  assert.ok(resultB.upgraded, 'B must also have computed a legacy-record upgrade (it read the row before A wrote)');
  const casB = await col.updateOne(
    { _id: rowAsBReadIt._id, encrypted: rowAsBReadIt.encrypted }, // credential-loader.ts:145's exact CAS filter
    { $set: { encrypted: resultB.upgraded!.encrypted, iv: resultB.upgraded!.iv } },
  );
  assert.equal(casB.matchedCount, 0, 'B\'s CAS must be a no-op — the row no longer holds the stale ciphertext B read');
  assert.equal(col.docs[0]!.encrypted, afterA, 'the row must STILL hold exactly A\'s upgraded ciphertext — never clobbered by B');
});

test('§12.2/CH-10 item 59: credential-loader — a genuine write-back failure surfaces (denies the call), never silently succeeds', async () => {
  const fixture = await legacyFixture(TENANT_ID, { apiKey: 'concurrent-secret-2' });
  const col = makeFakeCollection([
    { _id: 'row-2', tenantId: TENANT_ID, adapterId: ADAPTER_ID, status: 'active', shared: true, encrypted: fixture.encrypted, iv: fixture.iv },
  ]);
  setMongoClient(makeFakeMongoClient({ iam_adapter_credentials: col }), 'chariot');
  col.failNextUpdateOnce(new Error('simulated MongoDB write failure'));

  await assert.rejects(
    () => loadIamCredentialsForTenant(TENANT_ID, FAKE_ADAPTERS),
    /VAULT_UPGRADE_PERSIST_FAILED/,
    'a genuine write-back failure must deny the call (propagate), not silently succeed with the row left legacy',
  );
});
