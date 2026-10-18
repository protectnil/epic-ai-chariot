/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10), rulings item 59. Gate finding
 * F2/F3 follow-up: "tests per site: CAS no-op on a concurrent upgrade,
 * failure surfaces, success persists exactly {encrypted, iv} returned by
 * decryptFields."
 *
 * CAS predicate under test (src/iam/routes/oidc.ts,
 * `resolveOidcClientSecret`):
 *
 *   const writeRes = await col.updateOne(
 *     { tenantId, [`${sourceField}.clientSecretEncrypted`]: oidcConfig.clientSecretEncrypted },
 *     { $set: { [`${sourceField}.clientSecretEncrypted`]: `${result.upgraded.encrypted}:${result.upgraded.iv}` } },
 *   );
 *
 * Writer A is the REAL `resolveOidcClientSecret` entry point, run to
 * completion first. Writer B is simulated by re-decrypting the SAME
 * stale (pre-A-write) tenant doc it would have read, then applying the
 * IDENTICAL CAS predicate against B's own real upgrade payload.
 *
 * Run (after `npm run build:native` and `tsc`): node --test dist/iam/routes/oidc.concurrent-upgrade.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, hkdfSync, createCipheriv } from 'node:crypto';

process.env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');

const { resolveOidcClientSecret } = await import('./oidc.js');
const { decryptFields, splitEncryptedIv } = await import('../crypto.js');
const { setMongoClient } = await import('../db.js');
const { makeFakeCollection, makeFakeMongoClient, getPath } = await import('../testFakes/fakeMongoCollection.js');

const TENANT_ID = 'concurrent-tenant-oidc';
const SOURCE_FIELD = 'settings.oidc' as const;

// master-key derivation: TEST FIXTURE ONLY (pre-CH-10 legacy ciphertext)
async function legacyFixture(tenantId: string, plaintext: object): Promise<{ encrypted: string; iv: string }> {
  const masterKey = Buffer.from(process.env.ENTERPRISE_MASTER_KEY!, 'base64');
  const salt = Buffer.from(`tenant:${tenantId}`);
  const key = Buffer.from(hkdfSync('sha256', masterKey, salt, Buffer.alloc(0), 32));
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(plaintext), 'utf-8')), cipher.final(), cipher.getAuthTag()]);
  return { encrypted: ct.toString('base64'), iv: iv.toString('base64') };
}

test('§12.2/CH-10 item 59: oidc — concurrent upgrade race: writer A persists, writer B\'s CAS is a no-op, B still returns correct plaintext', async () => {
  const fixture = await legacyFixture(TENANT_ID, { value: 'concurrent-oidc-secret' });
  const col = makeFakeCollection([
    { _id: 'tenant-doc-1', tenantId: TENANT_ID, settings: { oidc: { clientSecretEncrypted: `${fixture.encrypted}:${fixture.iv}` } } },
  ]);
  setMongoClient(makeFakeMongoClient({ iam_tenants: col }), 'chariot');

  // B reads the doc BEFORE A's write.
  const docAsBReadIt = structuredClone(col.docs[0]!);

  const oidcConfig = { clientSecretEncrypted: `${fixture.encrypted}:${fixture.iv}` } as unknown as import('../types.js').OidcConfig;
  const secretA = await resolveOidcClientSecret(oidcConfig, TENANT_ID, SOURCE_FIELD);
  assert.equal(secretA, 'concurrent-oidc-secret', 'writer A must return the correct plaintext');
  const afterA = getPath(col.docs[0], 'settings.oidc.clientSecretEncrypted') as string;
  assert.ok(afterA.startsWith('v2:'), 'writer A must persist a v2 ciphertext');

  // Writer B: decrypts the SAME stale doc, then applies the EXACT CAS
  // predicate oidc.ts's resolveOidcClientSecret uses.
  const staleCombined = getPath(docAsBReadIt, 'settings.oidc.clientSecretEncrypted') as string;
  const staleParts = splitEncryptedIv(staleCombined)!;
  const resultB = await decryptFields(staleParts.encrypted, staleParts.iv, TENANT_ID, 'oidc-client-secret');
  assert.equal(resultB.fields.value, 'concurrent-oidc-secret', 'B\'s own decrypt must also return the correct plaintext');
  assert.ok(resultB.upgraded, 'B must also have computed a legacy-record upgrade');
  const casB = await col.updateOne(
    { tenantId: TENANT_ID, [`${SOURCE_FIELD}.clientSecretEncrypted`]: staleCombined },
    { $set: { [`${SOURCE_FIELD}.clientSecretEncrypted`]: `${resultB.upgraded!.encrypted}:${resultB.upgraded!.iv}` } },
  );
  assert.equal(casB.matchedCount, 0, 'B\'s CAS must be a no-op');
  assert.equal(
    getPath(col.docs[0], 'settings.oidc.clientSecretEncrypted'),
    afterA,
    'the field must STILL hold exactly A\'s upgraded value — never clobbered by B',
  );
});

test('§12.2/CH-10 item 59: oidc — a genuine write-back failure surfaces (fails the login attempt), never silently succeeds', async () => {
  const fixture = await legacyFixture(TENANT_ID, { value: 'concurrent-oidc-secret-2' });
  const col = makeFakeCollection([
    { _id: 'tenant-doc-2', tenantId: TENANT_ID, settings: { oidc: { clientSecretEncrypted: `${fixture.encrypted}:${fixture.iv}` } } },
  ]);
  setMongoClient(makeFakeMongoClient({ iam_tenants: col }), 'chariot');
  col.failNextUpdateOnce(new Error('simulated MongoDB write failure'));

  const oidcConfig = { clientSecretEncrypted: `${fixture.encrypted}:${fixture.iv}` } as unknown as import('../types.js').OidcConfig;
  await assert.rejects(
    () => resolveOidcClientSecret(oidcConfig, TENANT_ID, SOURCE_FIELD),
    /VAULT_UPGRADE_PERSIST_FAILED/,
  );
});
