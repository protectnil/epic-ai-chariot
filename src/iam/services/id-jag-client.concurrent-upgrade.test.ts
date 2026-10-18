/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10), rulings item 59. Gate finding
 * F2/F3 follow-up: "tests per site: CAS no-op on a concurrent upgrade,
 * failure surfaces, success persists exactly {encrypted, iv} returned by
 * decryptFields." Covers BOTH fields id-jag-client.ts upgrades.
 *
 * CAS predicates under test (src/iam/services/id-jag-client.ts):
 *
 *   clientSecretEncrypted (line ~194):
 *     await col.updateOne(
 *       { tenantId, issuer: idpIssuer, clientSecretEncrypted: doc.clientSecretEncrypted },
 *       { $set: { clientSecretEncrypted: `${result.upgraded.encrypted}:${result.upgraded.iv}` } },
 *     );
 *
 *   clientPrivateKeyEncrypted (line ~214):
 *     await col.updateOne(
 *       { tenantId, issuer: idpIssuer, clientPrivateKeyEncrypted: doc.clientPrivateKeyEncrypted },
 *       { $set: { clientPrivateKeyEncrypted: `${result.upgraded.encrypted}:${result.upgraded.iv}` } },
 *     );
 *
 * Writer A is the REAL `idpClientRegistry.getIdpClient` entry point, run
 * to completion first. Writer B is simulated by re-decrypting the SAME
 * stale (pre-A-write) doc it would have read, then applying the
 * IDENTICAL CAS predicate against B's own real upgrade payload.
 *
 * Run (after `npm run build:native` and `tsc`): node --test dist/iam/services/id-jag-client.concurrent-upgrade.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, hkdfSync, createCipheriv } from 'node:crypto';

process.env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');

const { idpClientRegistry } = await import('./id-jag-client.js');
const { decryptFields } = await import('../crypto.js');
const { setMongoClient } = await import('../db.js');
const { makeFakeCollection, makeFakeMongoClient } = await import('../testFakes/fakeMongoCollection.js');

const TENANT_ID = 'concurrent-tenant-idjag';
const ISSUER = 'https://idp.concurrent.test';

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

for (const [field, recordSuffix] of [
  ['clientSecretEncrypted', 'client-secret'],
  ['clientPrivateKeyEncrypted', 'client-private-key'],
] as const) {
  test(`§12.2/CH-10 item 59: id-jag-client ${field} — concurrent upgrade race: writer A persists, writer B's CAS is a no-op`, async () => {
    const fixture = await legacyFixture(TENANT_ID, { value: `concurrent-secret-${field}` });
    const authMethod = field === 'clientSecretEncrypted' ? 'client_secret_post' : 'private_key_jwt';
    const combined = `${fixture.encrypted}:${fixture.iv}`;
    const col = makeFakeCollection([
      { _id: 'idp-1', tenantId: TENANT_ID, issuer: ISSUER, active: true, authMethod, [field]: combined },
    ]);
    setMongoClient(makeFakeMongoClient({ iam_id_jag_idp_clients: col }), 'chariot');

    // B reads the doc BEFORE A's write.
    const docAsBReadIt = { ...col.docs[0]! };

    // Writer A: the real production entry point.
    const viewA = await idpClientRegistry.getIdpClient(TENANT_ID, ISSUER);
    assert.ok(viewA);
    const expectedPlaintext = `concurrent-secret-${field}`;
    const actualA = field === 'clientSecretEncrypted' ? viewA!.clientSecret : viewA!.clientPrivateKey;
    assert.equal(actualA, expectedPlaintext, 'writer A must return the correct plaintext');
    const afterA = col.docs[0]![field];
    assert.ok((afterA as string).startsWith('v2:'), 'writer A must persist a v2 ciphertext');

    // Writer B: decrypts the SAME stale doc, then applies the EXACT CAS
    // predicate id-jag-client.ts uses for this field.
    const recordId = `${ISSUER}:${recordSuffix}`;
    const staleCombined = docAsBReadIt[field] as string;
    const sep = staleCombined.lastIndexOf(':');
    const staleParts = { encrypted: staleCombined.slice(0, sep), iv: staleCombined.slice(sep + 1) };
    const resultB = await decryptFields(staleParts.encrypted, staleParts.iv, TENANT_ID, recordId);
    assert.equal(resultB.fields.value, expectedPlaintext, 'B\'s own decrypt must also return the correct plaintext');
    assert.ok(resultB.upgraded, 'B must also have computed a legacy-record upgrade');
    const casB = await col.updateOne(
      { tenantId: TENANT_ID, issuer: ISSUER, [field]: staleCombined },
      { $set: { [field]: `${resultB.upgraded!.encrypted}:${resultB.upgraded!.iv}` } },
    );
    assert.equal(casB.matchedCount, 0, 'B\'s CAS must be a no-op');
    assert.equal(col.docs[0]![field], afterA, 'the field must STILL hold exactly A\'s upgraded value — never clobbered by B');
  });

  test(`§12.2/CH-10 item 59: id-jag-client ${field} — a genuine write-back failure surfaces, never silently succeeds`, async () => {
    const fixture = await legacyFixture(TENANT_ID, { value: 'concurrent-secret-fail' });
    const authMethod = field === 'clientSecretEncrypted' ? 'client_secret_post' : 'private_key_jwt';
    const col = makeFakeCollection([
      { _id: 'idp-2', tenantId: TENANT_ID, issuer: ISSUER, active: true, authMethod, [field]: `${fixture.encrypted}:${fixture.iv}` },
    ]);
    setMongoClient(makeFakeMongoClient({ iam_id_jag_idp_clients: col }), 'chariot');
    col.failNextUpdateOnce(new Error('simulated MongoDB write failure'));

    await assert.rejects(
      () => idpClientRegistry.getIdpClient(TENANT_ID, ISSUER),
      /VAULT_UPGRADE_PERSIST_FAILED/,
    );
  });
}
