/**
 * CHARIOT::§5.1::9 — CHARIOT-SPEC.md ("Trust anchor", CH-52), verbatim node
 * text: "The Ed25519 verifying key used for catalog signature verification
 * SHALL be pinned to the compiled-in CHARIOT_CATALOG_PUBLIC_KEYS array
 * (src/engine/keys/chariot-catalog-public.ts)."
 * CHARIOT::§8.6::37: the load path "shall verify the Ed25519 envelope
 * signature against the embedded production public key, which is
 * KMS-signed per CH-52."
 *
 * This file pins the rotation set itself: the KMS-custodied production key
 * (CH-52, `ECC_NIST_EDWARDS25519`) is present and first, the prior
 * production key is still present for the dual-sign cycle, every entry is
 * a parseable Ed25519 SPKI, and `intersectWithRotationSet` accepts a
 * caller-supplied copy of the KMS key by MATERIAL.
 *
 * Run (after tsc): node --test dist/engine/keys/chariot-catalog-public.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import {
  CHARIOT_CATALOG_PUBLIC_KEYS,
  CHARIOT_CATALOG_PUBLIC_KEY_ID,
  CHARIOT_CATALOG_PUBLIC_KEY_PEM,
} from './chariot-catalog-public.js';
import { intersectWithRotationSet } from './verifyCatalogSignature.js';

/** SPKI (base64 DER) of the KMS production key's public half, exported 2026-08-06. */
const KMS_PROD_SPKI_B64 = 'MCowBQYDK2VwAyEAC5A3HFt51a9dg4jhcRA40vOCwRXi5AxDb+igChQZlbY=';
const KMS_PROD_ID = 'chariot-catalog-prod-2026-08-06-kms';
const PRIOR_PROD_ID = 'chariot-catalog-prod-2026-05-07';

function spkiB64(pem: string): string {
  return createPublicKey(pem).export({ type: 'spki', format: 'der' }).toString('base64');
}

test('rotation set holds the KMS production key first and the prior production key second', () => {
  assert.deepEqual(
    CHARIOT_CATALOG_PUBLIC_KEYS.map((k) => k.id),
    [KMS_PROD_ID, PRIOR_PROD_ID],
  );
});

test('every rotation-set entry is a parseable Ed25519 SPKI with unique id and unique material', () => {
  const ids = new Set<string>();
  const materials = new Set<string>();
  for (const key of CHARIOT_CATALOG_PUBLIC_KEYS) {
    const parsed = createPublicKey(key.pem);
    assert.equal(parsed.asymmetricKeyType, 'ed25519', `${key.id} is not ed25519`);
    ids.add(key.id);
    materials.add(spkiB64(key.pem));
  }
  assert.equal(ids.size, CHARIOT_CATALOG_PUBLIC_KEYS.length);
  assert.equal(materials.size, CHARIOT_CATALOG_PUBLIC_KEYS.length);
});

test('the KMS entry pins exactly the exported public half of the CH-52 key', () => {
  const kms = CHARIOT_CATALOG_PUBLIC_KEYS.find((k) => k.id === KMS_PROD_ID);
  assert.ok(kms, 'KMS production key missing from the rotation set');
  assert.equal(spkiB64(kms.pem), KMS_PROD_SPKI_B64);
});

test('intersectWithRotationSet accepts a caller-supplied copy of the KMS key by material, not by id', () => {
  const kms = CHARIOT_CATALOG_PUBLIC_KEYS.find((k) => k.id === KMS_PROD_ID);
  assert.ok(kms);
  const accepted = intersectWithRotationSet([{ id: 'some-other-label', pem: kms.pem }]);
  assert.equal(accepted.length, 1);
  assert.equal(accepted[0].pem, kms.pem);
});

test('legacy single-key aliases resolve to the first (KMS) entry', () => {
  assert.equal(CHARIOT_CATALOG_PUBLIC_KEY_ID, KMS_PROD_ID);
  assert.equal(CHARIOT_CATALOG_PUBLIC_KEY_PEM, CHARIOT_CATALOG_PUBLIC_KEYS[0].pem);
});
