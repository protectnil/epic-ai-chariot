/**
 * @epicai/chariot — Bundled Ed25519 Public Key(s) for Adapter Catalog Signing
 *
 * `CHARIOT_CATALOG_PUBLIC_KEYS` is the ordered list of keys accepted when
 * `AdapterCatalog` verifies a bundled or registry catalog signature. A
 * signature that validates against any entry in the list is accepted; the
 * matched entry's `id` is logged. Order affects only logging.
 *
 * Rotation procedure: see SECURITY.md. Briefly: prepend a new entry, ship
 * the release; have the catalog publisher dual-sign for one cycle; drop
 * the prior entry on the next release.
 *
 * The legacy single-string exports (`CHARIOT_CATALOG_PUBLIC_KEY_PEM`,
 * `CHARIOT_CATALOG_PUBLIC_KEY_ID`) reference the first array entry and
 * exist only for downstream SDK consumers that imported the pre-array
 * shape. Internal verification walks `CHARIOT_CATALOG_PUBLIC_KEYS`.
 *
 * Each entry's PEM is the SPKI form of an Ed25519 public key, embedded as
 * a contiguous string so this module imports cleanly under both ESM and
 * CJS without filesystem side effects.
 */

export interface ChariotCatalogPublicKey {
  /** Short stable identifier. Logged on every signature verification so
   *  operators can tell from a log line which key was in use. Bump
   *  when the key rotates. */
  id: string;
  /** Ed25519 public key, SPKI PEM format. */
  pem: string;
}

const PROD_KEY_2026_05_07: ChariotCatalogPublicKey = {
  id: 'chariot-catalog-prod-2026-05-07',
  pem:
    '-----BEGIN PUBLIC KEY-----\n' +
    'MCowBQYDK2VwAyEA67SjghRLl69hQlWUFtXqNv4WWCga1LcpQRNjp82TDxY=\n' +
    '-----END PUBLIC KEY-----\n',
};

/**
 * Production catalog/bundle signing key custodied in AWS KMS (CH-52:
 * key spec `ECC_NIST_EDWARDS25519`, signing mode pure `ED25519_SHA_512`
 * / `MessageType:RAW`; the private key never leaves the HSM and
 * verification here stays offline — CHARIOT-SPEC §5.1 "Catalog signature
 * verification SHALL NOT contact AWS KMS at verification time"). Public
 * half exported from the key on 2026-08-06; the SPKI below is the
 * byte-for-byte pin of that export. Prepended per the rotation procedure
 * in this module's header: the publisher dual-signs for one cycle, then
 * `PROD_KEY_2026_05_07` is dropped on the following release.
 */
const PROD_KEY_2026_08_06_KMS: ChariotCatalogPublicKey = {
  id: 'chariot-catalog-prod-2026-08-06-kms',
  pem:
    '-----BEGIN PUBLIC KEY-----\n' +
    'MCowBQYDK2VwAyEAC5A3HFt51a9dg4jhcRA40vOCwRXi5AxDb+igChQZlbY=\n' +
    '-----END PUBLIC KEY-----\n',
};

/**
 * Ordered list of bundled Ed25519 public keys accepted by the default
 * catalog verification path. Verification iterates this array and
 * succeeds if a signature validates against ANY entry. Order affects
 * only logging (the matched entry's `id` is recorded); rotation order
 * is documented in the module-level JSDoc above.
 *
 * As of 2026-05-13 the production key (`chariot-catalog-prod-2026-05-07`)
 * replaced the development key, which is dropped; no dev-signed catalog
 * remains in the release surface.
 *
 * As of 2026-09-05 the KMS-custodied production key
 * (`chariot-catalog-prod-2026-08-06-kms`, CH-52) is prepended and both
 * production keys are accepted for the dual-sign rotation cycle: bundles
 * already on disk (signed with the 2026-05-07 key) keep verifying, and
 * bundles signed by the KMS key verify against the same compiled-in set
 * (CHARIOT-SPEC §5.1: "The Ed25519 verifying key SHALL be pinned to the
 * compiled-in CHARIOT_CATALOG_PUBLIC_KEYS array"; §8.6: the load path
 * verifies "against the embedded production public key, which is
 * KMS-signed per CH-52"). The 2026-05-07 key is dropped on the release
 * after the publisher's cut-over.
 */
export const CHARIOT_CATALOG_PUBLIC_KEYS: ReadonlyArray<ChariotCatalogPublicKey> = [
  PROD_KEY_2026_08_06_KMS,
  PROD_KEY_2026_05_07,
];

/**
 * Backward-compatible alias for the legacy single-key API. Always
 * resolves to the FIRST entry of `CHARIOT_CATALOG_PUBLIC_KEYS`.
 * Kept as a const string so existing imports continue to compile.
 */
export const CHARIOT_CATALOG_PUBLIC_KEY_PEM: string =
  CHARIOT_CATALOG_PUBLIC_KEYS[0].pem;

/**
 * Backward-compatible alias for the legacy single-key API. Always
 * resolves to the FIRST entry's `id`. Kept as a const string so existing
 * imports continue to compile and so existing log lines that reference
 * this constant continue to surface a meaningful key id.
 */
export const CHARIOT_CATALOG_PUBLIC_KEY_ID: string =
  CHARIOT_CATALOG_PUBLIC_KEYS[0].id;
