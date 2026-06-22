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
 * Ordered list of bundled Ed25519 public keys accepted by the default
 * catalog verification path. Verification iterates this array and
 * succeeds if a signature validates against ANY entry. Order affects
 * only logging (the matched entry's `id` is recorded); rotation order
 * is documented in the module-level JSDoc above.
 *
 * As of 2026-05-13 the production key (`chariot-catalog-prod-2026-05-07`)
 * is the only accepted key. The upstream catalog publisher now signs
 * with the matching production private key; every bundled catalog on
 * disk verifies against the production key and no dev-signed catalog
 * remains in the release surface. The previous dev key is dropped.
 */
export const CHARIOT_CATALOG_PUBLIC_KEYS: ReadonlyArray<ChariotCatalogPublicKey> = [
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
