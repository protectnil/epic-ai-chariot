/**
 * CHARIOT::§12.2 (CH-10) — "Master-key domain separation" registry.
 *
 * Machine-readable manifest of every consumer of `ENTERPRISE_MASTER_KEY`'s
 * HKDF-SHA256 `(salt, info)` pair, quoted from CHARIOT-SPEC.md §12.2:
 *
 *   "Every consumer of `ENTERPRISE_MASTER_KEY` SHALL therefore use a
 *   `(salt, info)` pair disjoint from that of every other consumer."
 *   (CHARIOT::§12.2::11)
 *
 *   "A consumer of `ENTERPRISE_MASTER_KEY` whose HKDF-SHA256 salt could
 *   equal `tenant:{tenantId}` SHALL NOT use an empty `info` parameter."
 *   (CHARIOT::§12.2::12)
 *
 * `masterKeyConsumers.test.ts` (colocated) is the automated enforcement:
 * it (a) source-scans each registered file for the literal salt/info bytes
 * claimed here so this manifest cannot silently drift from the code, (b)
 * proves every pair in `MASTER_KEY_CONSUMERS` is pairwise disjoint, (c)
 * proves every consumer whose salt could collide with the vault's
 * `tenant:{tenantId}` salt uses a non-empty `info`, and (d) greps the repo
 * for HKDF/ENTERPRISE_MASTER_KEY call sites and fails if one is found whose
 * file is not in this manifest.
 *
 * Adding a NEW consumer of ENTERPRISE_MASTER_KEY (CHARIOT::§12.2::13/14)
 * REQUIRES an entry here in the SAME change, with a salt/info pair proven
 * disjoint from every existing entry by the tests above — the coverage
 * test in masterKeyConsumers.test.ts fails closed on an unregistered call
 * site.
 */

/** The HKDF-SHA256 `salt` a consumer uses, shaped for automated comparison. */
export type SaltShape =
  /** A fixed byte string with no per-call variation, e.g. the MFA salt. */
  | { readonly kind: 'literal'; readonly value: string }
  /**
   * A per-call string that always begins with a fixed `prefix` (e.g. the
   * vault's `tenant:{tenantId}` — prefix `tenant:`, the variable part is
   * the tenantId). Any concrete value of this shape necessarily starts
   * with `prefix`, which is what makes prefix-based collision detection
   * against a `literal` or another `templatePrefix` sound.
   */
  | { readonly kind: 'templatePrefix'; readonly prefix: string; readonly template: string }
  /**
   * A per-call string with no fixed prefix this registry can pin (e.g. the
   * §5.7 edge-snapshot seal's `salt`, which is caller-supplied catalog/
   * license context, not a compile-time constant). Treated conservatively
   * as "could collide with anything" by the disjointness checker below —
   * an opaque salt can only be proven disjoint from another consumer via
   * its `info`.
   */
  | { readonly kind: 'opaque'; readonly description: string };

/** The HKDF-SHA256 `info` a consumer uses, shaped for automated comparison. */
export type InfoShape =
  | { readonly kind: 'empty' }
  | { readonly kind: 'literal'; readonly value: string }
  | { readonly kind: 'templatePrefix'; readonly prefix: string; readonly template: string };

export interface MasterKeyConsumer {
  /** Stable identifier for this consumer, used in test failure messages. */
  readonly id: string;
  /** Repo-relative path (from the repository root) of the file that owns the derivation. */
  readonly file: string;
  readonly salt: SaltShape;
  readonly info: InfoShape;
  /**
   * `'ENTERPRISE_MASTER_KEY'` when this consumer's HKDF input keying
   * material is (or can be) the shared enterprise master key; a consumer
   * that is rooted ONLY in a different secret (e.g. a per-license key) is
   * out of scope for §12.2's disjointness obligation per §12.2::13's
   * "or use a distinct secret root" escape hatch, but is still listed here
   * for completeness when it CAN be rooted in ENTERPRISE_MASTER_KEY.
   */
  readonly secretRoot: 'ENTERPRISE_MASTER_KEY' | 'per-license-secret';
}

// CHARIOT::§12.2::11 — the shipped consumers and their (salt, info) pairs,
// transcribed verbatim from CHARIOT-SPEC.md §12.2 "Master-key domain
// separation (CH-10)".
export const MASTER_KEY_CONSUMERS: readonly MasterKeyConsumer[] = [
  // "Credential vault (native/src/vault.rs) — salt `tenant:{tenantId}`,
  // empty `info`."
  {
    id: 'credential-vault',
    file: 'native/src/vault.rs',
    salt: { kind: 'templatePrefix', prefix: 'tenant:', template: 'tenant:{tenantId}' },
    info: { kind: 'empty' },
    secretRoot: 'ENTERPRISE_MASTER_KEY',
  },
  // "IAM MFA TOTP-secret store (src/iam/services/mfa.ts) — salt
  // `epic-ai/chariot/iam/mfa`, `info` `mfa:{tenantId}`."
  {
    id: 'iam-mfa-totp',
    file: 'src/iam/services/mfa.ts',
    salt: { kind: 'literal', value: 'epic-ai/chariot/iam/mfa' },
    info: { kind: 'templatePrefix', prefix: 'mfa:', template: 'mfa:{tenantId}' },
    secretRoot: 'ENTERPRISE_MASTER_KEY',
  },
  // "§5.7 sealed-EdgeShard data key (native/src/edge_snapshot.rs), when and
  // only when rooted in `ENTERPRISE_MASTER_KEY` rather than a per-license
  // secret key — salt = the catalog version identifier, `info`
  // `chariot-edge-snapshot-seal-v1`."
  {
    id: 'edge-snapshot-seal',
    file: 'native/src/edge_snapshot.rs',
    salt: {
      kind: 'opaque',
      description:
        'caller-supplied context (catalog version identifier / license id, ' +
        'CHARIOT::§5.7::16) — not a compile-time constant, so this registry ' +
        'cannot pin its shape and treats it conservatively as unable to be ' +
        'proven disjoint from another consumer by salt alone',
    },
    info: { kind: 'literal', value: 'chariot-edge-snapshot-seal-v1' },
    secretRoot: 'ENTERPRISE_MASTER_KEY',
  },
] as const;

// Consumers that are NOT separately registered above because they do not
// introduce a new HKDF (salt, info) FORMULA: they call an already-registered
// consumer's own derivation function with a caller-chosen identifier, which
// is exactly the disjointness invariant that consumer's own registry entry
// already covers. Full list + named callee: `DOCUMENTED_DELEGATORS` below.

// ── Test-fixture-only derivations (CHARIOT::§12.2::11 follow-on) ───────────
//
// These files perform a RAW HKDF-SHA256 + AES-256-GCM derivation from
// ENTERPRISE_MASTER_KEY that byte-for-byte reproduces the PRE-CH-10 legacy
// vault formula (salt `tenant:{tenantId}`, empty info — see
// `native/src/vault.rs`'s `V2_PREFIX`/legacy-path doc comments) purely to
// build a legacy ciphertext FIXTURE for testing the CH-10 upgrade-on-decrypt
// migration path. There is no production primitive that produces a legacy
// ciphertext post-CH-10 — encrypt_credential always emits a `v2:`-prefixed
// record — so this derivation exists ONLY inside these tests, is never
// exported, and is never imported by any production code path. They are
// NOT registered as consumers: they do not define an independent (salt,
// info) domain, they reproduce the credential-vault's OWN pre-fix formula
// deliberately, as a test fixture, not a live encryption path.
//
// `masterKeyConsumers.test.ts`'s coverage scan does NOT take this list on
// faith — a blanket "*.test.ts is exempt" rule would let a real derivation
// helper hide behind a `.test.ts` filename and still be imported by
// production code. Every entry here is verified (per file) to (a) have a
// `.test.ts` path, (b) be imported by NO non-test source file anywhere in
// `src/`, and (c) carry the `TEST_FIXTURE_MARKER` comment below verbatim,
// which the scan's evasion corpus proves it actually enforces — a listed
// file failing any one of the three is still flagged as unregistered, with
// the specific missing condition named in the failure message.
export const TEST_FIXTURE_MARKER = '// master-key derivation: TEST FIXTURE ONLY (pre-CH-10 legacy ciphertext)';

export interface TestFixtureDeriver {
  readonly file: string;
  readonly reason: string;
}

export const TEST_FIXTURE_DERIVERS: readonly TestFixtureDeriver[] = [
  { file: 'src/iam/credential-loader.concurrent-upgrade.test.ts', reason: 'builds a pre-CH-10 legacy ciphertext fixture' },
  { file: 'src/iam/routes/oidc.concurrent-upgrade.test.ts', reason: 'builds a pre-CH-10 legacy ciphertext fixture' },
  { file: 'src/iam/services/id-jag-client.concurrent-upgrade.test.ts', reason: 'builds a pre-CH-10 legacy ciphertext fixture' },
  { file: 'src/iam/services/session.casSetWithTtl.concurrent-upgrade.test.ts', reason: 'builds a pre-CH-10 legacy ciphertext fixture' },
  { file: 'src/iam/vaultMigrate.seed-all-sites.test.ts', reason: 'builds a pre-CH-10 legacy ciphertext fixture' },
] as const;

// ── Documented delegators (CHARIOT::§12.2::11, structural-rule follow-on) ──
//
// A file that references master-key material (`ENTERPRISE_MASTER_KEY`,
// `getMasterKeyB64`, `masterKeyB64`, `master_key`, `masterKey`) AND
// references a crypto capability (an import of a crypto-shaped package, the
// bare `crypto`/`webcrypto`/`subtle` identifier, `globalThis...crypto`, or
// `Reflect.get`/`Reflect.apply`) is a STRUCTURAL derivation candidate per
// `masterKeyConsumers.test.ts`'s structural scan — regardless of whether it
// names an HKDF identifier anywhere. Every entry below was individually
// read and confirmed to call an ALREADY-REGISTERED consumer's own
// derivation function (never to derive independently) before being listed
// — the `callee` names exactly which one. `masterKeyConsumers.test.ts`
// verifies membership here does not (by itself) account for a file that
// independently triggers the identifier-based or computed-access
// detectors — see that file's coverage test for the full precedence.
export interface DocumentedDelegator {
  readonly file: string;
  /** The already-registered consumer's own derivation call this file makes, by file:function. */
  readonly callee: string;
  /**
   * Repo-relative path(s) of the callee module(s) named in `callee`, for
   * transitive chain verification (CHARIOT::§12.2::11 follow-on): every
   * path here must itself be a registered consumer (`MASTER_KEY_CONSUMERS`
   * `file`), another `DOCUMENTED_DELEGATORS` entry (recursed into), or a
   * `VALIDATION_ONLY_FILES` entry — walked by
   * `masterKeyConsumers.test.ts`'s coverage test, which fails naming a
   * cycle or a dead end (a callee that resolves to none of the three).
   */
  readonly calleeFiles: readonly string[];
}

export const DOCUMENTED_DELEGATORS: readonly DocumentedDelegator[] = [
  {
    file: 'src/engine/bin/build-edgeshard-snapshot.test.ts',
    callee: 'buildSnapshot with a fixture native sealer and loadSealedShardDescriptor configuration; the test forwards a fixture root but performs no derivation itself',
    calleeFiles: ['src/engine/bin/build-edgeshard-snapshot.ts', 'src/engine/retrieval/sealedShardConfig.ts'],
  },
  {
    file: 'src/engine/bin/build-edgeshard-snapshot.ts',
    callee: 'native/src/edge_snapshot.rs seal_edge_snapshot_file/unseal_and_verify_snapshot_to_file; Node crypto only hashes point identities and validates the signing public key',
    calleeFiles: ['native/src/edge_snapshot.rs'],
  },
  {
    file: 'src/engine/audit/chainSigner.ts',
    callee: 'src/iam/crypto.ts encryptFields/decryptFields -> native/src/vault.rs encrypt_credential/decrypt_credential (CH-10 vault primitives), tenantId=\'chariot-audit\' reserved within the vault\'s own tenant:{tenantId} salt space',
    calleeFiles: ['src/iam/crypto.ts'],
  },
  {
    file: 'src/engine/recovery/SqliteCheckpointStore.ts',
    callee: 'native encrypt_credential/decrypt_credential directly (via loadNativeBinding), keyed on the checkpoint row\'s own tenant_id',
    calleeFiles: ['native/src/vault.rs'],
  },
  {
    file: 'src/iam/crypto.ts',
    callee: 'native/src/vault.rs encrypt_credential/decrypt_credential via src/license/binding.ts loadNativeBinding() — this IS the credential-vault\'s TS wrapper; its own node:crypto import is createHash/randomBytes/timingSafeEqual for unrelated SCIM token hashing, not HKDF',
    calleeFiles: ['native/src/vault.rs'],
  },
  {
    file: 'src/iam/services/tenant.ts',
    callee: 'src/iam/crypto.ts encryptFields',
    calleeFiles: ['src/iam/crypto.ts'],
  },
  {
    file: 'src/iam/vaultMigrate.ts',
    callee: 'src/iam/crypto.ts encryptFields/decryptFieldsForVaultMigration',
    calleeFiles: ['src/iam/crypto.ts'],
  },
  {
    file: 'src/license/binding.ts',
    callee: 'hosts loadNativeBinding(), the native-addon loader src/iam/crypto.ts calls into, and declares masterKeyB64 parameter TYPES matching native/src/vault.rs encrypt_credential/decrypt_credential\'s signature — never calls them itself; its own node:crypto import (createHash/createPublicKey/verify) is for license-signature verification, unrelated to the master key',
    calleeFiles: ['native/src/vault.rs'],
  },
  {
    file: 'src/engine/audit/chainSigner.test.ts',
    callee: 'src/engine/audit/chainSigner.ts sealSigningKey',
    calleeFiles: ['src/engine/audit/chainSigner.ts'],
  },
  {
    file: 'src/engine/audit/auditCadence.chainSigner.test.ts',
    callee: 'src/engine/audit/chainSigner.ts sealSigningKey',
    calleeFiles: ['src/engine/audit/chainSigner.ts'],
  },
  {
    file: 'src/engine/audit/auditCadence.warning-not-throw.test.ts',
    callee: 'src/engine/audit/chainSigner.ts sealSigningKey',
    calleeFiles: ['src/engine/audit/chainSigner.ts'],
  },
  {
    file: 'src/cli/cli-honest-signal.test.ts',
    callee: 'src/engine/audit/chainSigner.ts sealSigningKey',
    calleeFiles: ['src/engine/audit/chainSigner.ts'],
  },
  {
    file: 'src/iam/crypto.aad-binding.test.ts',
    callee: 'src/iam/crypto.ts encryptFields/decryptFields',
    calleeFiles: ['src/iam/crypto.ts'],
  },
  {
    file: 'src/iam/crypto.ch10-cutover.test.ts',
    callee: 'src/iam/crypto.ts encryptFields/decryptFields/decryptFieldsForVaultMigration',
    calleeFiles: ['src/iam/crypto.ts'],
  },
  {
    file: 'src/engine/recovery/SqliteCheckpointStore.ch10-legacy-allowed.test.ts',
    callee: 'src/engine/recovery/SqliteCheckpointStore.ts (constructed directly, exercising its already-documented delegation)',
    calleeFiles: ['src/engine/recovery/SqliteCheckpointStore.ts'],
  },
  {
    file: 'src/bin/chariot.ts',
    callee: 'src/engine/audit/chainSigner.ts sealSigningKey (the `chariot` CLI\'s key-sealing command dynamically imports and calls it); also calls src/iam/crypto.ts validateMasterKey() elsewhere for format checking only',
    calleeFiles: ['src/engine/audit/chainSigner.ts'],
  },
] as const;

// ── Validation-only master-key references (CHARIOT::§12.2::11, structural-
// rule follow-on) ────────────────────────────────────────────────────────
//
// A file below references master-key material AND a crypto capability
// (usually only a TYPE-level `import('node:crypto').KeyObject`, or an
// unrelated crypto import used for something else entirely, e.g. Ed25519
// signature verification) but performs NEITHER a raw derivation NOR a call
// to any registered/delegated encrypt/decrypt function — it only checks
// that ENTERPRISE_MASTER_KEY is present/well-formed (`validateMasterKey`/
// `getMasterKeyB64`), or sets the env var so a SPAWNED subprocess (which
// itself does the real work, under its own accounting) can start.
// `masterKeyConsumers.test.ts` verifies this negatively: a listed file must
// NOT contain a call to any known derivation/delegator function — if it
// does, the listing itself is stale and the coverage test fails, naming the
// file, so a real derivation call can never hide behind this label.
export const VALIDATION_ONLY_MARKER = '// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)';

export interface ValidationOnlyFile {
  readonly file: string;
  readonly reason: string;
}

export const VALIDATION_ONLY_FILES: readonly ValidationOnlyFile[] = [
  { file: 'src/bin/audit-verify-length-rotation.test.ts', reason: 'sets ENTERPRISE_MASTER_KEY only in a SPAWNED subprocess\'s env so that process\'s own startup gate passes; never calls a derivation/delegator function directly' },
  { file: 'src/engine/bin/setup.test.ts', reason: 'sets ENTERPRISE_MASTER_KEY only in a spawned/tested process\'s env so that process\'s own startup gate passes; never calls a derivation/delegator function directly' },
  { file: 'src/iam/bootstrap.enterprise-gate.test.ts', reason: 'tests requireMasterKeyForEnterpriseStartup -> validateMasterKey() (format check only); never calls a derivation/delegator function directly' },
  { file: 'src/iam/bootstrap.ts', reason: 'imports and calls src/iam/crypto.ts validateMasterKey() (format check only) from requireMasterKeyForEnterpriseStartup; never calls a derivation/delegator function' },
  { file: 'src/bin/audit-rotate-key.test.ts', reason: 'references ENTERPRISE_MASTER_KEY for a spawned CLI subprocess\'s env only; no crypto capability, no derivation/delegator call' },
  { file: 'src/engine/audit/custodyCheck.ts', reason: 'audits WHO can read/rotate ENTERPRISE_MASTER_KEY (an attestation/custody check on the credential, not a use of it); no crypto capability, no derivation/delegator call' },
  { file: 'src/engine/audit/keyRotation.test.ts', reason: 'tests key-rotation bookkeeping around ENTERPRISE_MASTER_KEY; no crypto capability, no derivation/delegator call' },
  { file: 'src/engine/bin/seal-edge-snapshot.ts', reason: 'reads ENTERPRISE_MASTER_KEY as a CLI arg source and forwards it as the §5.7 secret root parameter to the native edge-snapshot sealer; no crypto capability referenced in this file itself, no derivation/delegator call' },
  { file: 'src/engine/bin/setup.ts', reason: 'reads/forwards ENTERPRISE_MASTER_KEY as part of enterprise bootstrap plumbing; no crypto capability, no derivation/delegator call' },
  { file: 'src/engine/retrieval/nativeEdge.ts', reason: 'references ENTERPRISE_MASTER_KEY only in a doc comment describing the §5.7 secret-root contract; no crypto capability, no derivation/delegator call' },
  { file: 'src/engine/retrieval/sealedShardConfig.test.ts', reason: 'tests §5.7 operator config resolution around ENTERPRISE_MASTER_KEY; no crypto capability, no derivation/delegator call' },
  { file: 'src/engine/retrieval/sealedShardConfig.ts', reason: 'resolves the §5.7 secret-root operator config (which may be ENTERPRISE_MASTER_KEY) and forwards it; no crypto capability, no derivation/delegator call' },
  { file: 'src/engine/server/ChariotState.sealed-shard.test.ts', reason: 'tests §5.7 sealed-shard loading wiring around ENTERPRISE_MASTER_KEY; no crypto capability, no derivation/delegator call' },
  { file: 'src/iam/bootstrap.jwt-secret-floor.test.ts', reason: 'tests the JWT-secret bootstrap floor alongside master-key gating; no crypto capability, no derivation/delegator call' },
  { file: 'src/iam/bootstrap.master-key-before-mongo.test.ts', reason: 'tests that validateMasterKey() runs before the Mongo dial (source-order regression); no crypto capability, no derivation/delegator call' },
  { file: 'src/iam/inProcessRedisShim.ts', reason: 'references ENTERPRISE_MASTER_KEY only in a doc comment describing the enterprise-mode gate; no crypto capability, no derivation/delegator call' },
  { file: 'src/iam/services/tenant.encryption-keyref.test.ts', reason: 'tests the tenant encryptionKeyRef field, whose default value is the string \'env:ENTERPRISE_MASTER_KEY\'; no crypto capability, no derivation/delegator call' },
  {
    file: 'src/iam/services/mfa.taxonomy-adoption.test.ts',
    reason:
      'sets a random ENTERPRISE_MASTER_KEY (via node:crypto randomBytes — a genuine crypto-capability import, unlike every other entry above) so it can drive saveMfaSecret() end-to-end and assert the CHARIOT::§16.1 mfa.enrolled emit; the actual encrypt call (encryptTotpSecret) is made BY mfa.ts, an already-registered MASTER_KEY_CONSUMERS entry — this file itself never calls encryptFields/decryptFields/decryptFieldsForVaultMigration/sealSigningKey/encryptCredential/decryptCredential (KNOWN_DERIVATION_OR_DELEGATOR_CALL), so it is a validation-only (key-presence) reference rather than a derivation or a delegation, despite carrying a real crypto import',
  },
] as const;

// ── Dynamic loader sites (CHARIOT::§12.2::11, MASTER ruling accept-all) ────
//
// These five call sites are the product's DESIGNED dynamic-loading points —
// they legitimately cannot take a static `import()`/`require()` specifier,
// because the whole point is loading a module chosen at runtime (which
// adapter package the catalog names, which platform's native addon this
// process is running on). `local/no-dynamic-module-specifier` (eslint-
// rules/no-dynamic-module-specifier.js) forbids a non-literal specifier
// everywhere else in the repo; these five are the ONLY exemptions, each
// marked EXPLICITLY at the exact call site with `// eslint-disable-next-
// line local/no-dynamic-module-specifier -- DYNAMIC_LOADER_SITES: <reason>`
// — never a bare disable with no reason, and never silent.
//
// `loads` states what class of module each site loads, so the disable is
// auditable against what it actually grants, not just that it exists:
//   - 'adapter-package': a vendor/community REST adapter module, resolved
//     from the signed catalog and confined to the package root by
//     `confinePath()` before the import. Adapter packages receive
//     CREDENTIALS THROUGH THE VAULT API (state.credentials / the
//     per-adapter envKey allowlist) — they are never handed
//     ENTERPRISE_MASTER_KEY itself.
//   - 'native-addon': THIS repo's own compiled native binary
//     (`chariot-native.node` / a platform-specific `@epicai/chariot-bin-*`
//     package), selected by `process.platform`/`process.arch`. The loaded
//     module IS the registered consumer `native/src/vault.rs` (see
//     `MASTER_KEY_CONSUMERS` above) — loading it is not a NEW exposure of
//     ENTERPRISE_MASTER_KEY, it is how the already-registered consumer's
//     code reaches this process at all.
//
// `masterKeyConsumers.test.ts`'s coverage test verifies, per listed file:
// exactly one `local/no-dynamic-module-specifier` disable directive exists
// and it carries the `DYNAMIC_LOADER_SITES:` marker; and, repo-wide, NO
// OTHER disable directive exists anywhere under `src/` for THIS rule or for
// `local/no-dynamic-crypto-access` — an unlisted directive fails the test
// naming the file:line, so a new disable can never land unaccounted for.
export const DYNAMIC_LOADER_SITES: readonly {
  readonly file: string;
  readonly reason: string;
  readonly loads: 'adapter-package' | 'native-addon';
}[] = [
  {
    file: 'src/engine/bin/setup.ts',
    reason: 'adapter package resolved from the signed catalog and confined by confinePath() to the package root before this import',
    loads: 'adapter-package',
  },
  {
    file: 'src/engine/server/toolHandlers.ts',
    reason: 'adapter package resolved from the signed catalog and confined by confinePath() to the package root before this import',
    loads: 'adapter-package',
  },
  {
    file: 'src/engine/federation/sandbox/SandboxManager.ts',
    reason: 'adapter package resolved from the signed catalog and confined by confinePath() to SANDBOX_PACKAGE_ROOT before this import',
    loads: 'adapter-package',
  },
  {
    file: 'src/engine/retrieval/nativeEdge.ts',
    reason: 'native addon package name selected by platform (process.platform/process.arch lookup, same package names as src/license/binding.ts\'s getPlatformPackage())',
    loads: 'native-addon',
  },
  {
    file: 'src/license/binding.ts',
    reason: 'native addon package name selected by platform via getPlatformPackage()',
    loads: 'native-addon',
  },
] as const;
