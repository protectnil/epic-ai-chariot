/**
 * @epicai/chariot — Audit Chain Signer (CHARIOT::§9.8.1 key custody)
 *
 * CHARIOT-SPEC.md §9.8.1, "Trust root and key custody" (see
 * docs/spec/CHARIOT-SPEC.md:899-906 for the exact governing bytes):
 *
 *   "The signing key MUST reside in a KMS, HSM, or sealed-store with
 *   audited access (e.g., AWS KMS, HashiCorp Vault transit engine, an
 *   HSM with PKCS#11 interface). Plaintext key material MUST NOT be
 *   stored on the application host filesystem."
 *
 * Prior to this module the IAM/audit chain signing key was read straight
 * from `CHARIOT_AUDIT_SIGNING_KEY` (plaintext PEM in the process
 * environment) with no custody abstraction — see auditCadence.ts and
 * length-attestation.ts's `signLengthAttestation(payload, privateKeyPem)`.
 * `ChainSigner` replaces the bare env-var read with a pluggable backend so
 * enterprise deployments can satisfy the MUST above.
 *
 * gate finding F1 (2026-09-04, BLOCK): an earlier version of this
 * module kept a fourth `env` backend (plaintext `CHARIOT_AUDIT_SIGNING_KEY`)
 * that was merely REFUSED outside enterprise mode. CHARIOT §9.8.1's MUST is
 * unconditional — "Plaintext key material MUST NOT be stored on the
 * application host filesystem" does not carve out single-user mode. The
 * `env` backend is REMOVED entirely; there are exactly three backends now
 * (`kms`, `vault-transit`, `sealed-store`), and the default — when
 * `CHARIOT_AUDIT_SIGNER_BACKEND` is unset — is `sealed-store`, not a
 * plaintext fallback. A single-user install with no `ENTERPRISE_MASTER_KEY`
 * configured (the sealed-store's own prerequisite — see src/iam/crypto.ts
 * `getMasterKeyB64()`, which THROWS unconditionally, single-user or
 * enterprise, when the key is absent/insecure) simply cannot attest until
 * an operator provisions a custody backend — `chariot audit attest` and the
 * periodic cadence report `SIGNING_KEY_NOT_CONFIGURED` naming all three
 * options rather than silently degrading to plaintext. `chariot audit
 * custody import-key` is the one-time path for an operator who already has
 * a PEM: it seals the key into sealed-store and tells the operator to
 * delete the plaintext source themselves (this code never deletes a file a
 * human didn't ask it to).
 *
 * Backend honesty note (corrected 2026-09-04 against vendor docs — see
 * docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html,
 * docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html, and the
 * 2025-11 AWS announcement of KMS EdDSA support): AWS KMS supports Ed25519
 * natively via key spec `ECC_NIST_EDWARDS25519` ("signing and verification
 * only"; "The private key that generates signatures never leaves AWS KMS
 * unencrypted") with `Sign` API `SigningAlgorithm: 'ED25519_SHA_512'` +
 * `MessageType: 'RAW'` (the raw, un-pre-hashed message; `ED25519_PH_SHA_512`
 * requires `MessageType: 'DIGEST'` and pre-hashes AGAIN inside KMS — using
 * it on our already-raw payload would double-hash and is deliberately NOT
 * used here) and `GetPublicKey` returning the SPKI DER public key + the
 * key's `KeySpec`. The `kms` backend below is therefore TRUE remote
 * signing — like `vault-transit` — never holding the private key,
 * plaintext or encrypted, on the application host at all; `GetPublicKey`'s
 * `KeySpec` is checked against `ECC_NIST_EDWARDS25519` and any other spec
 * is refused with an actionable error. HashiCorp Vault's transit engine
 * also supports a native `ed25519` key type, so `vault-transit` remains a
 * true remote-signing backend too — the private key never leaves Vault.
 *
 * `@aws-sdk/client-kms` is NOT a dependency of this package (see
 * package.json) — it is loaded lazily via dynamic `import()` so the
 * public package gains no new hard dependency; absence produces a clear
 * actionable error rather than a build failure.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import {
  createHash,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { resolvePublicKey, resolvePrivateKey } from './key-utils.js';
import { atomicWriteNew, atomicOverwriteIfUnchanged } from './auditFs.js';
import {
  encryptFields,
  decryptFields,
  decryptFieldsForVaultMigration,
  isLegacyCiphertext,
  VaultUpgradePersistFailedError,
  type VaultMigrateCounts,
  emptyVaultMigrateCounts,
} from '../../iam/crypto.js';
import { isEnterpriseModeRequested } from '../../iam/bootstrap.js';
import { loadVerifyKeyStore } from './verifyKeyStore.js';
import { checkKmsCustody, checkVaultCustody, checkSealedStoreCustody } from './custodyCheck.js';

export type ChainSignerBackend = 'kms' | 'vault-transit' | 'sealed-store';

export interface ChainSignerKeyInfo {
  kid: string;
  publicKeyPem: string;
}

/** Abstraction over "something that can Ed25519-sign audit-chain payloads
 * without exposing plaintext key material on the application host
 * filesystem" — CHARIOT::§9.8.1::1. */
export interface ChainSigner {
  readonly backend: ChainSignerBackend;
  sign(payload: Buffer): Promise<Buffer>;
  getKeyInfo(): Promise<ChainSignerKeyInfo>;
}

/** Injectable transports for testing the kms/vault-transit backends without
 * touching the network (BUILD-BRIEF requirement: "fake transport, no
 * network"). Production callers omit this and get the real AWS SDK /
 * global fetch. */
export interface ChainSignerDeps {
  kmsClientFactory?: (region: string | undefined) => {
    send: (cmd: unknown) => Promise<unknown>;
  };
  kmsGetPublicKeyCommandCtor?: new (input: { KeyId: string }) => unknown;
  kmsSignCommandCtor?: new (input: {
    KeyId: string;
    Message: Uint8Array;
    MessageType: string;
    SigningAlgorithm: string;
  }) => unknown;
  kmsGetKeyPolicyCommandCtor?: new (input: { KeyId: string; PolicyName: string }) => unknown;
  fetchImpl?: typeof fetch;
}

// ── kid derivation ──────────────────────────────────────────────────────────

/**
 * Deterministic key id: sha256 of the SPKI DER encoding of the public key,
 * hex, truncated to 16 chars — same shape as the `kid` convention already
 * used for JWKS lookups (src/license/loader.ts:337-374) and multi-key
 * verification is keyed off it (CHARIOT::§9.8.1::3).
 */
export function computeKid(publicKey: string | KeyObject): string {
  const key = resolvePublicKey(publicKey);
  const der = key.export({ type: 'spki', format: 'der' }) as Buffer;
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}

// ── audited access logging (CHARIOT::§9.8.1::2) ─────────────────────────────

/**
 * CHARIOT::§9.8.1::2 — "Key access MUST be gated by the same MFA and RBAC
 * controls used for production database root credentials." Logging alone is
 * NOT the gate (gate finding F4) — see custodyCheck.ts for the
 * application-enforced check run before a signer is constructed in
 * enterprise mode. This log line remains as the audit trail of WHO/WHEN a
 * key already cleared to sign was actually used.
 */
function logKeyAccess(
  backend: ChainSignerBackend,
  kid: string,
  action: 'sign' | 'decrypt' | 'access',
  principal?: string,
): void {
  process.stderr.write(
    JSON.stringify({
      ts: new Date().toISOString(),
      event: 'audit.signing_key.access',
      backend,
      kid,
      action,
      principal: principal ?? 'unknown',
    }) + '\n',
  );
}

// ── sealed-store backend ─────────────────────────────────────────────────────

/**
 * CH-10 (§12.2) 4-argument vault API — the SAME AES-256-GCM +
 * ENTERPRISE_MASTER_KEY primitive already used for IAM adapter credentials
 * (src/iam/crypto.ts:74-121, backed by the native Rust binding). A fixed
 * `tenantId`/`recordId` pair binds the sealed audit-signing-key blob the
 * same anti-relocation way an adapter credential row is bound — the AAD
 * ties the ciphertext to this specific record so a copy-paste into a
 * different sealed-store location fails to decrypt.
 *
 * `getMasterKeyB64()` (src/iam/crypto.ts:26-49) throws unconditionally —
 * single-user or enterprise — when `ENTERPRISE_MASTER_KEY` is absent or an
 * insecure default, so a single-user install with no master key configured
 * cannot use this backend at all; `createChainSigner()` surfaces that as
 * `SIGNING_KEY_NOT_CONFIGURED` naming all three backends, never falling
 * back to plaintext (CHARIOT §9.8.1::1 is unconditional).
 */
export const SEALED_TENANT_ID = 'chariot-audit';
export const SEALED_RECORD_ID = 'signing-key';

interface SealedKeyArtifact {
  schemaVersion: 1;
  backend: 'sealed-store';
  kid: string;
  publicKeyPem: string;
  encrypted: string;
  iv: string;
}

function sealedStoreDir(packageRoot: string): string {
  return join(packageRoot, 'audit');
}

/**
 * Seal an Ed25519 private key PEM under ENTERPRISE_MASTER_KEY and persist it.
 * The on-disk artifact carries ONLY ciphertext (`encrypted`/`iv`) plus the
 * public key and kid — never the private-key PEM. Returns the artifact path.
 * Used by the rotation flow (keyRotation.ts), `chariot audit custody
 * import-key`, and directly by operators provisioning a fresh sealed-store
 * key. The caller retains the plaintext PEM only in local scope — this
 * function does not return it and does not touch any source file it may
 * have been read from (an operator importing an existing PEM is told to
 * delete the plaintext source themselves; this code never deletes files a
 * human didn't ask it to).
 */
export function sealSigningKey(packageRoot: string, privateKeyPem: string): { path: string; kid: string } {
  const key = resolvePrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('sealSigningKey: key must be Ed25519 (CHARIOT §9.8.1).');
  }
  const publicKeyPem = createPublicKey(key).export({ type: 'spki', format: 'pem' }) as string;
  const kid = computeKid(publicKeyPem);
  const { encrypted, iv } = encryptFields({ privateKeyPem }, SEALED_TENANT_ID, SEALED_RECORD_ID);
  const artifact: SealedKeyArtifact = { schemaVersion: 1, backend: 'sealed-store', kid, publicKeyPem, encrypted, iv };
  const dir = sealedStoreDir(packageRoot);
  const filename = `signing-key.${kid}.sealed.json`;
  const path = atomicWriteNew(dir, filename, JSON.stringify(artifact, null, 2) + '\n');
  // Small, non-sensitive pointer file — overwritten on each rotation so a
  // caller without an explicit kid picks up the latest key. Contains only a
  // kid, never key material, so a plain (non-atomic-append) write is fine.
  mkdirSync(dir, { recursive: true, mode: 0o755 });
  writeFileSync(join(dir, 'signing-key.current.json'), JSON.stringify({ kid }) + '\n', { mode: 0o644 });
  return { path, kid };
}

/**
 * True if a sealed-store key has ever been provisioned under `packageRoot`
 * (the `signing-key.current.json` pointer file exists). Cheap, synchronous
 * filesystem check — used by auditCadence.ts to decide whether attestation
 * is "configured" for the default backend without needing an async
 * ENTERPRISE_MASTER_KEY decrypt (that happens only when a signer actually
 * constructs, on the first attest tick).
 */
export function isSealedStoreProvisioned(packageRoot: string): boolean {
  return existsSync(join(sealedStoreDir(packageRoot), 'signing-key.current.json'));
}

function loadSealedArtifact(packageRoot: string, kid?: string): SealedKeyArtifact {
  const dir = sealedStoreDir(packageRoot);
  let resolvedKid = kid;
  if (!resolvedKid) {
    const pointerPath = join(dir, 'signing-key.current.json');
    if (!existsSync(pointerPath)) {
      throw new Error(
        `CHARIOT_AUDIT_SIGNER_BACKEND=sealed-store: no sealed audit signing key found under ${dir}. ` +
          "Provision one with 'chariot audit custody import-key' (import an existing PEM) or the rotation flow " +
          '(mint a fresh key) first.',
      );
    }
    resolvedKid = (JSON.parse(readFileSync(pointerPath, 'utf-8')) as { kid: string }).kid;
  }
  const file = join(dir, `signing-key.${resolvedKid}.sealed.json`);
  if (!existsSync(file)) {
    throw new Error(`CHARIOT_AUDIT_SIGNER_BACKEND=sealed-store: sealed key artifact not found: ${file}`);
  }
  return JSON.parse(readFileSync(file, 'utf-8')) as SealedKeyArtifact;
}

/**
 * CH-10 migration walker (CHARIOT-SPEC.md:1237-1250, §12.2, rulings item
 * 59: "walks every stored ciphertext ... reports counts {legacy, upgraded,
 * failed, alreadyV2}"). The sealed-store artifact is a single JSON file,
 * not a database row, and every kid a rotation has ever minted persists on
 * disk (`signing-key.<kid>.sealed.json`) — this walks ALL of them, not
 * just the current one, so a rotated-away key is not silently left legacy
 * forever. `SEALED_TENANT_ID`/`SEALED_RECORD_ID` are the SAME pseudo-
 * tenant identity `createSealedStoreSigner`'s upgrade-on-decrypt already
 * uses; `chariot vault migrate` treats `SEALED_TENANT_ID` as one of the
 * ids it walks (see that command's tenant-discovery), so this artifact is
 * proven-by-walk rather than assumed-clean, closing gate finding F1.
 */
export async function walkSealedStoreLegacyArtifacts(
  packageRoot: string,
  dryRun: boolean,
): Promise<VaultMigrateCounts> {
  const counts = emptyVaultMigrateCounts();
  const dir = sealedStoreDir(packageRoot);
  if (!existsSync(dir)) return counts;

  const files = readdirSync(dir).filter((f) => /^signing-key\..+\.sealed\.json$/.test(f));
  for (const filename of files) {
    let raw: string;
    let artifact: SealedKeyArtifact;
    try {
      raw = readFileSync(join(dir, filename), 'utf-8');
      artifact = JSON.parse(raw) as SealedKeyArtifact;
    } catch {
      // Not a readable/parseable sealed artifact — out of this walker's
      // scope (corruption unrelated to the AAD format), skip silently.
      continue;
    }
    if (!isLegacyCiphertext(artifact.encrypted)) {
      counts.alreadyV2++;
      continue;
    }
    counts.legacy++;
    try {
      const { fields } = await decryptFieldsForVaultMigration(
        artifact.encrypted,
        artifact.iv,
        SEALED_TENANT_ID,
        SEALED_RECORD_ID,
      );
      const { encrypted, iv } = encryptFields(fields, SEALED_TENANT_ID, SEALED_RECORD_ID);
      if (!dryRun) {
        const updated: SealedKeyArtifact = { ...artifact, encrypted, iv };
        // CAS: only replace if the file still holds exactly what we read.
        atomicOverwriteIfUnchanged(dir, filename, raw, JSON.stringify(updated, null, 2) + '\n');
      }
      counts.upgraded++;
    } catch {
      counts.failed++;
    }
  }
  return counts;
}

async function createSealedStoreSigner(packageRoot: string, kid?: string): Promise<ChainSigner> {
  // CHARIOT::§9.8.1::2 (review gate F4) — the custody check runs BEFORE the
  // private key is ever decrypted into process memory, and only in
  // enterprise mode (single-user has no MFA/RBAC control to gate).
  if (isEnterpriseModeRequested()) {
    const custody = checkSealedStoreCustody();
    if (!custody.passed) {
      throw new Error(`CHARIOT::§9.8.1::2 — sealed-store custody check failed: ${custody.reason}`);
    }
    logKeyAccess('sealed-store', '(pre-decrypt)', 'access', custody.reason);
  }
  const artifact = loadSealedArtifact(packageRoot, kid);
  logKeyAccess('sealed-store', artifact.kid, 'decrypt');
  const result = await decryptFields(artifact.encrypted, artifact.iv, SEALED_TENANT_ID, SEALED_RECORD_ID);
  const decrypted = result.fields;
  // CH-10 upgrade-on-decrypt (§12.2, rulings item 59, "the caller MUST
  // persist {encrypted, iv} back to the SAME record, in the SAME
  // operation"). CAS via atomicOverwriteIfUnchanged: `expectedCurrentBytes`
  // is the exact serialization `loadSealedArtifact` read `artifact` from
  // (the same `JSON.stringify(x, null, 2) + '\n'` shape `sealSigningKey`
  // writes) — a concurrent writer (rotation, import, another upgrade)
  // changes those bytes, making this a no-op, never a clobber. A genuine
  // write error is NOT swallowed; it fails signing for this call.
  if (result.upgraded) {
    try {
      const updatedArtifact: SealedKeyArtifact = {
        ...artifact,
        encrypted: result.upgraded.encrypted,
        iv: result.upgraded.iv,
      };
      const { written } = atomicOverwriteIfUnchanged(
        sealedStoreDir(packageRoot),
        `signing-key.${artifact.kid}.sealed.json`,
        JSON.stringify(artifact, null, 2) + '\n',
        JSON.stringify(updatedArtifact, null, 2) + '\n',
      );
      if (!written) {
        logKeyAccess('sealed-store', artifact.kid, 'access', 'CH-10 upgrade-on-decrypt CAS no-op — concurrent writer');
      }
    } catch (writeBackErr) {
      logKeyAccess(
        'sealed-store',
        artifact.kid,
        'access',
        `CH-10 upgrade-on-decrypt write-back failed: ${writeBackErr instanceof Error ? writeBackErr.message : String(writeBackErr)}`,
      );
      throw new VaultUpgradePersistFailedError('chainSigner', artifact.kid, writeBackErr);
    }
  }
  const key = resolvePrivateKey(decrypted.privateKeyPem);
  return {
    backend: 'sealed-store',
    async sign(payload: Buffer): Promise<Buffer> {
      logKeyAccess('sealed-store', artifact.kid, 'sign');
      return edSign(null, payload, key);
    },
    async getKeyInfo(): Promise<ChainSignerKeyInfo> {
      return { kid: artifact.kid, publicKeyPem: artifact.publicKeyPem };
    },
  };
}

// ── kms backend (true remote signing — the private key never leaves KMS) ────

// `@aws-sdk/client-kms` is NOT a package.json dependency (public-package
// hygiene per the brief). The specifier is typed `string` — same pattern as
// `SDK_MODULE_ID` in src/license/license-manager.ts — so tsc never
// statically resolves it and the offline build requires no such package.
const KMS_SDK_MODULE_ID: string = '@aws-sdk/client-kms';

// CHARIOT::§9.8.1::1 — the ONLY KMS asymmetric key spec that signs/verifies
// Ed25519 (docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html:
// "ECC_NIST_EDWARDS25519 ... Signing and verification ... The private key
// that generates signatures never leaves AWS KMS unencrypted."). Any other
// KeySpec on the configured key is refused.
export const KMS_KEY_SPEC = 'ECC_NIST_EDWARDS25519';
// `ED25519_SHA_512` signs the RAW message directly (MessageType: 'RAW') —
// what our canonical-payload bytes need. `ED25519_PH_SHA_512` requires
// MessageType 'DIGEST' and pre-hashes AGAIN inside KMS; using it on an
// already-raw payload would double-hash and produce a signature no
// standard Ed25519 verifier (including our own edVerify) would accept, so
// it is deliberately never used here.
const KMS_SIGNING_ALGORITHM = 'ED25519_SHA_512';

interface AwsKmsSdk {
  KMSClient: new (cfg: { region?: string }) => { send(command: unknown): Promise<unknown> };
  GetPublicKeyCommand: new (input: { KeyId: string }) => unknown;
  SignCommand: new (input: {
    KeyId: string;
    Message: Uint8Array;
    MessageType: string;
    SigningAlgorithm: string;
  }) => unknown;
}

/**
 * Fetch and validate a KMS asymmetric signing key's public half. Shared by
 * `createKmsSigner` (construction, current key) and `rotateSigningKey`
 * (rotation, the NEW key id an operator provisioned out-of-band — KMS has
 * no in-place "rotate" for asymmetric keys, so rotation for this backend
 * means pointing at a fresh key, not mutating the old one). Builds its own
 * short-lived client — cheap (no network call to construct); the returned
 * `send` closure is NOT reused elsewhere, callers needing to Sign build
 * their own via the same pattern (see `createKmsSigner`).
 */
export async function fetchKmsPublicKey(
  keyId: string,
  region: string | undefined,
  deps: ChainSignerDeps = {},
): Promise<{ publicKeyPem: string; kid: string }> {
  let send: (cmd: unknown) => Promise<unknown>;
  let GetPublicKeyCommandCtor: new (input: { KeyId: string }) => unknown;
  if (deps.kmsClientFactory && deps.kmsGetPublicKeyCommandCtor) {
    send = deps.kmsClientFactory(region).send;
    GetPublicKeyCommandCtor = deps.kmsGetPublicKeyCommandCtor;
  } else {
    let mod: AwsKmsSdk;
    try {
      mod = (await import(KMS_SDK_MODULE_ID)) as unknown as AwsKmsSdk;
    } catch {
      throw new Error(
        "CHARIOT_AUDIT_SIGNER_BACKEND=kms requires the optional '@aws-sdk/client-kms' package. " +
          'Install it with: npm install @aws-sdk/client-kms',
      );
    }
    const client = new mod.KMSClient(region ? { region } : {});
    send = (cmd: unknown) => client.send(cmd);
    GetPublicKeyCommandCtor = mod.GetPublicKeyCommand;
  }

  const pubOut = (await send(new GetPublicKeyCommandCtor({ KeyId: keyId }))) as {
    PublicKey?: Uint8Array;
    KeySpec?: string;
  };
  if (pubOut.KeySpec !== KMS_KEY_SPEC) {
    throw new Error(
      `CHARIOT_AUDIT_KMS_KEY_ID (${keyId}) has KeySpec '${String(pubOut.KeySpec)}' — CHARIOT::§9.8.1::1 ` +
        `requires an Ed25519 KMS key (KeySpec=${KMS_KEY_SPEC}).`,
    );
  }
  if (!pubOut.PublicKey) {
    throw new Error('KMS GetPublicKey returned no PublicKey for the audit signing key.');
  }
  const publicKeyPem = createPublicKey({ key: Buffer.from(pubOut.PublicKey), format: 'der', type: 'spki' }).export({
    type: 'spki',
    format: 'pem',
  }) as string;
  return { publicKeyPem, kid: computeKid(publicKeyPem) };
}

async function createKmsSigner(deps: ChainSignerDeps = {}): Promise<ChainSigner> {
  const keyId = process.env.CHARIOT_AUDIT_KMS_KEY_ID;
  const region = process.env.CHARIOT_AUDIT_KMS_REGION;
  if (!keyId) {
    throw new Error(
      'CHARIOT_AUDIT_SIGNER_BACKEND=kms requires CHARIOT_AUDIT_KMS_KEY_ID (the KMS key id or ARN of an ' +
        `${KMS_KEY_SPEC} asymmetric signing key). See docs/product/AUDIT-SIGNING-KEY-RUNBOOK.md.`,
    );
  }

  // CHARIOT::§9.8.1::2 (review gate F4) — MFA-gating check BEFORE any Sign
  // call, enterprise mode only.
  if (isEnterpriseModeRequested()) {
    const custody = await checkKmsCustody(keyId, region, deps);
    if (!custody.passed) {
      throw new Error(`CHARIOT::§9.8.1::2 — kms custody check failed: ${custody.reason}`);
    }
    logKeyAccess('kms', keyId, 'access', custody.reason);
  }

  const { publicKeyPem, kid } = await fetchKmsPublicKey(keyId, region, deps);

  let send: (cmd: unknown) => Promise<unknown>;
  let SignCommandCtor: new (input: {
    KeyId: string;
    Message: Uint8Array;
    MessageType: string;
    SigningAlgorithm: string;
  }) => unknown;
  if (deps.kmsClientFactory && deps.kmsSignCommandCtor) {
    send = deps.kmsClientFactory(region).send;
    SignCommandCtor = deps.kmsSignCommandCtor;
  } else {
    const mod = (await import(KMS_SDK_MODULE_ID)) as unknown as AwsKmsSdk;
    const client = new mod.KMSClient(region ? { region } : {});
    send = (cmd: unknown) => client.send(cmd);
    SignCommandCtor = mod.SignCommand;
  }

  logKeyAccess('kms', kid, 'access', keyId);

  return {
    backend: 'kms',
    async sign(payload: Buffer): Promise<Buffer> {
      logKeyAccess('kms', kid, 'sign', keyId);
      const signOut = (await send(
        new SignCommandCtor({
          KeyId: keyId,
          Message: payload,
          MessageType: 'RAW',
          SigningAlgorithm: KMS_SIGNING_ALGORITHM,
        }),
      )) as { Signature?: Uint8Array };
      if (!signOut.Signature) {
        throw new Error('KMS Sign returned no Signature.');
      }
      return Buffer.from(signOut.Signature);
    },
    async getKeyInfo(): Promise<ChainSignerKeyInfo> {
      return { kid, publicKeyPem };
    },
  };
}

// ── vault-transit backend (true remote signing — key never leaves Vault) ────

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Wrap a raw 32-byte Ed25519 public key (Vault's `public_key` field) in an
 * SPKI DER envelope so node:crypto can consume it. The prefix is the fixed,
 * well-known SPKI-wrapper constant for Ed25519 (RFC 8410). */
function rawEd25519PublicKeyToSpkiPem(raw: Buffer): string {
  if (raw.length !== 32) {
    throw new Error(`Vault transit public_key must decode to 32 bytes (got ${raw.length}).`);
  }
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }) as string;
}

interface VaultTransitKeyInfo {
  publicKeyPem: string;
  kid: string;
  version: number;
}

/**
 * Fetch a Vault transit key's current (latest_version) public key. Shared
 * by `createVaultSigner` (construction) and `rotateSigningKey`/
 * `rotateVaultTransitKey` (rotation, after bumping the version).
 */
export async function fetchVaultPublicKey(
  addr: string,
  token: string,
  keyName: string,
  deps: ChainSignerDeps = {},
): Promise<VaultTransitKeyInfo> {
  const doFetch = deps.fetchImpl ?? fetch;
  const base = addr.replace(/\/+$/, '');
  const keyResp = await doFetch(`${base}/v1/transit/keys/${encodeURIComponent(keyName)}`, {
    headers: { 'X-Vault-Token': token },
  });
  if (!keyResp.ok) {
    throw new Error(`Vault transit key lookup failed: HTTP ${keyResp.status}`);
  }
  const keyJson = (await keyResp.json()) as {
    data?: { type?: string; latest_version?: number; keys?: Record<string, { public_key?: string }> };
  };
  if (keyJson.data?.type !== 'ed25519') {
    throw new Error(
      `Vault transit key '${keyName}' must be type ed25519 (got '${keyJson.data?.type}') — CHARIOT §9.8.1.`,
    );
  }
  const version = keyJson.data.latest_version;
  const rawPublicKeyB64 = version != null ? keyJson.data.keys?.[String(version)]?.public_key : undefined;
  if (!rawPublicKeyB64 || version == null) {
    throw new Error(`Vault transit key '${keyName}' has no public key for version ${String(version)}.`);
  }
  const publicKeyPem = rawEd25519PublicKeyToSpkiPem(Buffer.from(rawPublicKeyB64, 'base64'));
  return { publicKeyPem, kid: computeKid(publicKeyPem), version };
}

/**
 * CHARIOT::§9.8.1::3 rotation for vault-transit: `POST
 * /v1/transit/keys/<name>/rotate` bumps the key's `latest_version` in
 * place (Vault's native rotation primitive for transit keys — the OLD
 * version remains usable for verification, matching the CH-03 multi-key
 * pattern natively), then re-fetch the public key at the new version.
 */
export async function rotateVaultTransitKey(
  addr: string,
  token: string,
  keyName: string,
  deps: ChainSignerDeps = {},
): Promise<VaultTransitKeyInfo> {
  const doFetch = deps.fetchImpl ?? fetch;
  const base = addr.replace(/\/+$/, '');
  const rotateResp = await doFetch(`${base}/v1/transit/keys/${encodeURIComponent(keyName)}/rotate`, {
    method: 'POST',
    headers: { 'X-Vault-Token': token },
  });
  if (!rotateResp.ok) {
    throw new Error(`Vault transit key rotate failed: HTTP ${rotateResp.status}`);
  }
  return fetchVaultPublicKey(addr, token, keyName, deps);
}

async function createVaultSigner(deps: ChainSignerDeps = {}): Promise<ChainSigner> {
  const addr = process.env.CHARIOT_AUDIT_VAULT_ADDR;
  const token = process.env.CHARIOT_AUDIT_VAULT_TOKEN;
  const keyName = process.env.CHARIOT_AUDIT_VAULT_KEY_NAME;
  if (!addr || !token || !keyName) {
    throw new Error(
      'CHARIOT_AUDIT_SIGNER_BACKEND=vault-transit requires CHARIOT_AUDIT_VAULT_ADDR, ' +
        'CHARIOT_AUDIT_VAULT_TOKEN, and CHARIOT_AUDIT_VAULT_KEY_NAME (a Vault transit key of type ed25519).',
    );
  }

  // CHARIOT::§9.8.1::2 (review gate F4) — MFA-enforcement + RBAC-scope check
  // BEFORE any sign call, enterprise mode only.
  if (isEnterpriseModeRequested()) {
    const custody = await checkVaultCustody(addr, token, keyName, deps);
    if (!custody.passed) {
      throw new Error(`CHARIOT::§9.8.1::2 — vault-transit custody check failed: ${custody.reason}`);
    }
    logKeyAccess('vault-transit', keyName, 'access', custody.reason);
  }

  const { publicKeyPem, kid, version } = await fetchVaultPublicKey(addr, token, keyName, deps);
  const doFetch = deps.fetchImpl ?? fetch;
  const base = addr.replace(/\/+$/, '');

  // Best-effort caller-identity surface for the audited-access log — never
  // fatal if the lookup fails (e.g. a token without lookup-self grants).
  let principal: string | undefined;
  try {
    const selfResp = await doFetch(`${base}/v1/auth/token/lookup-self`, { headers: { 'X-Vault-Token': token } });
    if (selfResp.ok) {
      const selfJson = (await selfResp.json()) as { data?: { display_name?: string; entity_id?: string } };
      principal = selfJson.data?.display_name ?? selfJson.data?.entity_id;
    }
  } catch {
    // best-effort only
  }
  logKeyAccess('vault-transit', kid, 'access', principal);

  return {
    backend: 'vault-transit',
    async sign(payload: Buffer): Promise<Buffer> {
      logKeyAccess('vault-transit', kid, 'sign', principal);
      const signResp = await doFetch(`${base}/v1/transit/sign/${encodeURIComponent(keyName)}`, {
        method: 'POST',
        headers: { 'X-Vault-Token': token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: payload.toString('base64'), key_version: version }),
      });
      if (!signResp.ok) {
        throw new Error(`Vault transit sign failed: HTTP ${signResp.status}`);
      }
      const signJson = (await signResp.json()) as { data?: { signature?: string } };
      const sigField = signJson.data?.signature ?? '';
      const m = /^vault:v\d+:(.+)$/.exec(sigField);
      if (!m) {
        throw new Error(`Unrecognized Vault transit signature format: ${sigField}`);
      }
      return Buffer.from(m[1], 'base64');
    },
    async getKeyInfo(): Promise<ChainSignerKeyInfo> {
      return { kid, publicKeyPem };
    },
  };
}

// ── factory ──────────────────────────────────────────────────────────────────

export interface CreateChainSignerOpts {
  backend?: ChainSignerBackend;
  packageRoot?: string;
  sealedStoreKid?: string;
  deps?: ChainSignerDeps;
}

/**
 * Construct a ChainSigner for the configured backend
 * (`CHARIOT_AUDIT_SIGNER_BACKEND`; default `sealed-store` — CHARIOT
 * §9.8.1::1's plaintext-on-host MUST NOT is unconditional, so there is no
 * plaintext-env fallback here at all, single-user or enterprise).
 */
export async function createChainSigner(opts: CreateChainSignerOpts = {}): Promise<ChainSigner> {
  const backend =
    opts.backend ?? (process.env.CHARIOT_AUDIT_SIGNER_BACKEND as ChainSignerBackend | undefined) ?? 'sealed-store';
  switch (backend) {
    case 'sealed-store':
      if (!opts.packageRoot) {
        throw new Error('createChainSigner: packageRoot is required for backend=sealed-store.');
      }
      return createSealedStoreSigner(opts.packageRoot, opts.sealedStoreKid);
    case 'kms':
      return createKmsSigner(opts.deps);
    case 'vault-transit':
      return createVaultSigner(opts.deps);
    default:
      throw new Error(
        `Unknown CHARIOT_AUDIT_SIGNER_BACKEND '${String(backend)}'. Must be one of: kms, vault-transit, sealed-store.`,
      );
  }
}

// ── multi-key verification (CHARIOT::§9.8.1::3, "CH-03 pattern") ────────────

/**
 * Build the multi-key verification set. Sources, all MERGED (never
 * pruning) — CHARIOT-SPEC.md §9.8.1: "Historical records remain verifiable
 * only if the old public key is retained in a multi-key verification set":
 *   1. The persistent, rotation-maintained store at
 *      `<epicAiDir>/audit/verify-keys.json` (verifyKeyStore.ts) — the
 *      actual "same distribution path" `rotateSigningKey()` publishes to
 *      (gate finding F2).
 *   2. `CHARIOT_AUDIT_VERIFY_KEYS` (JSON `{kid: pem}`) — an env-level
 *      overlay for keys not yet persisted.
 *   3. The legacy single `CHARIOT_AUDIT_VERIFY_KEY`/`CHARIOT_AUDIT_SIGNING_KEY`
 *      fallback, preserved for backward compatibility — including the
 *      file-path-or-inline-PEM convenience the CLI's `verify-length`
 *      command used to hand-roll itself (a value not starting with
 *      `-----BEGIN` is read as a file path). Gate round-3 finding: callers
 *      (chariot.ts `verify-length`, admin.ts's export route) MUST source
 *      the legacy-var handling from HERE, not reimplement it locally, so
 *      there is exactly one place this convenience can drift.
 */
export function resolveVerifyKeys(epicAiDir: string): Map<string, KeyObject> {
  const map = new Map<string, KeyObject>();

  const store = loadVerifyKeyStore(epicAiDir);
  for (const [kid, entry] of Object.entries(store)) {
    try {
      map.set(kid, resolvePublicKey(entry.publicKeyPem));
    } catch {
      // A corrupt/unparseable stored entry does not take down the whole
      // resolution — it simply cannot vouch for anything, same as if it
      // were absent.
    }
  }

  const multiRaw = process.env.CHARIOT_AUDIT_VERIFY_KEYS;
  if (multiRaw) {
    let parsed: Record<string, string>;
    try {
      parsed = JSON.parse(multiRaw) as Record<string, string>;
    } catch (e) {
      throw new Error(`CHARIOT_AUDIT_VERIFY_KEYS must be JSON mapping kid -> PEM: ${(e as Error).message}`);
    }
    for (const [kid, pem] of Object.entries(parsed)) {
      map.set(kid, resolvePublicKey(pem));
    }
  }
  const singleRaw = process.env.CHARIOT_AUDIT_VERIFY_KEY ?? process.env.CHARIOT_AUDIT_SIGNING_KEY;
  if (singleRaw) {
    // File-path-or-inline-PEM convenience, preserved from the CLI's prior
    // hand-rolled implementation: a value that isn't PEM-shaped is read as
    // a file path. A misconfigured path/PEM throws here (same as it did
    // when the CLI parsed it inline) rather than silently vanishing.
    const pemSource = singleRaw.includes('-----BEGIN')
      ? singleRaw
      : (() => {
          try {
            return readFileSync(singleRaw, 'utf-8');
          } catch (e) {
            throw new Error(`could not read the verify key from '${singleRaw}': ${(e as Error).message}`);
          }
        })();
    const key = resolvePublicKey(pemSource);
    const kid = computeKid(key);
    if (!map.has(kid)) map.set(kid, key);
  }
  return map;
}

/**
 * Verify `signature` over `payload` against the `kid`-selected key in
 * `verifyKeys`. An unknown kid returns `false` (never throws) — CHARIOT §9.8.1
 * node 3 acceptance: "a record whose kid is unknown must fail."
 */
export function verifyWithKeySet(
  payload: Buffer,
  signature: Buffer,
  kid: string,
  verifyKeys: ReadonlyMap<string, KeyObject>,
): boolean {
  const key = verifyKeys.get(kid);
  if (!key) return false;
  return edVerify(null, payload, key, signature);
}
