/**
 * @epicai/chariot — §5.7 sealed EdgeShard snapshot: operator configuration
 *
 * CHARIOT-SPEC §5.7 pins the `sealedShard` envelope (ciphertext/iv/signature/
 * salt/aad) and the anti-rollback + context-binding + persisted-watermark
 * consumer contract enforced natively in `native/src/edge_snapshot.rs`. This
 * module is the TypeScript-side config seam: it resolves the operator-
 * supplied sealed-descriptor from disk/env, plus the REAL customer license
 * artifact, and returns `null` when the sealed path is not configured at
 * all, so `ChariotState.makeDiskArtifactSource.loadShard` can fall back to
 * the plaintext dev directory ONLY when the sealed path was never
 * configured — never as a fallback from a configured-but-failing sealed
 * load, which would silently defeat the seal.
 *
 * LICENSE ARTIFACT (R2 ruling, 2026-09-04, MASTER-accepted): the native §5.7
 * unseal entry point verifies the SAME signed license artifact
 * `src/license/loader.ts` already validates — the compact JWT from the
 * envelope at `~/.epic-ai/chariot.license` (`{ "jwt": "<compact JWT>",
 * "renewal_secret": … }`) — NOT a separate canonical-JSON + detached-
 * signature format. This module therefore reuses the loader's OWN envelope
 * reader (`readLicenseEnvelope()`) rather than a bespoke path/format, so the
 * two verifiers (loader.ts for licensing/entitlement, this path for §5.7
 * unseal) are reading literally the same bytes off disk.
 *
 * CONTEXT CLAIM (R1 ruling, 2026-09-04, NEEDS-MASTER-RULING escalated
 * separately): CHARIOT-SPEC §5.7::16 names the aad `<context>` "the catalog
 * version identifier", but §5.7::37/38 requires the consumer's expected
 * context be derived from the verified license, and the license carries no
 * catalog-version claim — the native side (`edge_snapshot.rs::
 * license_derived_floor_and_context`) resolves this INTERIM as `tenant_id`
 * when present, else `sub`/company id. This module does not itself compute
 * or duplicate that value — it only supplies the license artifact the
 * native code derives it from — but the `sealedShard` descriptor's `salt`/
 * `aad` MUST have been produced by a producer (`seal-edge-snapshot.ts`)
 * using that SAME value, or the native consumer will reject it.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createLogger } from '../logger.js';
import { sha256FileHex } from './fileDigest.js';
import { readLicenseEnvelope, licenseFilePath } from '../../license/loader.js';
import { EPIC_AI_DIR } from '../../cli/paths.js';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

const log = createLogger('epicai.retrieval.sealed_shard');

/** Path to the `sealedShard` descriptor JSON (CHARIOT::§5.7::1-7):
 * `{ ivB64, signatureB64, salt, aad }` plus the ciphertext in exactly ONE of
 * two forms (CHARIOT §5.7 envelope fields, AMENDED 2026-10-14): the
 * file-reference form `"ciphertext": { "file": "<basename>", "sha256":
 * "<hex>" }` or the legacy inline `ciphertextB64`. */
export const SEALED_SHARD_DESCRIPTOR_ENV = 'CHARIOT_EDGE_SEALED_SHARD_DESCRIPTOR_PATH';

/**
 * Default sealed-descriptor location under the Epic AI dir (dogfood-ready
 * 4.0 contract: `<dir>/edgeshard/catalog.edgeshard.sealed`), where the
 * offline kit installs it. `baseDir` defaults to `src/cli/paths.ts`'s
 * `EPIC_AI_DIR` (honours `EPIC_AI_DIR_OVERRIDE`).
 */
export function defaultSealedShardDescriptorPath(baseDir: string = EPIC_AI_DIR): string {
  return join(baseDir, 'edgeshard', 'catalog.edgeshard.sealed');
}

/** True when ANY directory entry exists at `p` — including a dangling
 * symlink or a directory — so a present-but-broken default declares a
 * sealed deployment and fails closed instead of silently selecting the
 * plaintext path. */
function entryExists(p: string): boolean {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * The single "is a sealed deployment declared?" predicate. Precedence:
 *   1. `CHARIOT_EDGE_SEALED_SHARD_DESCRIPTOR_PATH` when set and non-empty
 *      (env wins, even if the file is missing — that is configured-but-
 *      broken and fails closed downstream);
 *   2. else the default `<EPIC_AI_DIR>/edgeshard/catalog.edgeshard.sealed`
 *      when any entry exists there;
 *   3. else null — sealed path not configured (today's behaviour: the
 *      plaintext dev directory may be used).
 */
export function resolveSealedShardDescriptorPath(baseDir: string = EPIC_AI_DIR): string | null {
  const fromEnv = process.env[SEALED_SHARD_DESCRIPTOR_ENV];
  if (fromEnv) return fromEnv;
  const fallback = defaultSealedShardDescriptorPath(baseDir);
  return entryExists(fallback) ? fallback : null;
}

/**
 * Ed25519 SPKI PEM this installation offers as the SNAPSHOT signature's
 * candidate verifying key. `native/src/edge_snapshot.rs::pinned_verifying_key`
 * pins it to the compiled-in accepted set regardless — an operator cannot
 * substitute a different key by editing this constant — but the native call
 * still requires a candidate PEM, so it is duplicated here from
 * `native/src/license.rs::ACCEPTED_PUBLIC_KEYS_PEM` / `src/license/loader.ts
 * ACCEPTED_KEYS_PEM` (all three MUST rotate together; see either file's
 * rotation-model doc comment).
 */
export const SNAPSHOT_VERIFYING_KEY_PEM =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MCowBQYDK2VwAyEACBR74DxcFEvMcBO0YOxA9q5X/75uLAh3Z1CHOg2dHEc=\n' +
  '-----END PUBLIC KEY-----';

/**
 * Resolved descriptor. EXACTLY ONE ciphertext form is set:
 *   - `ciphertextB64` — the legacy inline base64 form (small/legacy shards);
 *   - `ciphertextPath` (+ `ciphertextSha256`) — the file-reference form:
 *     `ciphertext.file` resolved in the descriptor's own directory, verified
 *     at load to be a regular file (not a symlink) whose SHA-256 equals
 *     `ciphertext.sha256`.
 */
export interface SealedShardDescriptor {
  ciphertextB64?: string;
  /** Absolute path of the ciphertext file (file-reference form only). */
  ciphertextPath?: string;
  /** Lowercase hex SHA-256 the ciphertext file was verified against at load (file-reference form only). */
  ciphertextSha256?: string;
  ivB64: string;
  signatureB64: string;
  salt: string;
  aad: string;
}

export interface SealedShardConfig {
  descriptor: SealedShardDescriptor;
  publicKeyPem: string;
  secretRootB64: string;
  /** The compact license JWT (`src/license/loader.ts::readLicenseEnvelope().jwt`),
   * NOT the whole envelope object — the native unseal entry point verifies
   * this string's signature itself. */
  licenseJwt: string;
}

/** Default name of the file-form ciphertext beside the default descriptor
 * (`<descriptor basename>.ciphertext`, CHARIOT §5.7 / §17.2a). */
export const SEALED_SHARD_CIPHERTEXT_SUFFIX = '.ciphertext';

/**
 * CHARIOT §5.7 file-reference form: `file` is "a bare basename resolved in
 * the descriptor's own directory". Refused: non-string, empty, `.`, `..`,
 * any `/` or `\`, and NUL — so the reference can never leave the
 * descriptor's directory. A name merely containing `..` (e.g. `x..y`) is
 * a bare basename and is accepted.
 */
export function isBareCiphertextBasename(file: unknown): file is string {
  return (
    typeof file === 'string' &&
    file.length > 0 &&
    file !== '.' &&
    file !== '..' &&
    !file.includes('/') &&
    !file.includes('\\') &&
    !file.includes('\0')
  );
}

/** Lowercase hex SHA-256, exactly as the producer
 * (`seal_edge_snapshot_file` → `ciphertext_sha256_hex`) writes it. */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

type CiphertextForm = Pick<SealedShardDescriptor, 'ciphertextB64' | 'ciphertextPath' | 'ciphertextSha256'>;

/**
 * Resolve EXACTLY ONE ciphertext form (CHARIOT §5.7 envelope fields, AMENDED
 * 2026-10-14), fail-closed (`null` + ERROR log) on anything else:
 *   - file-reference form — `ciphertext` is an object `{ file, sha256 }`:
 *     `file` a bare basename, `sha256` 64 lowercase hex (the spec's form
 *     carries it, so its absence is refused); `<descriptor dir>/<file>` must
 *     `lstat` as a regular file (a symlink is refused) and its streamed
 *     SHA-256 must equal `sha256`;
 *   - inline form — `ciphertextB64` is a string; a legacy `ciphertext`
 *     alias, when present, must be the identical string;
 *   - BOTH forms (an object `ciphertext` together with `ciphertextB64`, or
 *     an inline alias that differs from `ciphertextB64`) — refused as
 *     ambiguous, never resolved by preference.
 */
function resolveCiphertextForm(descriptorPath: string, ciphertext: unknown, ciphertextB64: unknown): CiphertextForm | null {
  const isFileRef = ciphertext !== null && typeof ciphertext === 'object' && !Array.isArray(ciphertext);
  if (isFileRef) {
    if (ciphertextB64 !== undefined) {
      log.error('sealed_shard.descriptor_ambiguous_ciphertext', {
        path: descriptorPath,
        reason: 'the descriptor carries both the file-reference `ciphertext` and the inline `ciphertextB64`; ' +
          'CHARIOT §5.7 refuses a descriptor carrying both forms',
      });
      return null;
    }
    const { file, sha256 } = ciphertext as Record<string, unknown>;
    if (!isBareCiphertextBasename(file)) {
      log.error('sealed_shard.ciphertext_file_invalid', {
        path: descriptorPath,
        reason: '`ciphertext.file` must be a non-empty bare basename (no "/", "\\", "..", or NUL)',
      });
      return null;
    }
    if (typeof sha256 !== 'string' || !SHA256_HEX_RE.test(sha256)) {
      log.error('sealed_shard.ciphertext_sha256_invalid', {
        path: descriptorPath,
        reason: '`ciphertext.sha256` must be the 64-character lowercase hex SHA-256 of the ciphertext file',
      });
      return null;
    }
    const ciphertextPath = join(dirname(descriptorPath), file);
    let isRegularFile: boolean;
    try {
      const st = lstatSync(ciphertextPath);
      isRegularFile = !st.isSymbolicLink() && st.isFile();
    } catch (err) {
      log.error('sealed_shard.ciphertext_file_missing', { path: ciphertextPath, error: String(err) });
      return null;
    }
    if (!isRegularFile) {
      log.error('sealed_shard.ciphertext_file_not_regular', {
        path: ciphertextPath,
        reason: 'the referenced ciphertext must be a regular file, not a symbolic link (CHARIOT §5.7)',
      });
      return null;
    }
    let actual: string;
    try {
      actual = sha256FileHex(ciphertextPath);
    } catch (err) {
      log.error('sealed_shard.ciphertext_file_unreadable', { path: ciphertextPath, error: String(err) });
      return null;
    }
    if (actual !== sha256) {
      log.error('sealed_shard.ciphertext_sha256_mismatch', {
        path: ciphertextPath,
        reason: 'the ciphertext file does not match the descriptor `ciphertext.sha256`',
      });
      return null;
    }
    return { ciphertextPath, ciphertextSha256: sha256 };
  }

  // Inline form: a non-empty, canonical standard base64 string (§5.7::3).
  if (
    typeof ciphertextB64 !== 'string' ||
    ciphertextB64.length === 0 ||
    Buffer.from(ciphertextB64, 'base64').toString('base64') !== ciphertextB64
  ) {
    log.error('sealed_shard.descriptor_malformed', {
      path: descriptorPath,
      reason: 'the inline `ciphertextB64` must be a non-empty standard base64 string',
    });
    return null;
  }
  if (ciphertext !== undefined && ciphertext !== ciphertextB64) {
    log.error('sealed_shard.descriptor_ambiguous_ciphertext', {
      path: descriptorPath,
      reason: 'the inline `ciphertext` alias differs from `ciphertextB64`; refusing an ambiguous descriptor',
    });
    return null;
  }
  return { ciphertextB64 };
}

/**
 * Resolve the §5.7 sealed-shard configuration from disk/env. Returns `null`
 * when the sealed path is NOT configured ({@link resolveSealedShardDescriptorPath}
 * returns null — no env var and no default descriptor on disk — the normal,
 * expected state for a dev install using the plaintext
 * `CHARIOT_EDGE_SHARD_DIR` fallback). Also returns `null` (with an ERROR log)
 * when the descriptor path IS configured but any required companion
 * artifact (the license envelope, a usable secret root) is missing,
 * malformed or unreadable — the caller (`ChariotState.loadShard`) treats a
 * `null` return from THIS function as "not configured" only when
 * `resolveSealedShardDescriptorPath()` itself returned null; a configured-
 * but-broken sealed path must fail closed, never silently fall back to
 * plaintext, so callers evaluate that predicate themselves (and pass its
 * result in as `descriptorPath`, so both decisions use one resolution).
 *
 * Secret root precedence (CHARIOT-SPEC §5.7: "a per-license secret key or
 * ENTERPRISE_MASTER_KEY"): the licence envelope's `seal_secret` when
 * present and valid; else `ENTERPRISE_MASTER_KEY`. A PRESENT but malformed
 * `seal_secret` fails closed — it never falls through to the env key.
 */
export function loadSealedShardDescriptor(
  descriptorPath: string | null = resolveSealedShardDescriptorPath(),
): SealedShardConfig | null {
  if (!descriptorPath) return null;
  if (!existsSync(descriptorPath)) {
    log.error('sealed_shard.descriptor_missing', { path: descriptorPath });
    return null;
  }

  let descriptor: SealedShardDescriptor;
  try {
    const parsed = JSON.parse(readFileSync(descriptorPath, 'utf8')) as unknown;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      log.error('sealed_shard.descriptor_malformed', { path: descriptorPath });
      return null;
    }
    const raw = parsed as Record<string, unknown>;
    const { ciphertextB64, ivB64, signatureB64, salt, aad, ciphertext } = raw;
    if (
      typeof ivB64 !== 'string' ||
      typeof signatureB64 !== 'string' ||
      typeof salt !== 'string' ||
      typeof aad !== 'string'
    ) {
      log.error('sealed_shard.descriptor_malformed', { path: descriptorPath });
      return null;
    }
    const resolved = resolveCiphertextForm(descriptorPath, ciphertext, ciphertextB64);
    if (!resolved) return null;
    descriptor = { ...resolved, ivB64, signatureB64, salt, aad };
  } catch (err) {
    log.error('sealed_shard.descriptor_parse_failed', { path: descriptorPath, error: String(err) });
    return null;
  }

  // R2 — the SAME artifact src/license/loader.ts validates for licensing,
  // read via its own envelope reader (not a bespoke path/parser).
  const envelope = readLicenseEnvelope();
  if (!envelope || typeof envelope.jwt !== 'string' || envelope.jwt.length === 0) {
    log.error('sealed_shard.license_envelope_unavailable', {
      hint: `no readable license envelope at ${licenseFilePath()}; a §5.7 sealed shard cannot be ` +
        'unsealed without a valid chariot.license',
    });
    return null;
  }

  // §5.7::10/11 — the secret root is a per-license secret key OR
  // ENTERPRISE_MASTER_KEY, NEVER the public license blob. Precedence: the
  // envelope's per-licence `seal_secret` (validated by loader.ts as
  // canonical base64 of exactly 32 bytes), else ENTERPRISE_MASTER_KEY
  // (validated elsewhere as 32-byte base64 — src/iam/crypto.ts::
  // getMasterKeyB64 — the native call re-checks the >=32-byte floor
  // independently regardless).
  if (envelope.seal_secret_error) {
    // Present-but-malformed: fail closed. Falling through to
    // ENTERPRISE_MASTER_KEY here would unseal under a root the licence did
    // not name (or fail opaquely in native code) — never silently.
    log.error('sealed_shard.seal_secret_malformed', {
      reason: envelope.seal_secret_error.reason,
      hint: `the licence at ${licenseFilePath()} carries an invalid seal_secret; the sealed ` +
        'catalog shard cannot be unsealed. Activate a corrected licence file from the Epic AI ' +
        'portal (`chariot license activate <path>`).',
    });
    return null;
  }
  let secretRootB64: string | undefined;
  let secretRootSource: 'license_seal_secret' | 'enterprise_master_key';
  if (envelope.seal_secret !== undefined) {
    secretRootB64 = envelope.seal_secret;
    secretRootSource = 'license_seal_secret';
  } else {
    secretRootB64 = process.env.ENTERPRISE_MASTER_KEY;
    secretRootSource = 'enterprise_master_key';
  }
  if (!secretRootB64 || secretRootB64.trim() === '') {
    log.error('sealed_shard.secret_root_unconfigured', {
      hint: 'the licence carries no seal_secret and ENTERPRISE_MASTER_KEY is unset; one of them ' +
        'is required to unseal a §5.7 sealed shard',
    });
    return null;
  }
  log.info('sealed_shard.secret_root_selected', { source: secretRootSource });

  return {
    descriptor,
    publicKeyPem: SNAPSHOT_VERIFYING_KEY_PEM,
    secretRootB64,
    licenseJwt: envelope.jwt,
  };
}
