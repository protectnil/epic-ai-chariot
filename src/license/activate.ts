/**
 * `chariot license activate <path>` per portal spec §10.1.
 *
 * Reads a JSON envelope ({ jwt, renewal_secret }) from <path>, verifies
 * the JWT signature against the embedded ProtectNIL public key (via
 * loader.verifyAndDecode), refuses on bad signature / expired license /
 * missing renewal_secret, and atomically writes the envelope to
 * ~/.epic-ai/chariot.license (tmp + rename, mode 0600). The license
 * file replaces any existing one.
 *
 * The OPTIONAL `seal_secret` field (§5.7 per-licence secret root; see
 * loader.ts `LicenseEnvelope`) is carried into the installed envelope
 * verbatim when present. It never gates activation: a malformed value is
 * still installed as-is (so sealed access fails closed with an actionable
 * message rather than silently falling back to ENTERPRISE_MASTER_KEY) and
 * is surfaced to the caller as `sealSecretWarning`.
 */

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  renameSync,
  existsSync,
} from 'node:fs';
import { dirname } from 'node:path';
import {
  verifyAndDecode,
  licenseFilePath,
  readPersistedLicenseEpoch,
  persistLicenseEpoch,
  validateSealSecret,
  type VerifiedClaims,
} from './loader.js';
import { CLIENT_SECURITY_EPOCH } from './security-epoch.js';

export type ActivateOutcome =
  | {
      ok: true;
      claims: VerifiedClaims;
      writtenPath: string;
      /** Set when the envelope carries a `seal_secret` that fails
       * validation: the licence is installed, but a §5.7 sealed shard
       * cannot be unsealed until a corrected licence file is activated. */
      sealSecretWarning?: string;
    }
  | {
      ok: false;
      reason:
        | 'unreadable'
        | 'invalid_envelope'
        | 'invalid_signature'
        | 'expired'
        | 'missing_renewal_secret'
        | 'epoch_rollback'
        | 'security_epoch_too_low';
      message: string;
    };

export interface RawEnvelope {
  jwt: string;
  renewal_secret: string;
  /** Raw JSON value of the OPTIONAL `seal_secret` field, carried verbatim
   * (validated or not); `undefined` = the field is absent and is not
   * written. */
  seal_secret?: unknown;
}

/**
 * Parse a licence-envelope file's text. Null when the licence half
 * (`jwt`, `renewal_secret`) is missing/empty/non-string; an OPTIONAL
 * `seal_secret` key is carried through verbatim (any JSON value) and is
 * never a reason to reject. Exported for tests.
 */
export function parseEnvelope(content: string): RawEnvelope | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const r = parsed as { jwt?: unknown; renewal_secret?: unknown; seal_secret?: unknown };
  if (typeof r.jwt !== 'string' || r.jwt.length === 0) return null;
  if (typeof r.renewal_secret !== 'string' || r.renewal_secret.length === 0) {
    return null;
  }
  const out: RawEnvelope = { jwt: r.jwt, renewal_secret: r.renewal_secret };
  if (Object.prototype.hasOwnProperty.call(r, 'seal_secret')) {
    out.seal_secret = r.seal_secret;
  }
  return out;
}

/**
 * Atomic write: tmp file in the same directory + rename. Mode 0600 on
 * the tmp file is preserved across rename on POSIX. mkdir -p the parent
 * if missing.
 */
export function writeLicenseEnvelopeAtomic(
  envelope: RawEnvelope,
  destPath: string,
): void {
  const dir = dirname(destPath);
  mkdirSync(dir, { recursive: true });
  // Fixed key set and order; `seal_secret` only when present (never
  // `"seal_secret": undefined`-shaped drift from a spread of extra keys).
  const onDisk: Record<string, unknown> = {
    jwt: envelope.jwt,
    renewal_secret: envelope.renewal_secret,
  };
  if (envelope.seal_secret !== undefined) onDisk.seal_secret = envelope.seal_secret;
  const serialized = JSON.stringify(onDisk, null, 2) + '\n';
  const tmp = `${destPath}.tmp.${process.pid}`;
  writeFileSync(tmp, serialized, { encoding: 'utf-8', mode: 0o600 });
  renameSync(tmp, destPath);
}

/**
 * Activate the license at <sourcePath>. Pure (no console output) so the
 * CLI wrapper can format on outcome. Returns a discriminated result.
 */
export function activateLicenseFromPath(
  sourcePath: string,
  destPath: string = licenseFilePath(),
): ActivateOutcome {
  if (!existsSync(sourcePath)) {
    return {
      ok: false,
      reason: 'unreadable',
      message: `No file at ${sourcePath}`,
    };
  }
  let content: string;
  try {
    content = readFileSync(sourcePath, 'utf-8');
  } catch (err) {
    return {
      ok: false,
      reason: 'unreadable',
      message: err instanceof Error ? err.message : String(err),
    };
  }
  const envelope = parseEnvelope(content);
  if (!envelope) {
    return {
      ok: false,
      reason: 'invalid_envelope',
      message:
        'File is not a valid Chariot license envelope ({ jwt, renewal_secret }).',
    };
  }
  const claims = verifyAndDecode(envelope.jwt);
  if (!claims) {
    return {
      ok: false,
      reason: 'invalid_signature',
      message:
        'JWT signature did not verify against any embedded ProtectNIL key.',
    };
  }
  // refuse to activate a JWT that lacks a jti claim. The renewal
  // path requires jti (renew-client.ts:115-121) and fails permanently with
  // no_local_license when absent. Catching it here keeps the customer from
  // landing in a stuck-on-first-renewal state with a license that otherwise
  // validates today.
  if (typeof (claims as { jti?: unknown }).jti !== 'string' || ((claims as { jti?: string }).jti ?? '').length === 0) {
    return {
      ok: false,
      reason: 'invalid_signature',
      message:
        'License JWT is missing a non-empty `jti` claim. Re-issue the license ' +
        'with a jti so that renewal and revocation operate correctly.',
    };
  }
  const nowUnix = Math.floor(Date.now() / 1000);
  if (claims.expUnix < nowUnix) {
    return {
      ok: false,
      reason: 'expired',
      message: `License expired at ${claims.expiresAtIso}.`,
    };
  }
  // Mandated-patch-level floor (mirrors validateLicense). Reject eagerly at
  // activation so an operator gets an actionable "update Chariot" error instead
  // of a license that writes to disk yet validates as unlicensed on every load.
  if (claims.minSecurityEpoch > CLIENT_SECURITY_EPOCH) {
    return {
      ok: false,
      reason: 'security_epoch_too_low',
      message:
        `License requires security epoch ${claims.minSecurityEpoch}; this client ` +
        `is at ${CLIENT_SECURITY_EPOCH}. Update Chariot to a build that satisfies ` +
        'the mandated security patch level before activating.',
    };
  }
  // anti-rollback floor must be enforced BEFORE the envelope is
  // written to disk. The validateLicense path enforces this on every
  // load but a stale-but-signed file written here would force the next
  // validateLicense to reject every subsequent call until the floor is
  // hand-bumped. Reject up-front instead.
  const persistedEpoch = readPersistedLicenseEpoch(claims.companyId);
  if (claims.licenseEpoch < persistedEpoch) {
    return {
      ok: false,
      reason: 'epoch_rollback',
      message:
        `License license_epoch=${claims.licenseEpoch} is below the persisted ` +
        `high-water mark (${persistedEpoch}) for company ${claims.companyId}. ` +
        'Activation refused to prevent rollback.',
    };
  }
  try {
    writeLicenseEnvelopeAtomic(envelope, destPath);
    if (claims.licenseEpoch > persistedEpoch) {
      persistLicenseEpoch(claims.licenseEpoch, claims.companyId);
    }
  } catch (err) {
    return {
      ok: false,
      reason: 'unreadable',
      message: `Failed to write license to ${destPath}: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
  if (envelope.seal_secret !== undefined) {
    const v = validateSealSecret(envelope.seal_secret);
    if (!v.ok) {
      return {
        ok: true,
        claims,
        writtenPath: destPath,
        sealSecretWarning:
          `The licence was installed, but its seal_secret is invalid (${v.reason}). ` +
          'A sealed catalog shard cannot be unsealed with this licence; request a ' +
          'corrected licence file from your Epic AI portal and activate it.',
      };
    }
  }
  return { ok: true, claims, writtenPath: destPath };
}
