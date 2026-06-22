/**
 * `chariot license activate <path>` per portal spec §10.1.
 *
 * Reads a JSON envelope ({ jwt, renewal_secret }) from <path>, verifies
 * the JWT signature against the embedded ProtectNIL public key (via
 * loader.verifyAndDecode), refuses on bad signature / expired license /
 * missing renewal_secret, and atomically writes the envelope to
 * ~/.epic-ai/chariot.license (tmp + rename, mode 0600). The license
 * file replaces any existing one.
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
  type VerifiedClaims,
} from './loader.js';

export type ActivateOutcome =
  | {
      ok: true;
      claims: VerifiedClaims;
      writtenPath: string;
    }
  | {
      ok: false;
      reason:
        | 'unreadable'
        | 'invalid_envelope'
        | 'invalid_signature'
        | 'expired'
        | 'missing_renewal_secret'
        | 'epoch_rollback';
      message: string;
    };

interface RawEnvelope {
  jwt: string;
  renewal_secret: string;
}

function parseEnvelope(content: string): RawEnvelope | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const r = parsed as { jwt?: unknown; renewal_secret?: unknown };
  if (typeof r.jwt !== 'string' || r.jwt.length === 0) return null;
  if (typeof r.renewal_secret !== 'string' || r.renewal_secret.length === 0) {
    return null;
  }
  return { jwt: r.jwt, renewal_secret: r.renewal_secret };
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
  const serialized = JSON.stringify(envelope, null, 2) + '\n';
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
  return { ok: true, claims, writtenPath: destPath };
}
