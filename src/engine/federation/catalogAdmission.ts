/**
 * @epicai/chariot — §5.6 catalog admission: ONE rule, ONE implementation.
 *
 * CHARIOT-SPEC.md:436 requires this module to exist and to be the only place
 * the comparison is written:
 *
 *   "This rule is ONE rule with ONE implementation. Every admission site — the
 *    adapter-catalog bundle and the retrieval bundle — SHALL evaluate it
 *    through a single shared function rather than a local copy."
 *
 * Two hand-maintained copies previously drifted into contradictory readings of
 * the same clause: `AdapterCatalog` rejected every equal epoch and bricked boot
 * on the second start, while `VectorIndexVerifier` admitted an equal
 * epoch and additionally treated an ABSENT persisted hash as a wildcard that
 * matched any bundle. No gate caught the divergence. This module replaces both.
 *
 * The classification is total — every input maps to exactly one of advance /
 * re-admission / rejection (CHARIOT-SPEC.md:428-432) — and rejection always
 * names the failing condition, which the spec requires at :432 and :456.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/**
 * The persisted high-water mark, structurally. Declared here rather than
 * imported so this module sits below BOTH `federation/AdapterCatalog` and
 * `retrieval/VectorIndexVerifier` in the import graph with no cycle.
 * `CatalogEpochState` satisfies it structurally.
 */
export interface PersistedCatalogMark {
  epoch: number;
  catalogVersion: number;
  /** SHA-256 (hex) of the exact signed bytes admitted at this mark. */
  bundleSha256?: string;
}

export interface CatalogAdmissionInput {
  /** Envelope epoch (Unix ms integer), signature-verified. */
  epoch: number;
  /** Envelope catalogVersion (non-negative integer), signature-verified. */
  catalogVersion: number;
  /**
   * SHA-256 (hex) computed by the CALLER over the exact signature-verified
   * envelope bytes. Undefined means the caller could not establish identity,
   * which is `identity_unproven` at an equal epoch — never a wildcard.
   */
  bundleSha256?: string;
  /** The persisted mark, or null on a fresh install. */
  persisted: PersistedCatalogMark | null;
}

export type CatalogAdmissionKind = 'advance' | 're-admission' | 'rejection';

/**
 * Why a bundle was rejected. Each value names ONE failing condition, so the
 * caller can log `{reason}` per CHARIOT-SPEC.md:456 without re-deriving it.
 */
export type CatalogRejectionReason =
  | 'epoch_below_persisted'
  | 'catalog_version_downgrade'
  | 'identity_unproven_persisted'
  | 'identity_unproven_incoming'
  | 'identity_mismatch'
  | 'catalog_version_mismatch';

export interface CatalogAdmissionResult {
  kind: CatalogAdmissionKind;
  /** Present iff kind === 'rejection'. */
  reason?: CatalogRejectionReason;
  /** Human-readable, always names the failing condition on a rejection. */
  message: string;
}

/**
 * Operator-actionable remedy text for the two identity-unproven cases. The
 * spec requires this guidance by name at CHARIOT-SPEC.md:434 ("fails closed
 * with operator-actionable guidance").
 */
const IDENTITY_REMEDY =
  'remove the epoch file to re-establish the mark from the current signed bundle, ' +
  'or publish at a higher epoch';

/**
 * Classify an envelope against the persisted mark per CHARIOT-SPEC.md:428-434.
 *
 * Callers MUST have verified the Ed25519 envelope signature first; this
 * function decides ordering/identity only, never authenticity.
 *
 * A `re-admission` result means the caller may attach to the bundle but MUST
 * NOT rewrite the high-water mark (:431, :457) — a re-admission is not a
 * publication.
 */
export function classifyCatalogAdmission(
  input: CatalogAdmissionInput,
): CatalogAdmissionResult {
  const { epoch, catalogVersion, bundleSha256, persisted } = input;

  // CHARIOT-SPEC.md:423-424 type the envelope fields as `number (Unix ms
  // integer)` and `number (non-negative integer)`. Both call sites already
  // reject non-integers at the envelope boundary before reaching this
  // function, so a non-integer here is a CALLER invariant violation, not a
  // bundle-content decision — it must not be silently folded into one of the
  // three admission classes, where a NaN epoch would compare false against
  // every branch and fall through to re-admission.
  if (!Number.isInteger(epoch)) {
    throw new TypeError(
      `classifyCatalogAdmission: epoch must be an integer (§5.6:423), got ${String(epoch)}`,
    );
  }
  if (!Number.isInteger(catalogVersion) || catalogVersion < 0) {
    throw new TypeError(
      'classifyCatalogAdmission: catalogVersion must be a non-negative integer ' +
        `(§5.6:424), got ${String(catalogVersion)}`,
    );
  }
  if (persisted !== null) {
    if (
      !Number.isInteger(persisted.epoch) ||
      !Number.isInteger(persisted.catalogVersion) ||
      persisted.catalogVersion < 0
    ) {
      throw new TypeError(
        'classifyCatalogAdmission: the persisted mark carries a non-integer epoch, or a ' +
          'catalogVersion that is not a non-negative integer (§5.6:423-424); a malformed ' +
          'mark must be rejected at the store boundary, never compared against. A negative ' +
          'persisted catalogVersion would let any candidate at version 0 advance past it.',
      );
    }
  }

  // No mark yet — first bundle this deployment has ever accepted (:430).
  if (persisted === null) {
    return { kind: 'advance', message: 'no persisted mark; first admission' };
  }

  if (epoch < persisted.epoch) {
    return {
      kind: 'rejection',
      reason: 'epoch_below_persisted',
      message:
        `bundle epoch ${epoch} is below persisted epoch ${persisted.epoch} — ` +
        'refusing replay/rollback (§5.6)',
    };
  }

  if (epoch > persisted.epoch) {
    // Advance still carries the downgrade defense (:430, :424).
    if (catalogVersion < persisted.catalogVersion) {
      return {
        kind: 'rejection',
        reason: 'catalog_version_downgrade',
        message:
          `bundle catalogVersion ${catalogVersion} is below persisted ` +
          `catalogVersion ${persisted.catalogVersion} — refusing downgrade (§5.6)`,
      };
    }
    return {
      kind: 'advance',
      message: `epoch ${epoch} advances persisted ${persisted.epoch}`,
    };
  }

  // epoch === persisted.epoch — re-admission ONLY on PROVEN identity (:431).
  // Identity is proven, never assumed (:434): an absent hash on EITHER side is
  // identity_unproven and fails closed. Treating an absent persisted hash as a
  // wildcard would let anyone who can delete one field from a local file admit
  // an arbitrary bundle at the pinned epoch — strictly weaker than the epoch
  // check it stands in for.
  if (persisted.bundleSha256 === undefined) {
    return {
      kind: 'rejection',
      reason: 'identity_unproven_persisted',
      message:
        `bundle epoch ${epoch} equals the persisted epoch but the persisted record ` +
        `carries no bundleSha256, so identity cannot be proven — ${IDENTITY_REMEDY} (§5.6)`,
    };
  }
  if (bundleSha256 === undefined) {
    return {
      kind: 'rejection',
      reason: 'identity_unproven_incoming',
      message:
        `bundle epoch ${epoch} equals the persisted epoch but the incoming bundle's ` +
        `bundleSha256 was not supplied, so identity cannot be proven — ${IDENTITY_REMEDY} (§5.6)`,
    };
  }
  if (bundleSha256 !== persisted.bundleSha256) {
    return {
      kind: 'rejection',
      reason: 'identity_mismatch',
      message:
        `bundle epoch ${epoch} equals the persisted epoch but the bundle is a DIFFERENT ` +
        'artifact than the one accepted at that mark — refusing replay (§5.6)',
    };
  }
  // Identity is proven; the clause additionally requires catalogVersion
  // EQUALITY for a re-admission (:431, :457) — a re-admission is not a
  // publication, so the version cannot move under a fixed epoch.
  if (catalogVersion !== persisted.catalogVersion) {
    return {
      kind: 'rejection',
      reason: 'catalog_version_mismatch',
      message:
        `bundle epoch ${epoch} equals the persisted epoch with a byte-identical bundle, ` +
        `but catalogVersion ${catalogVersion} differs from the persisted ` +
        `${persisted.catalogVersion} — a re-admission cannot change the version (§5.6)`,
    };
  }

  return {
    kind: 're-admission',
    message:
      `epoch ${epoch} re-admitted: byte-identical bundle at the persisted mark ` +
      '(idempotent restart; high-water mark not rewritten)',
  };
}
