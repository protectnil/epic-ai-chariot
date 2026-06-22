/**
 * @epicai/chariot — Hash Chain
 * SHA-256 chain integrity for tamper-evident audit logging.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createHash } from 'node:crypto';
import { canonicalStringify } from '../../util/canonical-json.js';
import type { ActionRecord } from '../types/index.js';

/**
 * Out-of-band anchor / attestation metadata the hash chain exposes to
 * operators and verifiers. Populated by the operator-driven CLI flows
 * (`chariot audit anchor` → , `chariot audit attest` → )
 * — NOT by the per-record append loop. See:
 *   - src/engine/audit/anchor.ts          (RFC-3161 external anchor)
 *   - src/engine/audit/length-attestation.ts (signed length attestation)
 *
 * A verifier that holds the latest values from `getAnchorMetadata`
 * detects two attacks the bare hash chain cannot:
 *   - full re-stitch (Mode 2 of eval 07) — `lastAnchoredHead` was
 *     externally timestamped and any rewritten chain head differs.
 *   - silent truncation (Mode 5 of eval 07) — `lastAttestedLength`
 *     bounds the minimum acceptable current chain length.
 *
 * CLI registration GAP — neither `chariot audit anchor` nor `chariot
 * audit attest` is wired into the CLI registrar by this commit. The
 * CLI surface lives outside the engine package boundary; wire-up is a
 * follow-up commit on the CLI side.
 */
export interface AnchorMetadata {
  lastAnchoredHead?: Buffer;
  lastAnchoredAt?: Date;
  lastAttestedLength?: number;
}

export class HashChain {
  /**
   * Per-instance anchor metadata. Static methods on HashChain operate
   * over caller-supplied record arrays so this state lives on the
   * instance returned to operators rather than as module-global state.
   */
  private anchorMetadata: AnchorMetadata = {};

  /** See {@link AnchorMetadata}. Returns a defensive shallow copy so
   *  callers cannot mutate the internal record. The Buffer reference
   *  IS shared — Buffers are treated as immutable bytes by convention
   *  throughout this file. */
  getAnchorMetadata(): AnchorMetadata {
    return { ...this.anchorMetadata };
  }

  /** Hook for the `chariot audit anchor` CLI handler. Records the
   *  head hash and time most recently anchored to the operator's TSA.
   *  Does NOT itself perform the anchoring — see
   *  src/engine/audit/anchor.ts `anchorChainHead`. */
  recordAnchor(headHash: Buffer, anchoredAt: Date): void {
    if (!Buffer.isBuffer(headHash) || headHash.length !== 32) {
      throw new TypeError('recordAnchor: headHash must be a 32-byte Buffer');
    }
    if (!(anchoredAt instanceof Date) || Number.isNaN(anchoredAt.getTime())) {
      throw new TypeError('recordAnchor: anchoredAt must be a valid Date');
    }
    this.anchorMetadata.lastAnchoredHead = headHash;
    this.anchorMetadata.lastAnchoredAt = anchoredAt;
  }

  /** Hook for the `chariot audit attest` CLI handler. Records the
   *  highest length ever asserted in a signed length attestation for
   *  this chain. Detection of truncation against this value is the
   *  caller's responsibility — see
   *  src/engine/audit/length-attestation.ts `detectTruncation`. */
  recordLengthAttestation(length: number): void {
    if (!Number.isInteger(length) || length < 0) {
      throw new TypeError('recordLengthAttestation: length must be a non-negative integer');
    }
    const prior = this.anchorMetadata.lastAttestedLength ?? 0;
    if (length > prior) {
      this.anchorMetadata.lastAttestedLength = length;
    }
  }

  /**
   * Compute SHA-256 hash of a record.
   * The hash field is set to empty string during computation.
   * Uses canonicalStringify so nested object key order does not affect
   * the hash (see src/util/canonical-json.ts for the determinism
   * contract). Date fields serialize via their toJSON() method to
   * the same ISO-8601 string they would under standard JSON.stringify.
   */
  static computeHash(record: Omit<ActionRecord, 'hash'>): string {
    // Exclude mutable fields that may be updated after initial hashing
    // (status, output, durationMs are set by updateStatus on pending records)
    const { status: _s, output: _o, durationMs: _d, ...immutableFields } = record as Record<string, unknown>;
    const serializable = {
      ...immutableFields,
      hash: '',
    };
    const json = canonicalStringify(serializable);
    return createHash('sha256').update(json).digest('hex');
  }

  /**
   * Verify the integrity of a chain of records.
   * Walks from first to last, recomputing each hash and checking previousHash links.
   *
   * @returns valid=true if the entire chain is intact, or brokenAt=sequenceNumber where it breaks.
   */
  static verifyChain(records: ActionRecord[]): { valid: boolean; chainLength: number; brokenAt?: number } {
    if (records.length === 0) {
      return { valid: true, chainLength: 0 };
    }

    // Sort by sequence number
    const sorted = [...records].sort((a, b) => a.sequenceNumber - b.sequenceNumber);

    for (let i = 0; i < sorted.length; i++) {
      const record = sorted[i];

      // Verify hash of this record
      const { hash: _storedHash, ...recordWithoutHash } = record;
      const computedHash = this.computeHash(recordWithoutHash);
      if (computedHash !== record.hash) {
        return { valid: false, chainLength: sorted.length, brokenAt: record.sequenceNumber };
      }

      // Verify chain link (previousHash)
      if (i === 0) {
        // First record should have empty previousHash
        if (record.previousHash !== '') {
          return { valid: false, chainLength: sorted.length, brokenAt: record.sequenceNumber };
        }
      } else {
        // Subsequent records should reference the previous record's hash
        if (record.previousHash !== sorted[i - 1].hash) {
          return { valid: false, chainLength: sorted.length, brokenAt: record.sequenceNumber };
        }
      }
    }

    return { valid: true, chainLength: sorted.length };
  }
}
