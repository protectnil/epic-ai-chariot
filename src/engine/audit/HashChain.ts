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
 * Out-of-band anchor / attestation evidence is NOT held in this class.
 *
 * Re-stitch and silent-truncation detection are provided by FILE-BASED
 * evidence that is persisted and verified independently of any HashChain
 * instance:
 *   - src/engine/audit/anchor.ts — RFC-3161 external anchor. Persisted as a
 *     `.tsr` and verified via `verifyAnchor` (`chariot audit verify-anchor`).
 *   - src/engine/audit/length-attestation.ts — signed length attestation.
 *     Persisted as JSON and verified via `loadAttestations` + `detectTruncation`
 *     (`chariot audit verify-length`).
 *
 * A previous version exposed per-instance `recordAnchor` /
 * `recordLengthAttestation` / `getAnchorMetadata`, but the CLI wrote them to a
 * throwaway instance that was garbage-collected at process exit and no verifier
 * ever read them — dead, misleading API. It has been removed; use the
 * file-based verify paths above.
 */
export class HashChain {
  /**
   * Compute SHA-256 hash of a record.
   * The hash field is set to empty string during computation.
   * Uses canonicalStringify so nested object key order does not affect
   * the hash (see src/util/canonical-json.ts for the determinism
   * contract). Date fields serialize via their toJSON() method to
   * the same ISO-8601 string they would under standard JSON.stringify.
   */
  static computeHash(record: Omit<ActionRecord, 'hash'>): string {
    // Hash ALL fields — including status, output, and durationMs — so that any
    // post-hoc edit to those fields (e.g. flipping status completed→failed, or
    // altering output on a JSONL serve-path record) is detected by verifyChain.
    //
    // On the serve-sink path (serveAuditSink.recordDispatch) records are always
    // written complete and final in a single record() call; updateStatus is never
    // invoked on that path. On the orchestrator path (EpicAI.create) the
    // InMemoryAuditAdapter.updateStatus cascade-recomputes hashes forward from
    // the mutated record to maintain chain integrity after finalization.
    const serializable = {
      ...(record as Record<string, unknown>),
      hash: '',
    };
    const json = canonicalStringify(serializable);
    return createHash('sha256').update(json).digest('hex');
  }

  /**
   * True when a record is a full hash-chain participant — i.e. it carries a
   * numeric `sequenceNumber` and a non-empty `hash`. JSONLAdapter status-update
   * supplement lines carry neither (they only patch {id,status,output,...}),
   * so they are NOT chain records and must be excluded before verifyChain,
   * otherwise verifyChain recomputes a hash for a hashless supplement and
   * reports the chain broken even with zero tampering.
   *
   * Single source of truth for the three call sites that must agree:
   * AuditTrail.updateStatus lastHash sync, JSONLAdapter.lastRecord, and both
   * verify() paths.
   */
  static isChainRecord(r: ActionRecord): boolean {
    return typeof r.sequenceNumber === 'number' && typeof r.hash === 'string' && r.hash.length > 0;
  }

  /**
   * Verify the integrity of a chain of records.
   * Walks from first to last, recomputing each hash and checking previousHash links.
   *
   * Non-chain records (e.g. JSONLAdapter status-update supplement lines) are
   * filtered out first — they are not part of the hash chain and would
   * otherwise be misread as tampering.
   *
   * @returns valid=true if the entire chain is intact, or brokenAt=sequenceNumber where it breaks.
   */
  static verifyChain(allRecords: ActionRecord[]): { valid: boolean; chainLength: number; brokenAt?: number } {
    const records = allRecords.filter(r => HashChain.isChainRecord(r));
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
