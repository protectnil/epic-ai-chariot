/**
 * @epicai/chariot — In-Memory Audit Store Adapter
 * For development and testing. Not for production use.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { AuditStoreAdapter, ActionRecord, AuditFilter, FailureMode } from '../../types/index.js';
import { HashChain } from '../HashChain.js';

export class InMemoryAuditAdapter implements AuditStoreAdapter {
  private readonly records: ActionRecord[] = [];

  append(record: ActionRecord): Promise<void> {
    this.records.push(record);
    return Promise.resolve();
  }

  query(filter: AuditFilter): Promise<ActionRecord[]> {
    let results = [...this.records];

    if (filter.since) {
      const since = filter.since instanceof Date ? filter.since : new Date(filter.since);
      results = results.filter(r => r.timestamp >= since);
    }
    if (filter.until) {
      const until = filter.until instanceof Date ? filter.until : new Date(filter.until);
      results = results.filter(r => r.timestamp <= until);
    }
    if (filter.tier) {
      results = results.filter(r => r.tier === filter.tier);
    }
    if (filter.server) {
      results = results.filter(r => r.server === filter.server);
    }
    if (filter.tool) {
      results = results.filter(r => r.tool === filter.tool);
    }
    if (filter.persona) {
      results = results.filter(r => r.persona === filter.persona);
    }
    if (filter.approvedBy) {
      results = results.filter(r => r.approvedBy === filter.approvedBy);
    }
    if (filter.offset) {
      results = results.slice(filter.offset);
    }
    if (filter.limit) {
      results = results.slice(0, filter.limit);
    }

    return Promise.resolve(results);
  }

  lastRecord(): Promise<ActionRecord | undefined> {
    if (this.records.length === 0) return Promise.resolve(undefined);
    const sorted = [...this.records].sort((a, b) => a.sequenceNumber - b.sequenceNumber);
    return Promise.resolve(sorted[sorted.length - 1]);
  }

  verify(): Promise<{ valid: boolean; chainLength: number; brokenAt?: number }> {
    const { valid, chainLength, brokenAt } = HashChain.verifyChain(this.records);
    return Promise.resolve({ valid, chainLength, brokenAt });
  }

  /**
   * Update the status and output of a pending record by ID.
   * Mutates in-place and cascade-recomputes the SHA-256 hash chain forward from
   * the mutated record so that verifyChain() continues to pass after finalization.
   *
   * Because HashChain.computeHash now covers status/output/durationMs, simply
   * mutating those fields without updating the hash would break chain verification.
   * The cascade: recompute hash[i], then walk i+1..n updating previousHash[j] =
   * hash[j-1] and recomputing hash[j] so the chain remains structurally valid.
   */
  updateStatus(
    id: string,
    status: 'completed' | 'failed',
    output: Record<string, unknown>,
    durationMs: number,
    opts?: { failureMode?: FailureMode; retryCount?: number; retryReasons?: string[]; outcome?: import('../../types/index.js').CallOutcome; errorClass?: import('../../types/index.js').ErrorClass },
  ): Promise<void> {
    const idx = this.records.findIndex(r => r.id === id);
    if (idx === -1) return Promise.resolve();

    const record = this.records[idx];
    record.status = status;
    record.output = output;
    record.durationMs = durationMs;
    // Spec contract: only assign when supplied; never write null/undefined.
    if (opts?.failureMode !== undefined) {
      record.failureMode = opts.failureMode;
    }
    if (opts?.retryCount !== undefined) {
      record.retryCount = opts.retryCount;
    }
    if (opts?.retryReasons !== undefined) {
      record.retryReasons = opts.retryReasons;
    }
    if (opts?.outcome !== undefined) {
      record.outcome = opts.outcome;
    }
    if (opts?.errorClass !== undefined) {
      record.errorClass = opts.errorClass;
    }

    // Recompute hash for the mutated record and cascade forward so the chain
    // remains valid for verifyChain. The hash field itself is excluded from the
    // input to computeHash (canonicalStringify would include it otherwise).
    const { hash: _h, ...withoutHash } = record as ActionRecord & { hash: string };
    record.hash = HashChain.computeHash(withoutHash);

    for (let i = idx + 1; i < this.records.length; i++) {
      const cur = this.records[i];
      cur.previousHash = this.records[i - 1].hash;
      const { hash: _ch, ...curWithout } = cur as ActionRecord & { hash: string };
      cur.hash = HashChain.computeHash(curWithout);
    }

    return Promise.resolve();
  }

  /**
   * Get all records. For testing.
   */
  all(): ActionRecord[] {
    return [...this.records];
  }

  /**
   * Clear all records. For testing.
   */
  clear(): void {
    this.records.length = 0;
  }
}
