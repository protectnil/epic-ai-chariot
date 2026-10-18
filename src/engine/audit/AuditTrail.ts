/**
 * @epicai/chariot — Audit Trail
 * Hash-chained append-only action logging with integrity verification.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { randomUUID } from 'node:crypto';
import type { AuditConfig, AuditStoreAdapter, ActionRecord, AuditFilter, FailureMode } from '../types/index.js';
import { HashChain } from './HashChain.js';
import { InMemoryAuditAdapter } from './adapters/InMemoryAdapter.js';
import { JSONLAdapter } from './adapters/JSONLAdapter.js';
import { SqliteAuditAdapter } from './adapters/SqliteAdapter.js';

/**
 * RFC 4180 CSV field escaping.
 * Wraps fields containing commas, newlines, or double-quotes in double-quotes.
 * Internal double-quotes are doubled.
 */
function csvEscapeField(value: unknown): string {
  const str = String(value ?? '');
  if (str.includes(',') || str.includes('\n') || str.includes('\r') || str.includes('"')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * JSON-serialize a record field for SIEM export (args/response body). Never
 * throws: an unserializable value (e.g. a circular structure that slipped
 * through a tool adapter) degrades to a sentinel string rather than
 * aborting the whole export.
 */
function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value ?? {});
  } catch {
    return '"<unserializable>"';
  }
}

/** UTF-8 byte size of a record's response body, for SIEM response-size fields. */
function responseSizeBytes(output: Record<string, unknown>): number {
  return Buffer.byteLength(safeJsonStringify(output), 'utf8');
}

/** `server:tool` composite identifier — matches the toolId convention used
 * elsewhere in the engine (see HybridRetriever/ToolPreFilter) so SIEM rows
 * correlate against the same identifier other subsystems log. */
function toolId(r: Pick<ActionRecord, 'server' | 'tool'>): string {
  return `${r.server}:${r.tool}`;
}

export class AuditTrail {
  private readonly adapter: AuditStoreAdapter;
  private readonly integrity: 'sha256-chain' | 'none';
  private sequenceNumber = 0;
  private lastHash = '';
  private recordQueue: Promise<unknown> = Promise.resolve();

  constructor(config: AuditConfig) {
    this.integrity = config.integrity;

    if (config.store === 'custom' && config.adapter) {
      this.adapter = config.adapter;
    } else if (config.store === 'append-only-log') {
      if (!config.path) {
        throw new Error('AuditConfig store "append-only-log" requires a "path" field');
      }
      this.adapter = new JSONLAdapter(config.path);
    } else if (config.store === 'sqlite') {
 // SQLite durable audit backend. Path required;
      // production default of ~/.epic-ai/chariot.db is set by the
      // EpicAI startup wiring, not in this constructor.
      if (!config.path) {
        throw new Error('AuditConfig store "sqlite" requires a "path" field');
      }
      this.adapter = new SqliteAuditAdapter(config.path);
    } else {
      // Default to in-memory
      this.adapter = new InMemoryAuditAdapter();
    }
  }

  /**
   * Restore sequenceNumber and lastHash from existing records in the adapter.
   * Call this after construction when using a persistent adapter so that
   * sequence numbers and hash chain continuity are preserved across restarts.
   *
   * Uses adapter.lastRecord() when available to avoid loading the entire chain
   * into memory (which is O(n) and would exhaust heap for a long-running chain).
   * Falls back to query({}) + reduce for adapters that do not implement lastRecord.
   */
  async init(): Promise<void> {
    let last: import('../types/index.js').ActionRecord | undefined;
    if (typeof this.adapter.lastRecord === 'function') {
      last = await this.adapter.lastRecord();
    } else {
      const allRecords = await this.adapter.query({});
      if (allRecords.length > 0) {
        last = allRecords.reduce((a, b) => a.sequenceNumber > b.sequenceNumber ? a : b);
      }
    }
    if (last) {
      this.sequenceNumber = last.sequenceNumber + 1;
      this.lastHash = last.hash;
    }
  }

  /**
   * Record an action. Assigns ID, sequence number, computes hash chain.
   * Serialized via a promise queue to prevent race conditions in concurrent calls.
   *
   * Queue design: the queue itself never rejects — callers receive errors via the
   * returned promise, but a failed append does NOT poison the queue for subsequent
   * record() calls. This means an ENOSPC/EROFS burst drops individual records but
   * does not silently no-op the rest of the session.
   */
  record(
    partial: Omit<ActionRecord, 'id' | 'sequenceNumber' | 'previousHash' | 'hash'>,
  ): Promise<ActionRecord> {
    // Recover from any prior queue failure so a single append error does not
    // silence all subsequent records. The caller still receives the error via
    // `next` directly.
    const next = this.recordQueue.then(
      () => this._doRecord(partial),
      () => this._doRecord(partial),
    );
    // Drain both fulfilment and rejection off the queue so recordQueue is always
    // resolved-with-void, never rejected.
    this.recordQueue = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  private async _doRecord(
    partial: Omit<ActionRecord, 'id' | 'sequenceNumber' | 'previousHash' | 'hash'>,
  ): Promise<ActionRecord> {
    const id = randomUUID();
    // Snapshot current state — do NOT increment yet. If append fails, these
    // values must remain unchanged so the next record() call can reuse them.
    const sequenceNumber = this.sequenceNumber;
    const previousHash = this.lastHash;

    const recordWithoutHash = {
      ...partial,
      id,
      sequenceNumber,
      previousHash,
    };

    let hash = '';
    if (this.integrity === 'sha256-chain') {
      hash = HashChain.computeHash(recordWithoutHash);
    }

    const record: ActionRecord = { ...recordWithoutHash, hash };

    // Advance chain state ONLY after a successful write so a storage failure
    // (ENOSPC / EROFS) leaves this.sequenceNumber and this.lastHash consistent
    // for the next attempt rather than creating a gap or stale-hash state.
    await this.adapter.append(record);
    this.sequenceNumber++;
    this.lastHash = hash;

    return record;
  }

  /**
   * Update the status of a previously recorded pending audit entry.
   * Delegates to the adapter's updateStatus if available; silently no-ops otherwise.
   *
   * For sha256-chain integrity: the InMemoryAuditAdapter cascade-recomputes hashes
   * forward from the mutated record (see InMemoryAuditAdapter.updateStatus). After
   * delegating, this method re-queries the adapter to sync this.lastHash so a
   * subsequent record() call uses the correct previousHash linkage.
   */
  async updateStatus(
    id: string,
    status: 'completed' | 'failed',
    output: Record<string, unknown>,
    durationMs: number,
    opts?: { failureMode?: FailureMode; retryCount?: number; retryReasons?: string[]; outcome?: import('../types/index.js').CallOutcome; errorClass?: import('../types/index.js').ErrorClass },
  ): Promise<void> {
    if (typeof this.adapter.updateStatus !== 'function') return;
    await this.adapter.updateStatus(id, status, output, durationMs, opts);
    if (this.integrity === 'sha256-chain') {
      // Sync lastHash — the adapter may have cascade-recomputed record hashes
      // (InMemoryAuditAdapter does this to preserve chain integrity). Without this
      // sync a subsequent record() call would store a stale previousHash, breaking
      // the hash chain link from the updated record forward.
      const all = await this.adapter.query({});
      // Filter to only proper chain records (exclude JSONLAdapter status-update
      // supplement lines that carry no sequenceNumber or hash). Shared predicate
      // with verifyChain so all sites agree.
      const chained = all.filter(r => HashChain.isChainRecord(r));
      if (chained.length > 0) {
        const tail = chained.reduce((a, b) => a.sequenceNumber > b.sequenceNumber ? a : b);
        this.lastHash = tail.hash;
      }
    }
  }

  /**
   * Query the audit trail with filters.
   */
  async query(filter: AuditFilter): Promise<ActionRecord[]> {
    return this.adapter.query(filter);
  }

  /**
   * Verify the integrity of the hash chain.
   */
  async verify(): Promise<{ valid: boolean; chainLength: number; brokenAt?: number }> {
    if (this.integrity === 'none') {
      return { valid: true, chainLength: this.sequenceNumber };
    }

    const allRecords = await this.adapter.query({});
    return HashChain.verifyChain(allRecords);
  }

  /**
   * Export the audit trail in the specified format.
   */
  async export(format: 'json' | 'csv' | 'syslog'): Promise<string> {
    const records = await this.adapter.query({});

    switch (format) {
      case 'json':
        return JSON.stringify(records, null, 2);

      case 'csv': {
        if (records.length === 0) return '';
        // Vulnerability 16 fix: SIEM ingestion needs full tool-call args and
        // response body (not just metadata), plus who/where attribution
        // (userId/sourceIp) and a stable per-tool correlation id (toolId).
        // Previously this format omitted ALL of input/output/userId/
        // sourceIp — a SIEM consuming this export could not answer "what
        // did this actor send/receive" or "where did this call originate."
        const headers = [
          'id', 'sequenceNumber', 'timestamp', 'userId', 'sourceIp', 'toolId',
          'action', 'tool', 'server', 'tier', 'status', 'persona', 'approvedBy',
          'input', 'output', 'outputSizeBytes', 'durationMs', 'hash',
        ];
        const rows = records.map(r => [
          r.id,
          r.sequenceNumber,
          r.timestamp instanceof Date ? r.timestamp.toISOString() : r.timestamp,
          r.userId ?? '',
          r.sourceIp ?? '',
          toolId(r),
          r.action,
          r.tool,
          r.server,
          r.tier,
          r.status,
          r.persona,
          r.approvedBy ?? '',
          safeJsonStringify(r.input),
          safeJsonStringify(r.output),
          responseSizeBytes(r.output),
          r.durationMs,
          r.hash,
        ].map(csvEscapeField).join(','));
        return [headers.map(csvEscapeField).join(','), ...rows].join('\n');
      }

      case 'syslog':
        return records.map(r => {
          const ts = r.timestamp instanceof Date ? r.timestamp.toISOString() : r.timestamp;
          // Replace newlines in field values to prevent syslog injection
          const sanitize = (v: string | number) => String(v).replace(/[\n\r]/g, ' ');
          // Vulnerability 16 fix: same attribution + full args/response-body
          // gap as the CSV path above. args=/response= carry the sanitized
          // JSON payload; responseBytes= gives the SIEM a cheap size signal
          // without parsing the payload.
          return `<14>${sanitize(ts)} epic-ai audit[${r.sequenceNumber}]: ` +
            `user=${sanitize(r.userId ?? 'unknown')} srcip=${sanitize(r.sourceIp ?? 'unknown')} ` +
            `toolid=${sanitize(toolId(r))} action=${sanitize(r.action)} tool=${sanitize(r.tool)} ` +
            `server=${sanitize(r.server)} tier=${sanitize(r.tier)} status=${sanitize(r.status)} ` +
            `persona=${sanitize(r.persona)} args=${sanitize(safeJsonStringify(r.input))} ` +
            `response=${sanitize(safeJsonStringify(r.output))} responseBytes=${sanitize(responseSizeBytes(r.output))} ` +
            `duration=${sanitize(r.durationMs)}ms`;
        }).join('\n');

      default:
        throw new Error(`Unsupported export format: ${format as string}`);
    }
  }
}
