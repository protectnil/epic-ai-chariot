/**
 * @epicai/chariot — SQLite-backed AuditStoreAdapter
 *
 * Durable, queryable, append-only audit store backed by `node:sqlite`.
 * Joins the existing InMemoryAuditAdapter + JSONLAdapter under the
 * pluggable `AuditConfig.store` adapter pattern. Per spec
 * sqlite-durable-backend-2026-05.md §3.
 *
 * Tamper-evidence is defense-in-depth:
 *   - Layer 1 (engine): BEFORE UPDATE / BEFORE DELETE triggers on
 *     audit_records refuse mutation of hash-chain-covered fields and
 *     refuse deletion outright. The pending → completed/failed status
 *     transition is the one permitted mutation (matches the existing
 *     contract in `../AuditTrail.ts`
 *     updateStatus and the field-exclusion in HashChain.computeHash).
 *   - Layer 2 (cryptographic): the SHA-256 hash chain already on every
 *     ActionRecord. verify() walks rows in sequenceNumber order and
 *     surfaces the breakingAt sequence on any tamper.
 *   - Layer 3 (external attestation): `audit/anchor.ts` pins the chain
 *     head to an external anchor; layer 2 detection becomes unforgeable.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { DatabaseSync, type StatementSync } from 'node:sqlite';
import type { ActionRecord, AuditFilter, AuditStoreAdapter, CallOutcome, ErrorClass, FailureMode, StepKind } from '../../types/index.js';
import { HashChain } from '../HashChain.js';
import { canonicalStringify } from '../../../util/canonical-json.js';

interface AuditRow {
  id: string;
  sequence_number: number;
  previous_hash: string;
  hash: string;
  timestamp: number;
  action: string;
  tool: string;
  server: string;
  tier: 'auto' | 'escalate' | 'approve';
  status: 'pending' | 'completed' | 'failed';
  input: string;
  output: string;
  persona: string;
  approved_by: string | null;
  denied_by: string | null;
  deny_reason: string | null;
  duration_ms: number;
  trace_id: string | null;
  parent_step_id: string | null;
  step_kind: string | null;
  confidence: number | null;
  retry_count: number | null;
  retry_reasons: string | null;
  outcome: string | null;
  error_class: string | null;
  failure_mode: string | null;
}

export class SqliteAuditAdapter implements AuditStoreAdapter {
  private readonly db: DatabaseSync;
  private readonly appendStmt: StatementSync;
  private readonly updateStatusStmt: StatementSync;
  private readonly verifyStmt: StatementSync;

  constructor(dbPath: string, deps?: { Database?: typeof DatabaseSync }) {
    const Database = deps?.Database ?? DatabaseSync;
    this.db = new Database(dbPath);
    // Close the handle if schema setup, trigger creation, or
    // statement preparation throws — prevents leaking the database
    // lock on construction failure.
    try {
    this.db.exec(`PRAGMA journal_mode=WAL`);
    this.db.exec(`PRAGMA foreign_keys=ON`);
    // Multi-process deployments: wait up to 5s for the writer lock instead of
    // failing immediately with SQLITE_BUSY.
    this.db.exec(`PRAGMA busy_timeout=5000`);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_records (
        id TEXT PRIMARY KEY,
        sequence_number INTEGER UNIQUE NOT NULL,
        previous_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        action TEXT NOT NULL,
        tool TEXT NOT NULL,
        server TEXT NOT NULL,
        tier TEXT NOT NULL CHECK(tier IN ('auto','escalate','approve')),
        status TEXT NOT NULL CHECK(status IN ('pending','completed','failed')),
        input TEXT NOT NULL,
        output TEXT NOT NULL,
        persona TEXT NOT NULL,
        approved_by TEXT,
        denied_by TEXT,
        deny_reason TEXT,
        duration_ms INTEGER NOT NULL,
        trace_id TEXT,
        parent_step_id TEXT,
        step_kind TEXT,
        confidence REAL,
        retry_count INTEGER,
        retry_reasons TEXT,
        outcome TEXT,
        error_class TEXT,
        failure_mode TEXT
      );
    `);
    this.db.exec(`CREATE INDEX IF NOT EXISTS audit_by_timestamp ON audit_records(timestamp);`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS audit_by_server_tool ON audit_records(server, tool);`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS audit_by_trace ON audit_records(trace_id);`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS audit_by_persona ON audit_records(persona);`);

    // Engine-level append-only enforcement.
    //
    // DROP-then-CREATE (not CREATE IF NOT EXISTS) so an upgraded
    // chariot picks up the latest trigger logic on every startup. A
    // pre-existing DB created under an older trigger version would
    // otherwise keep its outdated guards in place under
    // CREATE IF NOT EXISTS semantics.
    //
    // Two clauses, both raising ABORT when violated:
    //   (a) Hash-chain-immutable fields — always blocked. These are
    //       the fields HashChain.computeHash includes in the chain
    //       hash; any mutation would silently invalidate the chain.
    //   (b) Mutable-once fields (status, output, duration_ms,
    //       failure_mode, retry_count, retry_reasons, outcome,
    //       error_class) — blocked UNLESS the UPDATE is the
    //       legitimate pending → terminal transition (OLD.status =
    //       'pending' AND NEW.status IN ('completed','failed')).
    //
 // round 5: the pending → terminal exemption now requires
    // BOTH status flip AND output change. Status-only flips ABORT.
    // Status + duration_ms partial tampering ABORTs (output unchanged).
    // Legitimate empty-output completions still pass because
    // SqliteAuditAdapter.updateStatus() routes the output through
    // normalizeCompletionOutput() which writes a sentinel object for
    // empty payloads — so the stored `output` column always differs
    // from the pending placeholder's empty `{}`. denormalizeCompletion-
    // Output() on the read path returns the sentinel to `{}` so
    // ActionRecord consumers see the original shape.
    //
    // SQLite NULL comparisons use IS NOT (not !=); failure_mode et
    // al. are nullable so we use IS NOT to detect change-or-null-flip.
    // Atomic trigger refresh: wrap DROP + CREATE in a single
    // transaction so a concurrent writer cannot hit audit_records in
    // the window between the DROP and the CREATE. Without the
    // transaction the brief gap reopens the tamper surface every
    // startup (pre-push review round 3).
    this.db.exec(`
      BEGIN IMMEDIATE TRANSACTION;
      DROP TRIGGER IF EXISTS audit_records_no_mutate_immutable;
      CREATE TRIGGER audit_records_no_mutate_immutable
      BEFORE UPDATE ON audit_records
      WHEN
        OLD.id != NEW.id OR
        OLD.sequence_number != NEW.sequence_number OR
        OLD.previous_hash != NEW.previous_hash OR
        OLD.hash != NEW.hash OR
        OLD.timestamp != NEW.timestamp OR
        OLD.action != NEW.action OR
        OLD.tool != NEW.tool OR
        OLD.server != NEW.server OR
        OLD.tier != NEW.tier OR
        OLD.input != NEW.input OR
        OLD.persona != NEW.persona OR
        (
          (OLD.status != NEW.status OR
           OLD.output != NEW.output OR
           OLD.duration_ms != NEW.duration_ms OR
           OLD.failure_mode IS NOT NEW.failure_mode OR
           OLD.retry_count IS NOT NEW.retry_count OR
           OLD.retry_reasons IS NOT NEW.retry_reasons OR
           OLD.outcome IS NOT NEW.outcome OR
           OLD.error_class IS NOT NEW.error_class)
          AND NOT (
            -- Legitimate pending → terminal transition:
            -- the supported updateStatus() path always changes
            -- status AND output (sentinel-normalized if empty) AND
            -- duration_ms (coerced to ≥1 if caller passed 0). A
            -- direct-SQL bypass that omits ANY of these three
            -- mutations falls into the trigger and ABORTs.
            OLD.status = 'pending'
            AND (NEW.status = 'completed' OR NEW.status = 'failed')
            AND OLD.output != NEW.output
            AND OLD.duration_ms != NEW.duration_ms
          )
        )
      BEGIN
        SELECT RAISE(ABORT, 'audit_records: immutable field mutation blocked');
      END;
      DROP TRIGGER IF EXISTS audit_records_no_delete;
      CREATE TRIGGER audit_records_no_delete
      BEFORE DELETE ON audit_records
      BEGIN
        SELECT RAISE(ABORT, 'audit_records: deletion blocked');
      END;
      COMMIT;
    `);

    this.appendStmt = this.db.prepare(`
      INSERT INTO audit_records (
        id, sequence_number, previous_hash, hash, timestamp, action, tool,
        server, tier, status, input, output, persona, approved_by, denied_by,
        deny_reason, duration_ms, trace_id, parent_step_id, step_kind,
        confidence, retry_count, retry_reasons, outcome, error_class, failure_mode
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `);
    this.updateStatusStmt = this.db.prepare(`
      UPDATE audit_records
      SET status = ?,
          output = ?,
          duration_ms = ?,
          failure_mode = COALESCE(?, failure_mode),
          retry_count = COALESCE(?, retry_count),
          retry_reasons = COALESCE(?, retry_reasons),
          outcome = COALESCE(?, outcome),
          error_class = COALESCE(?, error_class)
      WHERE id = ?
    `);
    this.verifyStmt = this.db.prepare(`
      SELECT id, sequence_number, previous_hash, hash, timestamp, action, tool,
             server, tier, status, input, output, persona, approved_by, denied_by,
             deny_reason, duration_ms, trace_id, parent_step_id, step_kind,
             confidence, retry_count, retry_reasons, outcome, error_class, failure_mode
      FROM audit_records ORDER BY sequence_number ASC
    `);
    } catch (err) {
      this.db.close();
      throw err;
    }
  }

  append(record: ActionRecord): Promise<void> {
    this.appendStmt.run(
      record.id,
      record.sequenceNumber,
      record.previousHash,
      record.hash,
      record.timestamp instanceof Date ? record.timestamp.getTime() : Number(record.timestamp),
      record.action,
      record.tool,
      record.server,
      record.tier,
      record.status,
      canonicalStringify(record.input),
      canonicalStringify(record.output),
      record.persona,
      record.approvedBy ?? null,
      record.deniedBy ?? null,
      record.denyReason ?? null,
      record.durationMs,
      record.traceId ?? null,
      record.parentStepId ?? null,
      record.stepKind ?? null,
      record.confidence ?? null,
      record.retryCount ?? null,
      record.retryReasons ? JSON.stringify(record.retryReasons) : null,
      record.outcome ?? null,
      record.errorClass ?? null,
      record.failureMode ?? null,
    );
    return Promise.resolve();
  }

  query(filter: AuditFilter): Promise<ActionRecord[]> {
    const where: string[] = [];
    const params: Array<string | number> = [];
    if (filter.since) {
      const since = filter.since instanceof Date ? filter.since : new Date(filter.since);
      where.push(`timestamp >= ?`);
      params.push(since.getTime());
    }
    if (filter.until) {
      const until = filter.until instanceof Date ? filter.until : new Date(filter.until);
      where.push(`timestamp <= ?`);
      params.push(until.getTime());
    }
    if (filter.tier) {
      where.push(`tier = ?`);
      params.push(filter.tier);
    }
    if (filter.server) {
      where.push(`server = ?`);
      params.push(filter.server);
    }
    if (filter.tool) {
      where.push(`tool = ?`);
      params.push(filter.tool);
    }
    if (filter.persona) {
      where.push(`persona = ?`);
      params.push(filter.persona);
    }
    if (filter.approvedBy) {
      where.push(`approved_by = ?`);
      params.push(filter.approvedBy);
    }
    let sql = `SELECT id, sequence_number, previous_hash, hash, timestamp, action, tool,
                      server, tier, status, input, output, persona, approved_by, denied_by,
                      deny_reason, duration_ms, trace_id, parent_step_id, step_kind,
                      confidence, retry_count, retry_reasons, outcome, error_class, failure_mode
               FROM audit_records`;
    if (where.length > 0) sql += ` WHERE ` + where.join(' AND ');
    sql += ` ORDER BY sequence_number ASC`;
    if (typeof filter.limit === 'number' && filter.limit >= 0) {
      sql += ` LIMIT ?`;
      params.push(filter.limit);
    }
    if (typeof filter.offset === 'number' && filter.offset >= 0) {
      // SQLite requires LIMIT when OFFSET is used. If caller supplied
      // OFFSET without LIMIT, set LIMIT to -1 (no limit).
      if (!('limit' in filter) || filter.limit === undefined) {
        sql += ` LIMIT -1`;
      }
      sql += ` OFFSET ?`;
      params.push(filter.offset);
    }
    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as unknown as AuditRow[];
    return Promise.resolve(rows.map(rowToActionRecord));
  }

  verify(): Promise<{ valid: boolean; chainLength: number; brokenAt?: number }> {
    const rows = this.verifyStmt.all() as unknown as AuditRow[];
    const records = rows.map(rowToActionRecord);
    const result = HashChain.verifyChain(records);
    return Promise.resolve(result);
  }

  updateStatus(
    id: string,
    status: 'completed' | 'failed',
    output: Record<string, unknown>,
    durationMs: number,
    opts?: { failureMode?: FailureMode; retryCount?: number; retryReasons?: string[]; outcome?: CallOutcome; errorClass?: ErrorClass },
  ): Promise<void> {
 // round 6: empty completion outputs go through the
    // sentinel so the stored row's output column differs from the
    // pending placeholder's empty `{}`. durationMs is coerced to
    // >= 1 so the stored row's duration_ms column differs from the
    // pending placeholder's 0. Together, both fields are guaranteed
    // to mutate on every legitimate updateStatus() call, which the
    // trigger requires in the pending → terminal exemption. A
    // direct-SQL bypass attempting status + output without duration
    // (or status + duration without output) is blocked by the
    // trigger; only an attacker that forges the full legitimate
    // shape can succeed (a stronger threat requires a MAC/nonce
    // column — not in this round's scope).
    const coercedDurationMs = Math.max(1, Math.trunc(durationMs));
    this.updateStatusStmt.run(
      status,
      canonicalStringify(normalizeCompletionOutput(output)),
      coercedDurationMs,
      opts?.failureMode ?? null,
      opts?.retryCount ?? null,
      opts?.retryReasons ? JSON.stringify(opts.retryReasons) : null,
      opts?.outcome ?? null,
      opts?.errorClass ?? null,
      id,
    );
    return Promise.resolve();
  }

  /** Close the underlying connection. Tests + clean-shutdown only. */
  close(): void {
    this.db.close();
  }
}

/**
 * round 5 — empty-completion sentinel.
 *
 * The audit trigger's pending → terminal exemption requires `output`
 * to change between OLD and NEW. A legitimate `updateStatus()` whose
 * tool returned an empty object would store `output='{}'` over a
 * pending row whose `output` was also `'{}'` — same bytes, exemption
 * fails, trigger ABORTs.
 *
 * Workaround scoped to the SQLite adapter: when storing a completed
 * or failed record whose output is the empty object, replace it with
 * a sentinel object `{__epicai_sqlite_empty_completion: true}`. The
 * stored row's output then differs from the pending placeholder's
 * empty `{}`, satisfying the trigger exemption. The denormalize
 * function on the read path returns `{}` to consumers so the
 * ActionRecord shape is preserved across the SQLite round-trip.
 *
 * In-memory and JSONL adapters do NOT do this — the sentinel is
 * SQLite-specific because only the SQLite adapter is constrained by
 * the engine-level trigger.
 */
const EMPTY_COMPLETION_SENTINEL_KEY = '__epicai_sqlite_empty_completion';

function normalizeCompletionOutput(output: Record<string, unknown>): Record<string, unknown> {
  return Object.keys(output).length === 0
    ? { [EMPTY_COMPLETION_SENTINEL_KEY]: true }
    : output;
}

function denormalizeCompletionOutput(output: Record<string, unknown>): Record<string, unknown> {
  if (
    output[EMPTY_COMPLETION_SENTINEL_KEY] === true &&
    Object.keys(output).length === 1
  ) {
    return {};
  }
  return output;
}

function rowToActionRecord(row: AuditRow): ActionRecord {
  return {
    id: row.id,
    sequenceNumber: row.sequence_number,
    previousHash: row.previous_hash,
    hash: row.hash,
    timestamp: new Date(row.timestamp),
    action: row.action,
    tool: row.tool,
    server: row.server,
    tier: row.tier,
    status: row.status,
    input: safeParseObject(row.input),
    output: denormalizeCompletionOutput(safeParseObject(row.output)),
    persona: row.persona,
    durationMs: row.duration_ms,
    ...(row.approved_by !== null ? { approvedBy: row.approved_by } : {}),
    ...(row.denied_by !== null ? { deniedBy: row.denied_by } : {}),
    ...(row.deny_reason !== null ? { denyReason: row.deny_reason } : {}),
    ...(row.trace_id !== null ? { traceId: row.trace_id } : {}),
    ...(row.parent_step_id !== null ? { parentStepId: row.parent_step_id } : {}),
    ...(row.step_kind !== null ? { stepKind: row.step_kind as StepKind } : {}),
    ...(row.confidence !== null ? { confidence: row.confidence } : {}),
    ...(row.retry_count !== null ? { retryCount: row.retry_count } : {}),
    ...(row.retry_reasons !== null ? { retryReasons: safeParseArray(row.retry_reasons) } : {}),
    ...(row.outcome !== null ? { outcome: row.outcome as CallOutcome } : {}),
    ...(row.error_class !== null ? { errorClass: row.error_class as ErrorClass } : {}),
    ...(row.failure_mode !== null ? { failureMode: row.failure_mode as FailureMode } : {}),
  };
}

function safeParseObject(s: string): Record<string, unknown> {
  try {
    const v = JSON.parse(s) as unknown;
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function safeParseArray(s: string): string[] {
  try {
    const v = JSON.parse(s) as unknown;
    return Array.isArray(v) ? (v as string[]) : [];
  } catch {
    return [];
  }
}


