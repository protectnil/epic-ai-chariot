/**
 * @epicai/chariot — SQLite-backed ApprovalRegistry
 *
 * Durable subclass of ApprovalRegistry that persists approval keys to
 * `node:sqlite`. Survives chariot process restart — addresses the
 * in-memory limitation where pending approvals vanished on
 * restart. README's "Three-tier autonomy governance (auto/escalate/
 * approve)" claim becomes truthful end-to-end with this backend.
 *
 * Per spec sqlite-durable-backend-2026-05.md §3. Default in production;
 * the original in-memory ApprovalRegistry remains for tests and the
 * Mongo binding remains as an opt-in for multi-host deployments.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { DatabaseSync, type StatementSync } from 'node:sqlite';
import { ApprovalRegistry } from './FederationManager.js';

export class SqliteApprovalRegistry extends ApprovalRegistry {
  private readonly db: DatabaseSync;
  private readonly hasStmt: StatementSync;
  private readonly addStmt: StatementSync;
  private readonly removeStmt: StatementSync;
  private readonly keysStmt: StatementSync;

  /**
   * Open the SQLite database at `dbPath`, bootstrap the `approvals`
   * table + index, prepare statements. Schema-version compatible with
   * SqliteCheckpointStore + SqliteAuditAdapter sharing the same file.
   */
  constructor(dbPath: string, deps?: { Database?: typeof DatabaseSync }) {
    super();
    const Database = deps?.Database ?? DatabaseSync;
    this.db = new Database(dbPath);
    // Constructor try/catch: close the handle if schema setup or
    // statement preparation throws, so a partially-initialized
    // instance does not leak the database file lock.
    try {
      this.db.exec(`PRAGMA journal_mode=WAL`);
      this.db.exec(`PRAGMA foreign_keys=ON`);
      // Multi-process deployments: wait up to 5s for the writer lock instead
      // of failing immediately with SQLITE_BUSY.
      this.db.exec(`PRAGMA busy_timeout=5000`);
      // Schema co-resident with checkpoints + audit_records in the same
      // chariot.db. Minimal v1 columns: just the approval key (composite
      // tenantId:server:tool:argsHash string already encodes everything
      // FederationManager.callTool's gate needs to look up). A future
      // enhancement can break out the column structure for richer
      // per-tenant listing UIs.
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS approvals (
          approval_key TEXT PRIMARY KEY,
          approved_at INTEGER NOT NULL
        );
      `);
      this.hasStmt = this.db.prepare(`SELECT 1 FROM approvals WHERE approval_key = ? LIMIT 1`);
      // INSERT OR REPLACE: re-approving an existing key refreshes its
      // approved_at timestamp. Intentional — supports approval refresh
      // semantics without a separate API call.
      this.addStmt = this.db.prepare(`INSERT OR REPLACE INTO approvals (approval_key, approved_at) VALUES (?, ?)`);
      this.removeStmt = this.db.prepare(`DELETE FROM approvals WHERE approval_key = ?`);
      this.keysStmt = this.db.prepare(`SELECT approval_key FROM approvals ORDER BY approved_at ASC`);
    } catch (err) {
      this.db.close();
      throw err;
    }
  }

  override has(key: string): boolean {
    const row = this.hasStmt.get(key);
    return row !== undefined && row !== null;
  }

  override approve(key: string): void {
    this.addStmt.run(key, Date.now());
  }

  override revoke(key: string): void {
    this.removeStmt.run(key);
  }

  override keys(): string[] {
    const rows = this.keysStmt.all() as unknown as Array<{ approval_key: string }>;
    return rows.map((r) => r.approval_key);
  }

  /** Close the underlying connection. Tests + clean-shutdown only. */
  close(): void {
    this.db.close();
  }
}

