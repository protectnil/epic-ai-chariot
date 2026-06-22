/**
 * @epicai/chariot — SQLite-backed CheckpointStore
 *
 * Durable store for orchestrator step checkpoints. Survives process
 * restart so a chariot crash mid-run can be inspected (and ultimately
 * resumed) via `chariot resume <traceId>`.
 *
 * Storage: `node:sqlite` built-in (DatabaseSync). Zero npm dependency,
 * zero native binary compile, available on Node 22+ (chariot ships
 * `engines.node >= 22.13.0` for stable node:sqlite support). One single
 * shared DB file (default `~/.epic-ai/chariot.db`) used by all three
 * SQLite-backed adapters (approval registry, checkpoint store, audit).
 *
 * Tenant scoping: every row carries `tenant_id`. list/latest/clear filter
 * by tenant_id; cross-tenant reads return empty results even when
 * trace_id collides.
 *
 * Encryption-at-rest: input and output payloads are encrypted with the
 * Rust binding's AES-256-GCM + HKDF-SHA256 per-tenant key derivation
 * (the same primitive the credential vault uses, src/iam/crypto.ts).
 * ENTERPRISE_MASTER_KEY must be configured; the binding load failure
 * surfaces a clear error at construction time.
 *
 * Per spec sqlite-durable-backend-2026-05.md §3. Default in production
 * for `npx @epicai/chariot serve`; in-memory store retained for tests
 * and Mongo store retained for multi-host deployments.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { DatabaseSync, type StatementSync } from 'node:sqlite';
import type { Checkpoint, CheckpointStore } from './CheckpointStore.js';
import { canonicalStringify } from '../../util/canonical-json.js';
import { loadNativeBinding } from '../../license/binding.js';

interface CheckpointRow {
  step_id: string;
  parent_step_id: string | null;
  tenant_id: string;
  trace_id: string;
  iteration: number;
  tool_name: string | null;
  server_name: string | null;
  input_ct: string;
  input_iv: string;
  output_ct: string;
  output_iv: string;
  timestamp: number;
}

function getMasterKeyB64(): string {
  const raw = process.env.ENTERPRISE_MASTER_KEY;
  if (!raw || raw.trim() === '' || raw === 'change-me' || raw === 'changeme') {
    throw new Error(
      'ENTERPRISE_MASTER_KEY is not set or is an insecure default. ' +
      'SqliteCheckpointStore requires a master key for at-rest encryption.'
    );
  }
  const decoded = Buffer.from(raw, 'base64');
  // AES-256 takes a 32-byte key; refuse anything that is not
  // exactly 32 bytes so a mis-generated key surfaces at construction
  // time rather than after rows have been written under the wrong
  // material.
  if (decoded.length !== 32) {
    throw new Error(
      `ENTERPRISE_MASTER_KEY must decode to exactly 32 bytes (got ${decoded.length}).`
    );
  }
  return raw;
}

type CryptoBinding = {
  encryptCredential(plaintext: string, tenantId: string, masterKeyB64: string): { encrypted: string; iv: string };
  decryptCredential(encryptedB64: string, ivB64: string, tenantId: string, masterKeyB64: string): string;
};

function resolveBinding(injected?: CryptoBinding): CryptoBinding {
  if (injected) return injected;
  const binding = loadNativeBinding();
  if (!binding) {
    throw new Error(
      'SqliteCheckpointStore requires the Chariot native binary for at-rest encryption. ' +
      'Install the platform sibling package (@epicai/chariot-<platform>) or inject a binding.'
    );
  }
  return binding;
}

export class SqliteCheckpointStore implements CheckpointStore {
  private readonly db: DatabaseSync;
  private readonly recordStmt: StatementSync;
  private readonly listStmt: StatementSync;
  private readonly latestStmt: StatementSync;
  private readonly clearStmt: StatementSync;
  private readonly binding: CryptoBinding;

  /**
   * Open or create the SQLite database at `dbPath` and bootstrap the
   * `checkpoints` table + index. Idempotent — re-running against an
   * existing database is safe; legacy rows without `tenant_id` are
   * backfilled with the default tenant 'local' via ALTER TABLE.
   *
   * The database connection is owned by this instance. Multiple
   * adapter instances against the same `dbPath` are supported via
   * journal_mode=WAL (one writer, many readers).
   */
  constructor(dbPath: string, deps?: { Database?: typeof DatabaseSync; binding?: CryptoBinding }) {
    const Database = deps?.Database ?? DatabaseSync;
    this.binding = resolveBinding(deps?.binding);
    this.db = new Database(dbPath);
    // Close the handle if schema setup or statement preparation
    // throws — prevents leaking the database lock on construction
    // failure.
    try {
      this.db.exec(`PRAGMA journal_mode=WAL`);
      this.db.exec(`PRAGMA foreign_keys=ON`);
      // Multi-process deployments: wait up to 5s for the writer lock instead of
      // failing immediately with SQLITE_BUSY.
      this.db.exec(`PRAGMA busy_timeout=5000`);
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS checkpoints (
          step_id TEXT PRIMARY KEY,
          parent_step_id TEXT,
          tenant_id TEXT NOT NULL DEFAULT 'local',
          trace_id TEXT NOT NULL,
          iteration INTEGER NOT NULL,
          tool_name TEXT,
          server_name TEXT,
          input_ct TEXT NOT NULL,
          input_iv TEXT NOT NULL,
          output_ct TEXT NOT NULL,
          output_iv TEXT NOT NULL,
          timestamp INTEGER NOT NULL
        );
      `);
      // Migrate legacy schemas that pre-date tenant scoping and
      // at-rest encryption. ALTER TABLE is no-op if the column
      // already exists (we catch + ignore the duplicate-column error).
      this.migrateAddColumn('tenant_id', `TEXT NOT NULL DEFAULT 'local'`);
      this.migrateAddColumn('input_ct', `TEXT NOT NULL DEFAULT ''`);
      this.migrateAddColumn('input_iv', `TEXT NOT NULL DEFAULT ''`);
      this.migrateAddColumn('output_ct', `TEXT NOT NULL DEFAULT ''`);
      this.migrateAddColumn('output_iv', `TEXT NOT NULL DEFAULT ''`);
      this.db.exec(
        `CREATE INDEX IF NOT EXISTS checkpoints_by_tenant_trace ON checkpoints(tenant_id, trace_id, iteration);`,
      );
      // Append-only by step_id. A duplicate step_id raises SQLITE_CONSTRAINT,
      // which the caller surfaces as `checkpoint.record_failed`. Previous
      // INSERT OR REPLACE silently overwrote the original recovery artifact.
      this.recordStmt = this.db.prepare(
        `INSERT INTO checkpoints
         (step_id, parent_step_id, tenant_id, trace_id, iteration, tool_name, server_name, input_ct, input_iv, output_ct, output_iv, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      this.listStmt = this.db.prepare(
        `SELECT step_id, parent_step_id, tenant_id, trace_id, iteration, tool_name, server_name, input_ct, input_iv, output_ct, output_iv, timestamp
         FROM checkpoints WHERE tenant_id = ? AND trace_id = ? ORDER BY iteration ASC, timestamp ASC`,
      );
      this.latestStmt = this.db.prepare(
        `SELECT step_id, parent_step_id, tenant_id, trace_id, iteration, tool_name, server_name, input_ct, input_iv, output_ct, output_iv, timestamp
         FROM checkpoints WHERE tenant_id = ? AND trace_id = ? ORDER BY iteration DESC, timestamp DESC LIMIT 1`,
      );
      this.clearStmt = this.db.prepare(`DELETE FROM checkpoints WHERE tenant_id = ? AND trace_id = ?`);
    } catch (err) {
      this.db.close();
      throw err;
    }
  }

  private migrateAddColumn(column: string, decl: string): void {
    try {
      this.db.exec(`ALTER TABLE checkpoints ADD COLUMN ${column} ${decl};`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!/duplicate column name/i.test(msg)) throw err;
    }
  }

  async record(c: Checkpoint): Promise<void> {
    const masterKey = getMasterKeyB64();
    const inEnc = this.binding.encryptCredential(canonicalStringify(c.input), c.tenantId, masterKey);
    const outEnc = this.binding.encryptCredential(canonicalStringify(c.output), c.tenantId, masterKey);
    this.recordStmt.run(
      c.stepId,
      c.parentStepId ?? null,
      c.tenantId,
      c.traceId,
      c.iteration,
      c.toolName ?? null,
      c.serverName ?? null,
      inEnc.encrypted,
      inEnc.iv,
      outEnc.encrypted,
      outEnc.iv,
      c.timestamp instanceof Date ? c.timestamp.getTime() : Number(c.timestamp),
    );
  }

  async list(tenantId: string, traceId: string): Promise<Checkpoint[]> {
    const rows = this.listStmt.all(tenantId, traceId) as unknown as CheckpointRow[];
    return rows.map((r) => this.rowToCheckpoint(r));
  }

  async latest(tenantId: string, traceId: string): Promise<Checkpoint | undefined> {
    const row = this.latestStmt.get(tenantId, traceId) as unknown as CheckpointRow | undefined;
    return row ? this.rowToCheckpoint(row) : undefined;
  }

  async clear(tenantId: string, traceId: string): Promise<void> {
    this.clearStmt.run(tenantId, traceId);
  }

  /** Close the underlying database connection. Tests + clean-shutdown only. */
  close(): void {
    this.db.close();
  }

  private rowToCheckpoint(row: CheckpointRow): Checkpoint {
    const masterKey = getMasterKeyB64();
    return {
      tenantId: row.tenant_id,
      stepId: row.step_id,
      parentStepId: row.parent_step_id,
      traceId: row.trace_id,
      iteration: row.iteration,
      toolName: row.tool_name ?? undefined,
      serverName: row.server_name ?? undefined,
      input: safeParse(this.binding.decryptCredential(row.input_ct, row.input_iv, row.tenant_id, masterKey)),
      output: safeParse(this.binding.decryptCredential(row.output_ct, row.output_iv, row.tenant_id, masterKey)),
      timestamp: new Date(row.timestamp),
    };
  }
}

function safeParse(s: string): Record<string, unknown> {
  try {
    const v = JSON.parse(s) as unknown;
    return v !== null && typeof v === 'object' ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
