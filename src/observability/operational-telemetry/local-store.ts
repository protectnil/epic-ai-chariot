/**
 * Operational-telemetry LOCAL store (C4AMD §8, "Local store" amendment
 * 2026-10-12): consent versions and captured events kept as append-only
 * JSONL files under the Epic AI state directory, so a workstation or edge
 * install can opt in without MongoDB. Used when no enterprise MongoDB
 * client has been injected (see `src/iam/db.ts` `hasMongoClient`).
 *
 * Layout (per tenant):  <EPIC_AI_DIR>/state/telemetry/<tenant-dir>/
 *   consent.jsonl      one JSON object per line, append-only, `version`
 *                      is 1,2,3… (the line ordinal) — versioned, auditable,
 *                      revocable by appending `enabled:false` (C4AMD §8::6)
 *   events.jsonl       one redacted nine-field event per line, append-only
 *   upload-state.json  the automatic-upload cursor + last attempt (atomic
 *                      tmp+rename); never holds event content
 *
 * NO NETWORK I/O: this file imports only node:fs/os/path/crypto
 * (`egress-guard.test.ts` grep-guards the directory).
 */

import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import type { OperationalTelemetryEvent } from './redact.js';

export type TelemetryTransport = 'export-only' | 'auto';

export interface LocalConsentRecord {
  /** 1,2,3… — the ordinal of the appended line. 0 is never written. */
  version: number;
  enabled: boolean;
  transport: TelemetryTransport;
  changedAt: string;
  changedBy: string;
  /** The operator's own words recorded with an enable, when supplied. */
  statement: string | null;
}

export interface LocalUploadState {
  /** Opaque store cursor: a line count for the local store, an ObjectId hex for MongoDB. */
  cursor: string | null;
  lastAttemptAt: string | null;
  lastResult: string | null;
  /** Identity (the starting cursor) of the batch the attempt budget below belongs to; null when none is in flight. */
  batchKey: string | null;
  /** Transmission attempts already spent on that batch — the persisted "at most three per batch" budget. */
  batchAttempts: number;
}

function rootDir(): string {
  return join(process.env.EPIC_AI_DIR_OVERRIDE ?? join(homedir(), '.epic-ai'), 'state', 'telemetry');
}

/** Per-tenant directory name: sanitized prefix + hash, so distinct tenants never collide. */
export function telemetryTenantDir(tenantId: string): string {
  const safe = tenantId.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 48) || 'tenant';
  const h = createHash('sha256').update(tenantId).digest('hex').slice(0, 12);
  return join(rootDir(), `${safe}-${h}`);
}

function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function withLock<T>(dir: string, fn: () => T): T {
  ensureDir(dir);
  const lockPath = join(dir, '.lock');
  const deadline = Date.now() + 2000;
  for (;;) {
    try {
      closeSync(openSync(lockPath, 'wx', 0o600));
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > 10_000) {
          unlinkSync(lockPath);
          continue;
        }
      } catch {
        continue; // lock vanished between the EEXIST and the stat — retry
      }
      if (Date.now() > deadline) throw new Error('telemetry local store: lock timeout');
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  try {
    return fn();
  } finally {
    try { unlinkSync(lockPath); } catch { /* already gone */ }
  }
}

function readJsonLines<T>(file: string): T[] {
  if (!existsSync(file)) return [];
  const out: T[] = [];
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (line.length === 0) continue;
    try {
      out.push(JSON.parse(line) as T);
    } catch {
      // A torn/corrupt line is skipped, never fatal; consent reads fail closed
      // because a skipped consent line can only make the log look older.
    }
  }
  return out;
}

function isConsentRecord(v: unknown): v is LocalConsentRecord {
  if (v === null || typeof v !== 'object') return false;
  const r = v as Record<string, unknown>;
  return (
    typeof r['version'] === 'number' && Number.isInteger(r['version']) && r['version'] >= 1 &&
    typeof r['enabled'] === 'boolean' &&
    (r['transport'] === 'export-only' || r['transport'] === 'auto') &&
    typeof r['changedAt'] === 'string' &&
    typeof r['changedBy'] === 'string'
  );
}

/** Every well-formed consent version, oldest first, plus whether any non-empty line failed to parse or validate. */
function readConsentFile(tenantId: string): { records: LocalConsentRecord[]; corrupt: boolean } {
  const file = join(telemetryTenantDir(tenantId), 'consent.jsonl');
  if (!existsSync(file)) return { records: [], corrupt: false };
  const records: LocalConsentRecord[] = [];
  let corrupt = false;
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (line.length === 0) continue;
    try {
      const v: unknown = JSON.parse(line);
      if (isConsentRecord(v)) records.push({ ...v, statement: typeof v.statement === 'string' ? v.statement : null });
      else corrupt = true;
    } catch {
      corrupt = true;
    }
  }
  return { records, corrupt };
}

export function localConsentHistory(tenantId: string): LocalConsentRecord[] {
  return readConsentFile(tenantId).records;
}

/** True when the consent log has an unreadable or malformed line (integrity cannot be established). */
export function localConsentCorrupt(tenantId: string): boolean {
  return readConsentFile(tenantId).corrupt;
}

/**
 * Latest consent record, or null when the tenant has never recorded one
 * (off by default, §8::2). If ANY line of the log is unreadable, consent
 * FAILS CLOSED: a synthetic `enabled:false` record is returned, because
 * skipping a damaged newest line would otherwise resurrect an older
 * `enabled:true` and silently undo a revocation (§8::6).
 */
export function localCurrentConsent(tenantId: string): LocalConsentRecord | null {
  const { records, corrupt } = readConsentFile(tenantId);
  if (corrupt) {
    const last = records.length === 0 ? 0 : records[records.length - 1].version;
    return {
      version: last,
      enabled: false,
      transport: 'export-only',
      changedAt: new Date(0).toISOString(),
      changedBy: 'integrity-check',
      statement: null,
    };
  }
  return records.length === 0 ? null : records[records.length - 1];
}

/** Append one consent version. Never rewrites or deletes a prior line. */
export function localAppendConsent(
  tenantId: string,
  rec: { enabled: boolean; transport: TelemetryTransport; changedBy: string; statement: string | null; now?: Date },
): LocalConsentRecord {
  const dir = telemetryTenantDir(tenantId);
  return withLock(dir, () => {
    const file = join(dir, 'consent.jsonl');
    const hist = readConsentFile(tenantId).records;
    const last = hist.length === 0 ? 0 : hist[hist.length - 1].version;
    const next: LocalConsentRecord = {
      version: last + 1,
      enabled: rec.enabled,
      transport: rec.enabled ? rec.transport : 'export-only',
      changedAt: (rec.now ?? new Date()).toISOString(),
      changedBy: rec.changedBy,
      statement: rec.statement,
    };
    appendFileSync(file, JSON.stringify(next) + '\n', { encoding: 'utf8', mode: 0o600 });
    return next;
  });
}

export function localAppendEvent(event: OperationalTelemetryEvent): void {
  const dir = telemetryTenantDir(event.tenantId);
  ensureDir(dir);
  appendFileSync(join(dir, 'events.jsonl'), JSON.stringify(event) + '\n', { encoding: 'utf8', mode: 0o600 });
}

export function localReadEvents(tenantId: string, opts: { sinceHourBucket?: string } = {}): OperationalTelemetryEvent[] {
  const all = readJsonLines<OperationalTelemetryEvent>(join(telemetryTenantDir(tenantId), 'events.jsonl'));
  return opts.sinceHourBucket ? all.filter((e) => e.hourBucket >= (opts.sinceHourBucket as string)) : all;
}

/** Events from line index `from` (0-based), at most `limit`; `next` is the index to resume from. */
export function localReadEventsFrom(
  tenantId: string,
  from: number,
  limit: number,
): { events: OperationalTelemetryEvent[]; next: number; total: number } {
  const all = readJsonLines<OperationalTelemetryEvent>(join(telemetryTenantDir(tenantId), 'events.jsonl'));
  const start = Math.max(0, Math.min(from, all.length));
  const events = all.slice(start, start + limit);
  return { events, next: start + events.length, total: all.length };
}

export function readUploadState(tenantId: string): LocalUploadState {
  const file = join(telemetryTenantDir(tenantId), 'upload-state.json');
  try {
    const p = JSON.parse(readFileSync(file, 'utf8')) as Partial<LocalUploadState>;
    return {
      cursor: typeof p.cursor === 'string' ? p.cursor : null,
      lastAttemptAt: typeof p.lastAttemptAt === 'string' ? p.lastAttemptAt : null,
      lastResult: typeof p.lastResult === 'string' ? p.lastResult : null,
      batchKey: typeof p.batchKey === 'string' ? p.batchKey : null,
      batchAttempts: typeof p.batchAttempts === 'number' && Number.isInteger(p.batchAttempts) && p.batchAttempts >= 0 ? p.batchAttempts : 0,
    };
  } catch {
    return { cursor: null, lastAttemptAt: null, lastResult: null, batchKey: null, batchAttempts: 0 };
  }
}

export function writeUploadState(tenantId: string, state: LocalUploadState): void {
  const dir = telemetryTenantDir(tenantId);
  ensureDir(dir);
  const file = join(dir, 'upload-state.json');
  const tmp = `${file}.${process.pid}-${Date.now()}.tmp`;
  writeFileSync(tmp, JSON.stringify(state), { encoding: 'utf8', mode: 0o600 });
  renameSync(tmp, file);
}

export type AttemptReservation =
  | { ok: true; attempts: number }
  | { ok: false; reason: 'exhausted' | 'moved' };

/**
 * Atomically reserve ONE transmission attempt from a batch's persisted
 * budget (C4AMD §8: "at most three attempts per batch"). The read of the
 * upload state, the budget test and the write of the incremented count all
 * happen under the tenant's lock file, so concurrent processes sharing a
 * tenant store can never spend more than `max` attempts between them.
 *
 *   `moved`     the cursor is no longer `expectedCursor`: another process
 *               already sent or dropped this batch — nothing to do.
 *   `exhausted` the batch has already used `max` attempts.
 */
export function reserveUploadAttempt(
  tenantId: string,
  expectedCursor: string | null,
  max: number,
  atIso: string,
): AttemptReservation {
  return withLock(telemetryTenantDir(tenantId), () => {
    const cur = readUploadState(tenantId);
    if (cur.cursor !== expectedCursor) return { ok: false, reason: 'moved' };
    const key = expectedCursor ?? '';
    const used = cur.batchKey === key ? cur.batchAttempts : 0;
    if (used >= max) return { ok: false, reason: 'exhausted' };
    writeUploadState(tenantId, { ...cur, batchKey: key, batchAttempts: used + 1, lastAttemptAt: atIso, lastResult: 'attempting' });
    return { ok: true, attempts: used + 1 };
  });
}

/**
 * Move the cursor past a batch — but only if the cursor is still where this
 * caller started. Done under the same lock as `reserveUploadAttempt`, so a
 * slow process finishing late can never rewind the cursor or reset the
 * reserved attempt count of the NEXT batch another process already started.
 * Returns whether the cursor was advanced.
 */
export function advanceUploadCursor(
  tenantId: string,
  expectedCursor: string | null,
  nextCursor: string,
  result: string,
  atIso: string,
): boolean {
  return withLock(telemetryTenantDir(tenantId), () => {
    const cur = readUploadState(tenantId);
    if (cur.cursor !== expectedCursor) return false;
    writeUploadState(tenantId, { cursor: nextCursor, batchKey: null, batchAttempts: 0, lastAttemptAt: atIso, lastResult: result });
    return true;
  });
}

/** Record an outcome string without touching the cursor or the reserved attempt count (locked read-modify-write). */
export function noteUploadResult(tenantId: string, result: string, atIso: string): void {
  withLock(telemetryTenantDir(tenantId), () => {
    const cur = readUploadState(tenantId);
    writeUploadState(tenantId, { ...cur, lastAttemptAt: atIso, lastResult: result });
  });
}
