/**
 * @epicai/chariot — CLI Adapter Approval Helper (AS §1.5)
 *
 * Pure functions backing the operator-driven first-use approval gate
 * for CLI-bridge adapters. Per the Adapter Standard §1.5:
 *
 *   - The dispatcher MUST refuse a CLI tool call until the operator
 *     has interactively approved that adapter via `chariot approve <id>`.
 *   - Approval is recorded as an ISO-8601 timestamp on
 *     `AdapterState.adapters[id].approvedAt`, paired with a SHA-256 hex
 *     hash of the binary + argv template the operator saw — so a
 *     post-approval swap of either is detected and refused.
 *   - Absent / null `approvedAt` means unapproved.
 *   - No AI-proxied approval — the `chariot approve` command MUST
 *     require an interactive human operator and MUST NOT accept any
 *     `--yes` / env-var bypass.
 *
 * Architectural note: AdapterState is per-OS-user (~/.epic-ai/adapter-
 * state.json). In a shared deployment where multiple human operators
 * share a single chariot process user, one operator's approval covers
 * all operators on that user. A per-tenant approval store is a future
 * extension that requires explicit product-spec authorisation; the
 * current AS §1.5 contract is satisfied by per-process-user state.
 *
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { appendFileSync, chmodSync, closeSync, existsSync, fstatSync, openSync, readFileSync, readSync, statSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { loadState, saveState } from './state.js';
import { APPROVAL_AUDIT_FILE, EPIC_AI_DIR, ensureDir } from './paths.js';
import { canonicalStringify } from '../util/canonical-json.js';
import { GENESIS_HASH } from '../util/audit-chain.js';
import type { AdapterState } from './types.js';

/**
 * Canonical hash over the operator-visible CLI shape — covers EVERY
 * input that contributes to the executed argv at dispatch time:
 *   - binary path
 *   - base args (cli.args)
 *   - every tool schema's name + subcommand + flags + positional
 *
 * Per AS §1.5, the operator approves the binary + argv template they
 * see displayed. The dispatcher builds the actual argv from base args
 * PLUS the selected tool schema's subcommand/flags/positional, so the
 * approval guarantee must cover all of them. A post-approval mutation
 * of any contributing field flips the hash and forces re-approval.
 *
 * Exported so the dispatcher gate can recompute on every call.
 */
export interface AdapterShapeInput {
  binary: string;
  args?: readonly unknown[];
  toolSchemas?: ReadonlyArray<{
    name: string;
    subcommand?: string;
    flags?: Record<string, string>;
    positional?: readonly string[];
  }>;
}

export function computeAdapterShapeHash(shape: AdapterShapeInput): string;
// Backward-compat overload — older callers pass (binary, args).
export function computeAdapterShapeHash(binary: string, args?: readonly unknown[]): string;
export function computeAdapterShapeHash(
  shapeOrBinary: AdapterShapeInput | string,
  args?: readonly unknown[],
): string {
  const shape: AdapterShapeInput = typeof shapeOrBinary === 'string'
    ? { binary: shapeOrBinary, args }
    : shapeOrBinary;
  // Q-2.4: reject non-string args members at hash time so a malformed
  // catalog entry can't produce a hash that collides between different
  // semantic shapes (e.g. args:[null] vs args:[undefined] both serialise
  // to `[null]` under the prior JSON.stringify-mapping). The dispatcher's
  // argv spawn requires strings — non-strings here are a contract
  // violation that would fail at spawn time anyway; rejecting at hash
  // time surfaces the issue at approval/dispatch instead of silently
  // producing a colliding fingerprint.
  if (Array.isArray(shape.args)) {
    for (const a of shape.args) {
      if (typeof a !== 'string') {
        throw new TypeError(`computeAdapterShapeHash: args member must be string, got ${typeof a}`);
      }
    }
  }
  // canonicalStringify performs deep, locale-independent key sorting
  // at every nesting level. Array order is preserved by definition, so
  // toolSchemas[] is still sorted by name here to make the hash
  // independent of catalog ordering (the canonical sort applies to
  // object keys, not array elements).
  const canonical = canonicalStringify({
    binary: shape.binary,
    args: Array.isArray(shape.args) ? [...shape.args] : [],
    tools: Array.isArray(shape.toolSchemas)
      ? [...shape.toolSchemas]
          .sort((a, b) => a.name.localeCompare(b.name))
          .map((s) => ({
            name: s.name,
            subcommand: typeof s.subcommand === 'string' ? s.subcommand : null,
            flags: s.flags && typeof s.flags === 'object' ? { ...s.flags } : null,
            positional: Array.isArray(s.positional) ? [...s.positional] : null,
          }))
      : [],
  });
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Render the full operator-facing argv template for one tool. Matches
 * the dispatcher's spawn semantics at toolHandlers.ts CLI-bridge branch:
 *
 *   - cli.args spread first
 *   - schema.subcommand
 *   - schema.positional[]  → <paramName>
 *   - schema.flags[paramName] = flagString  → flagString <paramName>
 *
 * Used by both `chariot approve` display and the dispatcher's structured
 * log line per AS §1.5. The flag rendering mirrors the dispatcher's
 * `for (const [param, flag] of Object.entries(schema.flags))` /
 * `argv.push(flag, String(v))` shape — operator approval display must
 * match what the dispatcher will actually spawn.
 */
export function renderToolArgv(
  baseArgs: readonly unknown[] | undefined,
  schema: { subcommand?: string; flags?: Record<string, string>; positional?: readonly string[] } | undefined,
): string[] {
  const out: string[] = [];
  if (Array.isArray(baseArgs)) {
    for (const a of baseArgs) out.push(typeof a === 'string' ? a : JSON.stringify(a));
  }
  if (schema) {
    if (typeof schema.subcommand === 'string' && schema.subcommand) out.push(schema.subcommand);
    if (Array.isArray(schema.positional)) {
      for (const p of schema.positional) out.push(`<${escapeDisplayPlaceholder(p)}>`);
    }
    if (schema.flags && typeof schema.flags === 'object') {
      for (const [param, flag] of Object.entries(schema.flags)) {
        out.push(flag, `<${escapeDisplayPlaceholder(param)}>`);
      }
    }
  }
  return out;
}

// R11-1: shared control-character stripper used by both
// escapeDisplayPlaceholder and sanitizeDisplayString. Centralising the
// regex prevents silent drift if the stripped range is ever widened
// (e.g. to include C1 controls \x80-\x9f). A one-sided edit elsewhere
// would otherwise leave the other call site lagging.
function stripControlChars(s: string): string {
  return s.replace(/[\x00-\x1f\x7f]/g, '');
}

// L-3.5: a param name like `evil<` would render as `<evil<>` and look
// ambiguous in display + log surfaces. Strip the three chars that have
// meaning in our `<placeholder>` notation. The dispatcher never sees
// this string (it builds the real argv from the live catalog), so this
// is a display-safety guard only — no shell-escaping semantics.
//
// Q-4.4: also strip C0 control characters (\x00-\x1f) and DEL (\x7f).
// A schema with `positional: ['evil\x1b[31m']` would otherwise inject
// ANSI escape sequences into the operator's terminal during
// `chariot approve` and could be abused to mis-paint the approval
// display (hide chars, fake cursor motion).
function escapeDisplayPlaceholder(s: string): string {
  return stripControlChars(s).replace(/[<>"]/g, '');
}

/**
 * Strip C0 control characters (\x00-\x1f) and DEL (\x7f) from a string
 * before printing it to the operator terminal in the `chariot approve`
 * display. Used for `cli.binary` and each `cli.args` element so a
 * malicious catalog can't inject ANSI escape sequences, fake cursor
 * motion, or hidden bytes into the human-approval surface.
 *
 * Unlike escapeDisplayPlaceholder, this helper does NOT strip `<>"` —
 * those characters are legitimate in real binary paths and argv strings.
 * The dispatcher builds the actual argv from the live catalog and never
 * uses this string, so there's no shell-escaping semantic.
 *
 * review-flagged: a raw `defaultArgs.join(' ')` in
 * src/bin/chariot.ts cmdApprove allowed base-args spoofing even though
 * the tool-schema placeholders were sanitised. This helper closes that
 * gap.
 */
export function sanitizeDisplayString(s: unknown): string {
  const str = typeof s === 'string' ? s : (s == null ? '' : String(s));
  return stripControlChars(str);
}

function isApprovedEntry(entry: { approvedAt?: string | null } | undefined): boolean {
  return typeof entry?.approvedAt === 'string' && entry.approvedAt.length > 0;
}

/**
 * Read the approval state for an adapter. Returns the timestamp + the
 * shape-hash that was approved, or null when absent. Fail-closed on
 * any parse / IO error.
 */
export function readAdapterApproval(adapterId: string): { approvedAt: string; approvedShapeHash: string | null } | null {
  try {
    const state = loadState();
    const entry = state.adapters?.[adapterId];
    if (!isApprovedEntry(entry)) return null;
    return {
      approvedAt: entry!.approvedAt as string,
      approvedShapeHash: typeof entry!.approvedShapeHash === 'string' ? entry!.approvedShapeHash : null,
    };
  } catch {
    return null;
  }
}

/**
 * Backward-compat thin wrapper used by callers that only need the
 * timestamp (e.g. existing CLI listing). New callers should use
 * `readAdapterApproval` and check the shape-hash too.
 */
export function readAdapterApprovedAt(adapterId: string): string | null {
  const r = readAdapterApproval(adapterId);
  return r ? r.approvedAt : null;
}

/**
 * Record interactive operator approval for an adapter — 2PC protocol
 * (review-prescribed 2026-05-25).
 *
 * Crash-safe across audit + state by treating the audit chain as the
 * transaction journal:
 *
 *   1. Generate tx_id.
 *   2. Append `cli_approval_intent` row (tx_id, shapeHash).
 *      → If THIS throws, nothing changed; intent never landed.
 *   3. Save pending state (approvalTx set, approvedAt=null,
 *      approvedShapeHash=null).
 *      → If THIS throws, intent is on disk but state didn't change.
 *        Reconcile on next load: pending entries with no terminator
 *        clear approvalTx (treat as failed).
 *   4. Append `cli_approval_committed` row (same tx_id).
 *      → If THIS throws, append `cli_approval_failed` (best-effort),
 *        rethrow. Reconcile: pending + failed terminator → clear
 *        approvalTx; pending + no terminator → clear approvalTx.
 *      → If `cli_approval_failed` ALSO throws (rare double-IO failure),
 *        we just rethrow the original. Reconcile: pending + no
 *        terminator → clear approvalTx.
 *   5. Save committed state (approvedAt + approvedShapeHash set,
 *      approvalTx cleared).
 *      → If THIS throws, audit committed but state still pending.
 *        Reconcile on next load: pending + committed → finalize.
 *
 * Returns { approvedAt, approvedShapeHash } as the canonical record
 * the operator saw at approval time, even when step 5 throws. The
 * caller has succeeded in committing the intent; eventual consistency
 * via reconcile guarantees state convergence.
 */
export function recordAdapterApproval(
  adapterId: string,
  shape?: AdapterShapeInput,
): { approvedAt: string; approvedShapeHash: string } {
  const state = loadState();
  const txId = randomUUID();
  const now = new Date().toISOString();
  const existingAdapters = state.adapters ?? {};
  const existing = existingAdapters[adapterId];
  const shapeHash = shape ? computeAdapterShapeHash(shape) : '';

  // Step 1 — intent (write-ahead).
  appendApprovalAudit('cli_approval_intent', adapterId, shapeHash, txId);

  // Step 2 — save pending state. The committed approvedAt/Hash on any
  // prior approval is intentionally cleared during the in-flight
  // window: dispatch must refuse until commit lands. If commit fails,
  // the prior approval stays cleared (conservative — "an attempt to
  // change approval that failed leaves the adapter unapproved").
  const pendingState: AdapterState = {
    ...state,
    adapters: {
      ...existingAdapters,
      [adapterId]: {
        type: existing?.type ?? 'cli-bridge',
        status: existing?.status ?? 'approved',
        toolCount: existing?.toolCount ?? 0,
        installedVersion: existing?.installedVersion,
        lastVerified: existing?.lastVerified ?? null,
        approvedAt: null,
        approvedShapeHash: null,
        approvalTx: { id: txId, kind: 'approve', startedAt: now, shapeHash },
      },
    },
  };
  saveState(pendingState);

  // Step 3 — commit terminator. On any throw, append failed (best-
  // effort) and rethrow.
  try {
    appendApprovalAudit('cli_approval_committed', adapterId, shapeHash, txId);
  } catch (err) {
    try { appendApprovalAudit('cli_approval_failed', adapterId, shapeHash, txId); } catch { /* best-effort terminator; reconcile will treat no-terminator as failed */ }
    throw err;
  }

  // Step 4 — save final committed state. This is the in-process
  // shortcut that avoids a reconcile round-trip on the next load.
  // If THIS throws, the audit chain is the source of truth:
  // reconcile on next loadState sees pending + committed → finalize.
  const committedState: AdapterState = {
    ...pendingState,
    adapters: {
      ...pendingState.adapters,
      [adapterId]: {
        ...pendingState.adapters[adapterId],
        approvedAt: now,
        approvedShapeHash: shapeHash,
        approvalTx: null,
      },
    },
  };
  saveState(committedState);

  return { approvedAt: now, approvedShapeHash: shapeHash };
}

/**
 * Remove approval — 2PC mirror of recordAdapterApproval. The audit
 * chain serialises the revocation in three steps; state on disk only
 * advances after each step's commit/terminator. Reconcile handles
 * crash recovery the same way as for approve.
 */
export function revokeAdapterApproval(adapterId: string): boolean {
  const state = loadState();
  const existingAdapters = state.adapters ?? {};
  const entry = existingAdapters[adapterId];
  if (!isApprovedEntry(entry)) return false;

  const txId = randomUUID();
  const now = new Date().toISOString();

  // Step 1 — intent.
  appendApprovalAudit('cli_revocation_intent', adapterId, null, txId);

  // Step 2 — pending state. approvedAt/Hash cleared immediately —
  // dispatch refuses during the in-flight window.
  const pendingState: AdapterState = {
    ...state,
    adapters: {
      ...existingAdapters,
      [adapterId]: {
        ...entry!,
        approvedAt: null,
        approvedShapeHash: null,
        approvalTx: { id: txId, kind: 'revoke', startedAt: now, shapeHash: null },
      },
    },
  };
  saveState(pendingState);

  // Step 3 — commit terminator.
  try {
    appendApprovalAudit('cli_revocation_committed', adapterId, null, txId);
  } catch (err) {
    try { appendApprovalAudit('cli_revocation_failed', adapterId, null, txId); } catch { /* best-effort */ }
    throw err;
  }

  // Step 4 — finalize state (clear approvalTx; approvedAt/Hash stay null).
  const committedState: AdapterState = {
    ...pendingState,
    adapters: {
      ...pendingState.adapters,
      [adapterId]: {
        ...pendingState.adapters[adapterId],
        approvalTx: null,
      },
    },
  };
  saveState(committedState);

  return true;
}

// ── Append-only hash-chained approval-action audit log ──────────────────────
// Q-3.4: every `chariot approve` and `chariot revoke` writes a record
// to APPROVAL_AUDIT_FILE. Each record carries the SHA-256 hash of the
// canonical-JSON serialisation of (prev_hash || record-body). The log
// is therefore tamper-evident — silent deletion or re-ordering of
// records is detected by verifyApprovalAudit() walking the chain.
//
// This is the chariot-side equivalent of the IAM-side AuditTrail; it
// lives in a separate file because CLI operator actions have no tenant
// context and therefore don't fit the tenant-keyed IAM audit model.

/**
 * Audit event taxonomy.
 *
 * Legacy single-row events (still accepted for backward compatibility
 * with existing on-disk chains; `appendApprovalAudit` may emit them
 * when called via the legacy 3-arg signature):
 *   - `cli_approval_recorded`  — approve happened (legacy 1-phase)
 *   - `cli_approval_revoked`   — revoke happened (legacy 1-phase)
 *
 * 2PC events (review-prescribed 2026-05-25). Every approve/revoke
 * traces a 3-step trajectory: intent → save pending state → terminator.
 * The terminator is either `*_committed` (state finalized) or
 * `*_failed` (state rolled back to no approval). `reconcilePendingApprovals`
 * walks the chain by `tx_id` to determine the outcome of any pending
 * transaction in the loaded state.
 *   - `cli_approval_intent`        — approve initiated
 *   - `cli_approval_committed`     — approve finalized
 *   - `cli_approval_failed`        — approve rolled back
 *   - `cli_revocation_intent`      — revoke initiated
 *   - `cli_revocation_committed`   — revoke finalized
 *   - `cli_revocation_failed`      — revoke rolled back
 */
export type ApprovalAuditEvent =
  | 'cli_approval_recorded'
  | 'cli_approval_revoked'
  | 'cli_approval_intent'
  | 'cli_approval_committed'
  | 'cli_approval_failed'
  | 'cli_revocation_intent'
  | 'cli_revocation_committed'
  | 'cli_revocation_failed';

export interface ApprovalAuditRecord {
  seq: number;
  ts: string;
  event: ApprovalAuditEvent;
  adapter_id: string;
  approved_shape_hash: string | null;
  /**
   * 2PC transaction id linking an intent record to its committed/failed
   * terminator. Optional for backward compatibility — old legacy
   * `cli_approval_recorded` / `cli_approval_revoked` rows do not carry
   * a tx_id, and canonicalStringify drops undefined fields, so the
   * existing on-disk chains continue to verify byte-for-byte.
   */
  tx_id?: string;
  prev_hash: string;
  hash: string;
}

// E-4.1: tail-read window for readLastAuditEntry. A current record
// JSON-serialises to ~250-400 bytes; 4096 gives ~10x headroom so a
// single readSync recovers the last record even if the schema grows.
const APPROVAL_AUDIT_TAIL_BYTES = 4096;

// canonicalStringify performs deterministic key-sorted serialisation,
// so the chain's hash output is invariant to object-literal key order
// here and in any future caller. No manual key-order contract needed.
//
// `tx_id` is optional: canonicalStringify drops `undefined` fields
// (src/util/canonical-json.ts:101), so legacy records that pre-date the
// 2PC protocol (no tx_id) recompute byte-identical hashes. New 2PC
// records with `tx_id: string` get a different canonical body and a
// different hash — but they were always written with tx_id included,
// so verifyApprovalAudit also recomputes with tx_id and the chain
// stays internally consistent.
function computeAuditHash(prevHash: string, body: { seq: number; ts: string; event: string; adapter_id: string; approved_shape_hash: string | null; tx_id?: string }): string {
  const canonical = canonicalStringify({
    prev_hash: prevHash,
    seq: body.seq,
    ts: body.ts,
    event: body.event,
    adapter_id: body.adapter_id,
    approved_shape_hash: body.approved_shape_hash,
    tx_id: body.tx_id,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

// E-4.1: O(1) tail-read. The previous implementation called
// readFileSync(entire file) + split('\n') on every append, which is
// O(N) in the chain length. The append-only nature of the log means
// the last record is always within the final APPROVAL_AUDIT_TAIL_BYTES
// of the file — we readSync that window only.
//
// Correctness notes:
//   - If the file is shorter than the window, we read from offset 0
//     and treat every line as complete.
//   - If we read from a non-zero offset, the bytes before the first
//     '\n' belong to a partial line that started earlier — drop it.
//   - Empty trailing line (from JSON.stringify(record)+'\n') is filtered.
//   - On any IO / parse failure we return null. Returning null means
//     the next append will start a NEW chain at seq=1; this matches
//     the prior swallow-and-restart semantic and is NOT a regression.
//   - UTF-8 boundary safety: all current record field values are ASCII
//     (ISO-8601 ts, 64-char hex hashes, slug adapter_ids, fixed event
//     strings, ASCII numbers). If a future schema admits non-ASCII
//     adapter_ids, the tail-window cut may land mid-codepoint and the
//     slice-after-first-\n still recovers cleanly because the dropped
//     prefix is the only place a partial codepoint can land.
//   - E6-1: file-absent detection is folded into the openSync ENOENT
//     catch so we don't pay a separate existsSync syscall before open.
//   - Pre-existence (for the appendApprovalAudit chmod-tighten decision)
//     is NOT derived from this function's return — a 0-byte file still
//     pre-exists but readLastAuditEntry returns null. The caller checks
//     existsSync directly to close that security gap (Q6-1).
function readLastAuditEntry(): { seq: number; hash: string } | null {
  let fd: number | null = null;
  try {
    fd = openSync(APPROVAL_AUDIT_FILE, 'r');
  } catch {
    return null;
  }
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return null;
    const readLen = size < APPROVAL_AUDIT_TAIL_BYTES ? size : APPROVAL_AUDIT_TAIL_BYTES;
    const offset = size - readLen;
    const buf = Buffer.alloc(readLen);
    const bytesRead = readSync(fd, buf, 0, readLen, offset);
    if (bytesRead <= 0) return null;
    let text = buf.subarray(0, bytesRead).toString('utf-8');
    if (offset > 0) {
      const firstNl = text.indexOf('\n');
      if (firstNl < 0) return null;
      text = text.slice(firstNl + 1);
    }
    const lines = text.split('\n').filter((l) => l.length > 0);
    if (lines.length === 0) return null;
    const last = JSON.parse(lines[lines.length - 1]) as ApprovalAuditRecord;
    if (typeof last.seq !== 'number' || typeof last.hash !== 'string') return null;
    return { seq: last.seq, hash: last.hash };
  } catch {
    return null;
  } finally {
    try { closeSync(fd); } catch { /* fd already closed or invalid */ }
  }
}

export function appendApprovalAudit(
  event: ApprovalAuditEvent,
  adapterId: string,
  approvedShapeHash: string | null,
  txId?: string,
): ApprovalAuditRecord {
  ensureDir(EPIC_AI_DIR);
  // Q-4.3 + Q6-1: appendFileSync's { mode } option only applies when
  // the file is CREATED. If approval-audit.jsonl pre-exists at a wider
  // mode (e.g. 0644 from a prior chariot version, an aborted prior
  // write that left a 0-byte file, or an operator umask of 0022 when
  // an unrelated tool touched it), the append leaves the wider mode
  // intact. We chmod-tighten AFTER the write; a sub-millisecond window
  // exists where the new bytes are readable at the pre-existing mode
  // before the chmod completes. Full atomicity would require fchmod-
  // before-write via open/fchmod/write/close which Node's
  // appendFileSync doesn't expose. On the per-user `~/.epic-ai/`
  // threat model this window is acceptable.
  //
  // `preExisted` MUST come from existsSync (NOT from readLastAuditEntry
  // returning non-null) so that a 0-byte pre-existing file — which
  // returns null from readLastAuditEntry — still triggers the chmod
  // tightening on its first written record.
  const preExisted = existsSync(APPROVAL_AUDIT_FILE);
  const last = readLastAuditEntry();
  const seq = (last?.seq ?? 0) + 1;
  const ts = new Date().toISOString();
  const prevHash = last?.hash ?? GENESIS_HASH;
  const hash = computeAuditHash(prevHash, { seq, ts, event, adapter_id: adapterId, approved_shape_hash: approvedShapeHash, tx_id: txId });
  const record: ApprovalAuditRecord = {
    seq, ts, event,
    adapter_id: adapterId,
    approved_shape_hash: approvedShapeHash,
    ...(txId !== undefined ? { tx_id: txId } : {}),
    prev_hash: prevHash,
    hash,
  };
  appendFileSync(APPROVAL_AUDIT_FILE, JSON.stringify(record) + '\n', { mode: 0o600 });
  if (preExisted) {
    try {
      const st = statSync(APPROVAL_AUDIT_FILE);
      // Skip the chmod when bits are already 0600 to avoid touching
      // ctime on every append (and to avoid the syscall).
      if ((st.mode & 0o777) !== 0o600) chmodSync(APPROVAL_AUDIT_FILE, 0o600);
    } catch { /* best-effort tightening; append already succeeded */ }
  }
  return record;
}

/**
 * Walk the approval-audit log and verify every hash link. Returns the
 * count of records on success; throws Error with chain-break detail
 * when a link is broken (silent delete, re-order, or tamper). Exposed
 * as a test seam and for future `chariot approvals --verify` subcommand.
 */
export function verifyApprovalAudit(): number {
  if (!existsSync(APPROVAL_AUDIT_FILE)) return 0;
  const text = readFileSync(APPROVAL_AUDIT_FILE, 'utf-8');
  const lines = text.split('\n').filter((l) => l.length > 0);
  let prev = GENESIS_HASH;
  let expectedSeq = 1;
  for (let i = 0; i < lines.length; i++) {
    // Q-4.2: a truncated mid-append write (power loss, disk full) or
    // on-disk corruption produces a raw `SyntaxError: Unexpected token`
    // from JSON.parse with no record-location context. Wrap and rethrow
    // an Error that names the offending line so operators investigating
    // a verify failure can locate the bad record immediately.
    let r: ApprovalAuditRecord;
    try {
      r = JSON.parse(lines[i]) as ApprovalAuditRecord;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`approval-audit: malformed record at line ${i + 1}: ${msg}`);
    }
    if (r.seq !== expectedSeq) throw new Error(`approval-audit: seq gap at line ${i + 1}; expected ${expectedSeq}, got ${r.seq}`);
    if (r.prev_hash !== prev) throw new Error(`approval-audit: prev_hash mismatch at seq ${r.seq}`);
    const recomputed = computeAuditHash(prev, {
      seq: r.seq,
      ts: r.ts,
      event: r.event,
      adapter_id: r.adapter_id,
      approved_shape_hash: r.approved_shape_hash,
      tx_id: r.tx_id,
    });
    if (r.hash !== recomputed) throw new Error(`approval-audit: hash tampered at seq ${r.seq}`);
    prev = r.hash;
    expectedSeq++;
  }
  return lines.length;
}

// ── 2PC reconcile — review-prescribed crash recovery ─────────────────────────
// reconcilePendingApprovals is called by loadState on every parse. It
// resolves any entry with `approvalTx` set by walking the audit chain
// for that tx_id's terminator:
//   - committed → finalize approvedAt/approvedShapeHash, clear approvalTx
//   - failed   → clear approvalTx (state stays unapproved)
//   - no terminator → treat as failed; clear approvalTx
// The dispatcher trusts ONLY approvedAt/approvedShapeHash, so a stale
// approvalTx without reconciliation is safe but non-functional — the
// adapter stays unapproved until reconcile rolls it forward.

type TerminalOutcome = 'committed' | 'failed';

/**
 * Walk the audit chain forward and record the latest terminal event
 * (`*_committed` / `*_failed`) for each requested tx_id. Returns a
 * map. Tx_ids with no terminal event are NOT present in the map —
 * callers should treat absence as "failed / unknown" so a crashed
 * 2PC never leaves a phantom approval.
 *
 * Reads the audit file once via readFileSync. Cold path
 * (loadState reconcile), not the dispatcher hot path, so the
 * full-file read is fine.
 */
function readAuditChainOutcomes(txIds: ReadonlyArray<string>): Map<string, TerminalOutcome> {
  const want = new Set(txIds);
  const out = new Map<string, TerminalOutcome>();
  if (want.size === 0) return out;
  if (!existsSync(APPROVAL_AUDIT_FILE)) return out;
  let text: string;
  try { text = readFileSync(APPROVAL_AUDIT_FILE, 'utf-8'); } catch { return out; }
  const lines = text.split('\n');
  for (const line of lines) {
    if (line.length === 0) continue;
    let r: ApprovalAuditRecord;
    try { r = JSON.parse(line) as ApprovalAuditRecord; } catch { continue; }
    const id = r.tx_id;
    if (typeof id !== 'string' || !want.has(id)) continue;
    if (r.event === 'cli_approval_committed' || r.event === 'cli_revocation_committed') {
      out.set(id, 'committed');
    } else if (r.event === 'cli_approval_failed' || r.event === 'cli_revocation_failed') {
      out.set(id, 'failed');
    }
    // intent rows do not set an outcome; absence-from-map means
    // "no terminator seen" which the reconcile loop treats as failed.
  }
  return out;
}

/**
 * Pure function — given a parsed AdapterState, return a NEW state with
 * any in-flight `approvalTx` entries resolved according to the audit
 * chain. If nothing pending, returns the input state unchanged (same
 * object reference) so callers can cheaply detect "no work to do."
 */
export function reconcilePendingApprovals(state: AdapterState): AdapterState {
  const adapters = state.adapters ?? {};
  const pending: Array<[string, NonNullable<AdapterState['adapters'][string]['approvalTx']>]> = [];
  for (const [id, entry] of Object.entries(adapters)) {
    if (entry && entry.approvalTx) pending.push([id, entry.approvalTx]);
  }
  if (pending.length === 0) return state;

  const outcomes = readAuditChainOutcomes(pending.map(([, tx]) => tx.id));

  let changed = false;
  const newAdapters: AdapterState['adapters'] = { ...adapters };
  for (const [id, tx] of pending) {
    const entry = adapters[id];
    if (!entry) continue;
    const outcome = outcomes.get(tx.id);
    if (outcome === 'committed') {
      if (tx.kind === 'approve') {
        newAdapters[id] = {
          ...entry,
          approvedAt: tx.startedAt,
          approvedShapeHash: tx.shapeHash,
          approvalTx: null,
        };
      } else {
        // Revocation committed: approvedAt/Hash were already cleared
        // when the pending state was written; just clear approvalTx.
        newAdapters[id] = {
          ...entry,
          approvedAt: null,
          approvedShapeHash: null,
          approvalTx: null,
        };
      }
      changed = true;
    } else {
      // 'failed' OR no terminator: roll back the in-flight marker but
      // preserve the prior committed state (approvedAt/Hash were
      // already cleared by the pending save; that clearing was the
      // intentional conservative-failure semantic, so we leave it).
      newAdapters[id] = { ...entry, approvalTx: null };
      changed = true;
    }
  }
  if (!changed) return state;
  return { ...state, adapters: newAdapters };
}

/**
 * Enumerate every adapter that carries an `approvedAt` timestamp. Used
 * by `chariot approvals` to show the operator their approval ledger.
 */
export function listApprovedAdapters(): Array<{ id: string; approvedAt: string; type: string; approvedShapeHash: string | null }> {
  try {
    const state = loadState();
    const out: Array<{ id: string; approvedAt: string; type: string; approvedShapeHash: string | null }> = [];
    for (const [id, entry] of Object.entries(state.adapters ?? {})) {
      if (isApprovedEntry(entry)) {
        out.push({
          id,
          approvedAt: entry.approvedAt as string,
          type: entry.type ?? 'cli-bridge',
          approvedShapeHash: typeof entry.approvedShapeHash === 'string' ? entry.approvedShapeHash : null,
        });
      }
    }
    return out;
  } catch {
    return [];
  }
}
