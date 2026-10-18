/**
 * IAM — Audit Service
 *
 * Hash-chained, tamper-evident audit logging with optimistic-locking
 * writes and full chain verification.
 */

import { createHash } from 'node:crypto';
import { canonicalStringify } from '../../util/canonical-json.js';
import { GENESIS_HASH } from '../../util/audit-chain.js';
import { getCollection } from '../db.js';
import type { AuditEventDocument, AuditEventType, AuditTargetType } from '../types.js';
import { withAuditLock } from './audit-mutex.js';
import { chariotEmitter } from '../../observability/emitter.js';
import { createLogger } from '../../engine/logger.js';

// Production logging goes through the project logger (never console.*).
const moduleLog = createLogger('iam.audit');

const EVENTS_COLLECTION = 'iam_audit_events';
const COUNTERS_COLLECTION = 'iam_audit_counters';
const MAX_RETRIES = 10;
/** §3.3::7: the per-tenant audit counter document is keyed by _id = `audit:{tenantId}`. */
function auditCounterId(tenantId: string): string {
  return `audit:${tenantId}`;
}

// ── Internal types ──────────────────────────────────────────────────────────

interface AuditCounter {
  _id: string;
  tenantId: string;
  seq: number;
  lastHash: string;
}

export interface ChainedAuditEvent extends AuditEventDocument {
  seq: number;
  hash: string;
  previousHash: string;
}

export interface AuditQueryOptions {
  eventType?: AuditEventType;
  actorId?: string;
  targetId?: string;
  startDate?: Date;
  endDate?: Date;
  page?: number;
  limit?: number;
}

export interface VerifyChainResult {
  valid: boolean;
  eventsChecked: number;
  errors: string[];
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function computeHash(
  previousHash: string,
  timestamp: Date,
  eventType: string,
  actorId: string,
  targetId: string | undefined,
  metadata: Record<string, unknown> | undefined,
): string {
  // canonicalStringify guarantees byte-identical output for any two
  // metadata objects that are deeply equal — without this, two writes
  // of the same logical metadata with different key insertion order
  // produced different hashes and verifyChain reported false breaks.
  // See src/util/canonical-json.ts for the exact contract.
  const payload = [
    previousHash,
    timestamp.toISOString(),
    eventType,
    actorId,
    targetId ?? '',
    metadata ? canonicalStringify(metadata) : '',
  ].join('|');

  return createHash('sha256').update(payload).digest('hex');
}

/**
 * Ensure a counter document exists for the tenant. Returns the current state.
 */
async function ensureCounter(tenantId: string): Promise<AuditCounter> {
  const col = await getCollection<AuditCounter>(COUNTERS_COLLECTION);

  const existing = await col.findOne({ _id: auditCounterId(tenantId) });
  if (existing) return existing;

  await col.updateOne(
    { _id: auditCounterId(tenantId) },
    {
      $setOnInsert: {
        tenantId,
        seq: 0,
        lastHash: GENESIS_HASH,
      },
    },
    { upsert: true },
  );

  const created = await col.findOne({ _id: auditCounterId(tenantId) });
  if (!created) {
    // Unreachable under normal operation: updateOne with upsert:true has just
    // succeeded. A null here means either a concurrent delete or a storage
    // consistency failure — both are operator-critical.
    throw new Error(
      `[iam/audit] ensureCounter: counter document missing after upsert (tenant=${tenantId}). ` +
        'Possible concurrent delete or storage inconsistency.',
    );
  }
  return created;
}

// ── Write (Optimistic Locking) ──────────────────────────────────────────────

/**
 * Append a hash-chained audit event with race-safe optimistic locking.
 *
 * 1. Read counter (seq, lastHash)
 * 2. Compute SHA-256 hash from previousHash|timestamp|eventType|actorId|targetId|metadata
 * 3. CAS update counter: only if seq still matches
 * 4. On conflict (matchedCount=0), retry up to MAX_RETRIES
 * 5. Insert the event. On failure, conditionally roll back the counter.
 */
export async function log(
  tenantId: string,
  eventType: AuditEventType,
  opts: {
    actorId: string;
    /**
     * §3.5::17 — optional: the pre-dispatch request boundary (CallContext) holds
     * `auth.userId` but carries no email, and fabricating one would put a false
     * identity in a hash-chained record. Absent is recorded as '' exactly like
     * the neighbouring `ip` / `userAgent` fields.
     */
    actorEmail?: string;
    targetType: AuditTargetType;
    targetId: string;
    detail?: Record<string, unknown>;
    ip?: string;
    userAgent?: string;
  },
): Promise<ChainedAuditEvent> {
  // Serialize per-tenant audit writes in-process so the hash-chain CAS
  // loop never has to contend with itself under same-tenant bursts. The
  // CAS retry loop below remains as the cross-process fallback for
  // multi-replica deployments (which still need a Redis-backed sibling
  // lock).
  return withAuditLock(tenantId, () => logImpl(tenantId, eventType, opts));
}

async function logImpl(
  tenantId: string,
  eventType: AuditEventType,
  opts: {
    actorId: string;
    /**
     * §3.5::17 — optional: the pre-dispatch request boundary (CallContext) holds
     * `auth.userId` but carries no email, and fabricating one would put a false
     * identity in a hash-chained record. Absent is recorded as '' exactly like
     * the neighbouring `ip` / `userAgent` fields.
     */
    actorEmail?: string;
    targetType: AuditTargetType;
    targetId: string;
    detail?: Record<string, unknown>;
    ip?: string;
    userAgent?: string;
  },
): Promise<ChainedAuditEvent> {
  const eventsCol = await getCollection<ChainedAuditEvent>(EVENTS_COLLECTION);
  const countersCol = await getCollection<AuditCounter>(COUNTERS_COLLECTION);

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    // Step 1 — read current counter
    const counter = await ensureCounter(tenantId);
    // Snapshot the counter's lastHash / seq BEFORE the CAS update. The
    // CAS in step 3 mutates the counter document in place; some drivers
    // and in-process fakes return live references to the underlying
    // document. Reading `counter.lastHash` after the CAS would observe
    // the NEW lastHash (the hash we are about to write) instead of the
    // genuine previousHash, producing events whose `previousHash` is a
    // self-reference and a hash chain that verifyChain reports as broken
    // at seq 1 (see ai-eval 15 §audit-log flooding). The snapshot here
    // is the authoritative previousHash for THIS write attempt.
    const previousHashSnapshot = counter.lastHash;
    const previousSeqSnapshot = counter.seq;
    const nextSeq = previousSeqSnapshot + 1;
    const timestamp = new Date();

    // Step 2 — compute hash
    const hash = computeHash(
      previousHashSnapshot,
      timestamp,
      eventType,
      opts.actorId,
      opts.targetId,
      opts.detail,
    );

    // Step 3 — CAS update counter
    const casResult = await countersCol.updateOne(
      { _id: auditCounterId(tenantId), seq: previousSeqSnapshot },
      { $set: { seq: nextSeq, lastHash: hash } },
    );

    if (casResult.matchedCount === 0) {
      continue;
    }

    // Step 5 — insert event
    const event: Omit<ChainedAuditEvent, '_id'> = {
      tenantId,
      seq: nextSeq,
      eventType,
      actorId: opts.actorId,
      actorEmail: opts.actorEmail ?? '',
      targetType: opts.targetType,
      targetId: opts.targetId,
      detail: opts.detail ?? {},
      ip: opts.ip ?? '',
      userAgent: opts.userAgent ?? '',
      hash,
      previousHash: previousHashSnapshot,
      timestamp,
    };

    try {
      const insertResult = await eventsCol.insertOne(event as ChainedAuditEvent);
      return { ...event, _id: insertResult.insertedId } as ChainedAuditEvent;
    } catch (insertErr) {
      // Roll back counter conditionally. The CAS filter includes the new
      // (nextSeq, hash) so the rollback is a no-op if another concurrent
      // writer has already advanced the counter past our slot — we do NOT
      // want to clobber their progress with our stale values.
      //
      // The rollback is wrapped in its own try/catch so that a rollback
      // failure is surfaced distinctly from the insert failure and does
      // NOT mask the original `insertErr`. Without this inner try/catch,
      // an error in `countersCol.updateOne` would throw out of the catch
      // block, replacing `insertErr` in the caller's view and leaving the
      // audit counter advanced with no corresponding event — a silent
      // hash-chain break.
      try {
        await countersCol.updateOne(
          { _id: auditCounterId(tenantId), seq: nextSeq, lastHash: hash },
          { $set: { seq: previousSeqSnapshot, lastHash: previousHashSnapshot } },
        );
      } catch (rollbackErr) {
         
        moduleLog.error(
          `[iam/audit] CRITICAL: counter rollback failed after insert failure ` +
            `(tenant=${tenantId}, seq=${nextSeq}) — hash chain may be inconsistent. ` +
            `Original insert error: ${insertErr instanceof Error ? insertErr.message : String(insertErr)}. ` +
            `Rollback error: ${rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)}`,
        );
      }
      throw insertErr;
    }
  }

  throw new Error(
    `[iam/audit] Failed to write audit event after ${MAX_RETRIES} retries (tenant=${tenantId})`,
  );
}

// ── Query ───────────────────────────────────────────────────────────────────

/**
 * §3.5::21 (CH-15) — compare the chain head against the `iam_audit_counters`
 * document and raise an integrity alert on a gap. A mismatch means events were
 * deleted or the counter was tampered with: the tail the counter promises is
 * not the tail the events collection actually holds.
 *
 * Fail-closed: the alert is emitted AND the caller is thrown to, so a tampered
 * log can never be served as if it were intact. Deliberately unfiltered — the
 * head is the tenant's true maximum `seq`, independent of any query filter.
 */
async function assertChainHeadMatchesCounter(
  tenantId: string,
  col: Awaited<ReturnType<typeof getCollection<ChainedAuditEvent>>>,
): Promise<void> {
  const counter = await ensureCounter(tenantId);
  const head = await col.findOne({ tenantId }, { sort: { seq: -1 } });

  const observedSeq = head?.seq ?? 0;
  const observedHash = head?.hash ?? GENESIS_HASH;

  if (counter.seq === observedSeq && counter.lastHash === observedHash) return;

  chariotEmitter.send('system.error', {
    severity: 'critical',
    alertWorthy: true,
    data: {
      reason: 'iam_audit_chain_head_counter_mismatch',
      tenantId,
      counterSeq: counter.seq,
      observedSeq,
      counterHash: counter.lastHash,
      observedHash,
    },
  });
  // CHARIOT::§16.1 Audit (CHARIOT-SPEC.md:1349, rulings item 91/105) —
  // the customer-facing, spec-pinned counterpart to the system.error
  // emit directly above (CH-15's own generic operational event) — both
  // fire, neither replaces the other. Also §16.2's own named critical-
  // severity bypass event (CHARIOT-SPEC.md:1365).
  chariotEmitter.send('audit.gap_detected', {
    severity: 'critical',
    alertWorthy: true,
    data: {
      tenantId,
      counterSeq: counter.seq,
      observedSeq,
      counterHash: counter.lastHash,
      observedHash,
    },
  });

  throw new Error(
    `[iam/audit] integrity gap detected for tenant=${tenantId}: ` +
      `counter=(${counter.seq},${counter.lastHash}) head=(${observedSeq},${observedHash})`,
  );
}

export async function query(
  tenantId: string,
  options: AuditQueryOptions = {},
): Promise<{ events: ChainedAuditEvent[]; total: number }> {
  const col = await getCollection<ChainedAuditEvent>(EVENTS_COLLECTION);

  // §3.5::21 — gap detection runs on EVERY read, before any event is returned.
  await assertChainHeadMatchesCounter(tenantId, col);

  const filter: Record<string, unknown> = { tenantId };

  if (options.eventType) filter.eventType = options.eventType;
  if (options.actorId) filter.actorId = options.actorId;
  if (options.targetId) filter.targetId = options.targetId;

  if (options.startDate || options.endDate) {
    const dateFilter: Record<string, Date> = {};
    if (options.startDate) dateFilter.$gte = options.startDate;
    if (options.endDate) dateFilter.$lte = options.endDate;
    filter.timestamp = dateFilter;
  }

  const page = options.page ?? 1;
  const limit = options.limit ?? 50;
  const skip = (page - 1) * limit;

  const [events, total] = await Promise.all([
    col.find(filter).sort({ seq: 1 }).skip(skip).limit(limit).toArray(),
    col.countDocuments(filter),
  ]);

  return { events, total };
}

/**
 * Returns the single most recent event of `eventType` for `tenantId`, or
 * null if none has ever been appended. Extension point for callers that
 * derive a "current state" from the latest record in this append-only log
 * (e.g. telemetry-consent.ts's `version` = the returned event's `seq`)
 * without pulling the tenant's full history via `query()`.
 */
export async function queryLatest(
  tenantId: string,
  eventType: AuditEventType,
): Promise<ChainedAuditEvent | null> {
  const col = await getCollection<ChainedAuditEvent>(EVENTS_COLLECTION);
  return col.findOne({ tenantId, eventType }, { sort: { seq: -1 } });
}

// ── Chain Verification ──────────────────────────────────────────────────────

/**
 * Verify the integrity of the hash chain for a tenant.
 *
 * Checks:
 * 1. Hash recomputation matches stored hash
 * 2. Chain linkage: event.previousHash === prior event's hash
 * 3. Sequence gaps: seq must be prev+1
 */
export async function verifyChain(
  tenantId: string,
  startSeq?: number,
  endSeq?: number,
): Promise<VerifyChainResult> {
  const col = await getCollection<ChainedAuditEvent>(EVENTS_COLLECTION);

  const filter: Record<string, unknown> = { tenantId };
  if (startSeq !== undefined || endSeq !== undefined) {
    const seqFilter: Record<string, number> = {};
    if (startSeq !== undefined) seqFilter.$gte = startSeq;
    if (endSeq !== undefined) seqFilter.$lte = endSeq;
    filter.seq = seqFilter;
  }

  const events = await col.find(filter).sort({ seq: 1 }).toArray();
  const errors: string[] = [];

  // If we start from seq > 1, fetch the preceding event for chain linkage
  let previousHash: string | null = null;
  let previousSeq: number | null = null;

  if (events.length > 0 && events[0].seq > 1) {
    const preceding = await col.findOne({
      tenantId,
      seq: events[0].seq - 1,
    });
    if (preceding) {
      previousHash = preceding.hash;
      previousSeq = preceding.seq;
    }
  } else if (events.length > 0 && events[0].seq === 1) {
    previousHash = GENESIS_HASH;
    previousSeq = 0;
  }

  for (const event of events) {
    // Check sequence gaps
    if (previousSeq !== null && event.seq !== previousSeq + 1) {
      errors.push(
        `Sequence gap: expected ${previousSeq + 1}, got ${event.seq}`,
      );
    }

    // Check chain linkage
    if (previousHash !== null && event.previousHash !== previousHash) {
      errors.push(
        `Chain break at seq ${event.seq}: previousHash mismatch`,
      );
    }

    // Recompute hash and compare
    const recomputed = computeHash(
      event.previousHash,
      event.timestamp,
      event.eventType,
      event.actorId,
      event.targetId,
      event.detail,
    );

    if (recomputed !== event.hash) {
      errors.push(
        `Hash mismatch at seq ${event.seq}: stored=${event.hash.slice(0, 12)}... computed=${recomputed.slice(0, 12)}...`,
      );
    }

    previousHash = event.hash;
    previousSeq = event.seq;
  }

  // §3.5::21 (CH-15) — the in-window checks above cannot see events truncated
  // from the TAIL: deleting the last N events leaves a perfectly self-consistent
  // chain. Compare the true head against the iam_audit_counters document, which
  // records the seq/hash the chain is supposed to end on. Only meaningful for a
  // full-range verification — a caller-bounded window legitimately ends early.
  const isFullRange = startSeq === undefined && endSeq === undefined;
  if (isFullRange) {
    const counter = await ensureCounter(tenantId);
    const headSeq = events.length > 0 ? events[events.length - 1].seq : 0;
    const headHash = events.length > 0 ? events[events.length - 1].hash : GENESIS_HASH;

    if (counter.seq !== headSeq || counter.lastHash !== headHash) {
      errors.push(
        `Counter/head mismatch: counter=(${counter.seq},${counter.lastHash}) ` +
          `head=(${headSeq},${headHash})`,
      );
      chariotEmitter.send('system.error', {
        severity: 'critical',
        alertWorthy: true,
        data: {
          reason: 'iam_audit_chain_head_counter_mismatch',
          tenantId,
          counterSeq: counter.seq,
          observedSeq: headSeq,
          counterHash: counter.lastHash,
          observedHash: headHash,
        },
      });
    }
  }

  return {
    valid: errors.length === 0,
    eventsChecked: events.length,
    errors,
  };
}
