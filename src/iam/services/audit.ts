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

const EVENTS_COLLECTION = 'iam_audit_events';
const COUNTERS_COLLECTION = 'iam_audit_counters';
const MAX_RETRIES = 10;

// ── Internal types ──────────────────────────────────────────────────────────

interface AuditCounter {
  tenantId: string;
  seq: number;
  lastHash: string;
}

interface ChainedAuditEvent extends AuditEventDocument {
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

  const existing = await col.findOne({ tenantId });
  if (existing) return existing;

  await col.updateOne(
    { tenantId },
    {
      $setOnInsert: {
        tenantId,
        seq: 0,
        lastHash: GENESIS_HASH,
      },
    },
    { upsert: true },
  );

  const created = await col.findOne({ tenantId });
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
    actorEmail: string;
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
    actorEmail: string;
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
      { tenantId, seq: previousSeqSnapshot },
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
      actorEmail: opts.actorEmail,
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
          { tenantId, seq: nextSeq, lastHash: hash },
          { $set: { seq: previousSeqSnapshot, lastHash: previousHashSnapshot } },
        );
      } catch (rollbackErr) {
         
        console.error(
          `[iam/audit] CRITICAL: counter rollback failed after insert failure ` +
            `(tenant=${tenantId}, seq=${nextSeq}) — hash chain may be inconsistent. ` +
            `Original insert error: ${insertErr instanceof Error ? insertErr.message : String(insertErr)}. ` +
            `Rollback error:`,
          rollbackErr,
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

export async function query(
  tenantId: string,
  options: AuditQueryOptions = {},
): Promise<{ events: ChainedAuditEvent[]; total: number }> {
  const col = await getCollection<ChainedAuditEvent>(EVENTS_COLLECTION);

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

  return {
    valid: errors.length === 0,
    eventsChecked: events.length,
    errors,
  };
}
