/**
 * Automatic operational-telemetry upload — C4AMD §8 "Connected deployments"
 * (AMENDED 2026-10-12, MASTER chat authorization "Approve all three, wire
 * the telemetry commands."), superseding ruling item 93(6) for connected
 * topologies only.
 *
 * WHAT THIS DOES: sends already-captured, already-redacted closed
 * nine-field events (`redact.ts`) to the license host and to no other
 * destination. It is the ONLY telemetry network call site; it lives
 * OUTSIDE `src/observability/` so `egress-guard.test.ts` keeps proving
 * that directory has no network import.
 *
 * HARD GATES (every one fails closed, none throws to the caller):
 *   1. the tenant's current consent is enabled          (§8::2, §8::6)
 *   2. the consent's transport is `auto`                 (separate opt-in)
 *   3. a local license verifies and carries a `jti`      (authenticates the call)
 *   4. the license topology claim is `public-llm` or `hybrid`
 *      — `air-gapped` or ABSENT never uploads            (§8::9, "cannot be determined")
 * Failure never affects dispatch (callers use `maybeUploadAfterCapture`,
 * fire-and-forget), never falls back to another destination, and is
 * retried a bounded number of times.
 *
 * AUTHENTICATION: the same renewal-secret HMAC primitive as
 * `license/renew-client.ts`, with the SHA-256 of the exact payload string
 * bound into the proof so the batch cannot be altered in transit:
 *   proof = HMAC-SHA256(renewal_secret,
 *             company_id NUL current_jti NUL nonce NUL ts NUL sha256hex(payload))
 */

import { createHash, createHmac, randomBytes } from 'node:crypto';
import { getCurrentConsent } from '../iam/services/telemetry-consent.js';
import { getCollection, hasMongoClient } from '../iam/db.js';
import { readLicenseEnvelope, verifyAndDecode } from '../license/loader.js';
import { OPERATIONAL_TELEMETRY_COLLECTION } from '../observability/operational-telemetry/capture.js';
import { advanceUploadCursor, localReadEventsFrom, noteUploadResult, readUploadState, reserveUploadAttempt } from '../observability/operational-telemetry/local-store.js';
import { redactEvent, type OperationalTelemetryEvent } from '../observability/operational-telemetry/redact.js';
import { createLogger } from '../engine/logger.js';

const log = createLogger('telemetry-upload');

/** The ONLY destination. No environment override exists by design (C4AMD §8: "and to no other destination"). */
export const TELEMETRY_UPLOAD_URL = 'https://license.epic-ai.io/api/license/telemetry';
export const MAX_BATCH_EVENTS = 500;
export const MIN_ATTEMPT_INTERVAL_MS = 15 * 60_000;
const MAX_ATTEMPTS = 3;
const REQUEST_TIMEOUT_MS = 10_000;
const NUL = Buffer.from([0]);

export type UploadIneligibleCode =
  | 'CONSENT_DISABLED'
  | 'TRANSPORT_NOT_AUTO'
  | 'NO_LICENSE'
  | 'NO_JTI'
  | 'TOPOLOGY_UNDETERMINED'
  | 'TOPOLOGY_AIR_GAPPED';

export type UploadEligibility =
  | { eligible: true; companyId: string; jti: string; secret: Buffer; topology: 'public-llm' | 'hybrid' }
  | { eligible: false; code: UploadIneligibleCode; reason: string };

export type UploadOutcome =
  | { kind: 'ineligible'; code: UploadIneligibleCode; reason: string }
  | { kind: 'throttled'; nextAttemptAt: string }
  | { kind: 'nothing_to_upload' }
  | { kind: 'uploaded'; count: number }
  | { kind: 'failed'; stage: 'network' | 'http' | 'response' | 'store' | 'budget'; status: number; message: string };

export interface UploadOptions {
  /** Inject fetch (tests). Default: globalThis.fetch. */
  fetchImpl?: typeof fetch;
  /** Inject the clock in ms (tests). */
  nowMs?: number;
  /** Skip the inter-attempt throttle (explicit operator-requested upload, tests). */
  force?: boolean;
  /** Test-only destination override; production call sites never pass this. */
  url?: string;
  /** Test-only: replace the backoff sleep. */
  sleep?: (ms: number) => Promise<void>;
  /** Test-only: replace the local-license + topology gate (a real license needs the billing signing key). */
  licenseGate?: () => UploadEligibility;
}

/**
 * Gates 3 and 4 only (license + connected topology) — the part of
 * eligibility that does not depend on consent, so `telemetry enable
 * --transport auto` can refuse an impossible selection up front.
 */
export function evaluateConnectedLicenseGate(): UploadEligibility {
  const envelope = readLicenseEnvelope();
  if (!envelope) {
    return { eligible: false, code: 'NO_LICENSE', reason: 'No local license is installed to authenticate an upload.' };
  }
  const claims = verifyAndDecode(envelope.jwt);
  if (!claims) {
    return { eligible: false, code: 'NO_LICENSE', reason: 'The local license did not verify.' };
  }
  if (!claims.jti) {
    return { eligible: false, code: 'NO_JTI', reason: 'The local license carries no jti claim.' };
  }
  if (claims.topology === 'air-gapped') {
    return { eligible: false, code: 'TOPOLOGY_AIR_GAPPED', reason: 'Air-gapped deployments never transmit automatically (C4AMD §8::9).' };
  }
  if (claims.topology !== 'public-llm' && claims.topology !== 'hybrid') {
    return { eligible: false, code: 'TOPOLOGY_UNDETERMINED', reason: 'The license does not state a connected topology; automatic transport requires one.' };
  }
  return {
    eligible: true,
    companyId: claims.companyId,
    jti: claims.jti,
    secret: Buffer.from(envelope.renewal_secret, 'base64url'),
    topology: claims.topology,
  };
}

/** Evaluate all four hard gates. Pure aside from the consent read and the local license read. */
export async function evaluateUploadEligibility(
  tenantId: string,
  licenseGate: () => UploadEligibility = evaluateConnectedLicenseGate,
): Promise<UploadEligibility> {
  const consent = await getCurrentConsent(tenantId);
  if (!consent.enabled) {
    return { eligible: false, code: 'CONSENT_DISABLED', reason: 'Operational telemetry is not enabled for this tenant.' };
  }
  if (consent.transport !== 'auto') {
    return { eligible: false, code: 'TRANSPORT_NOT_AUTO', reason: 'Automatic transport has not been selected (export-only).' };
  }
  return licenseGate();
}

export function computeTelemetryProof(
  secret: Buffer,
  input: { companyId: string; jti: string; nonce: string; ts: number; payload: string },
): string {
  const h = createHmac('sha256', secret);
  h.update(
    Buffer.concat([
      Buffer.from(input.companyId, 'utf-8'), NUL,
      Buffer.from(input.jti, 'utf-8'), NUL,
      Buffer.from(input.nonce, 'utf-8'), NUL,
      Buffer.from(String(input.ts), 'utf-8'), NUL,
      Buffer.from(createHash('sha256').update(input.payload).digest('hex'), 'utf-8'),
    ]),
  );
  return h.digest('base64url');
}

interface Batch {
  events: OperationalTelemetryEvent[];
  nextCursor: string;
}

async function readBatch(tenantId: string, cursor: string | null): Promise<Batch> {
  if (!hasMongoClient()) {
    const from = cursor !== null && /^\d+$/.test(cursor) ? Number(cursor) : 0;
    const r = localReadEventsFrom(tenantId, from, MAX_BATCH_EVENTS);
    return { events: r.events, nextCursor: String(r.next) };
  }
  const { ObjectId } = await import('mongodb');
  const col = await getCollection(OPERATIONAL_TELEMETRY_COLLECTION);
  const filter: Record<string, unknown> = { 'event.tenantId': tenantId };
  if (cursor !== null && /^[0-9a-f]{24}$/.test(cursor)) filter['_id'] = { $gt: new ObjectId(cursor) };
  const docs = await col.find(filter).sort({ _id: 1 }).limit(MAX_BATCH_EVENTS).toArray();
  // Events are stored nested (`{ event }`); the wrapper `_id` is only the cursor.
  const events = docs.map((d) => d['event'] as OperationalTelemetryEvent);
  const last = docs.length > 0 ? docs[docs.length - 1]['_id'] : null;
  return { events, nextCursor: last !== null && last !== undefined ? String(last) : (cursor ?? '') };
}

/**
 * Upload one batch of pending events. Never throws. Advances the stored
 * cursor ONLY after the server confirms acceptance, so a failure re-sends
 * the same batch next time (the server de-duplicates by nonce+proof only
 * per request; at-least-once delivery is the documented contract).
 */
export async function uploadPending(tenantId: string, options: UploadOptions = {}): Promise<UploadOutcome> {
  const nowMs = options.nowMs ?? Date.now();
  try {
    const gate = await evaluateUploadEligibility(tenantId, options.licenseGate);
    if (!gate.eligible) return { kind: 'ineligible', code: gate.code, reason: gate.reason };

    const state = readUploadState(tenantId);
    if (!options.force && state.lastAttemptAt !== null) {
      const next = Date.parse(state.lastAttemptAt) + MIN_ATTEMPT_INTERVAL_MS;
      if (Number.isFinite(next) && nowMs < next) {
        return { kind: 'throttled', nextAttemptAt: new Date(next).toISOString() };
      }
    }

    let batch: Batch;
    try {
      batch = await readBatch(tenantId, state.cursor);
    } catch (err) {
      return { kind: 'failed', stage: 'store', status: 0, message: err instanceof Error ? err.message : String(err) };
    }

    // Second independent pass through the closed-schema allowlist: nothing
    // outside the nine fields can leave, even from a tampered store.
    const events: OperationalTelemetryEvent[] = [];
    for (const e of batch.events) {
      try {
        events.push(
          redactEvent({
            tenantId: e.tenantId,
            canonicalToolId: e.canonicalToolId,
            outcome: e.outcome,
            latencyMs: e.latencyMs,
            failureStage: e.failureStage,
            hourBucket: e.hourBucket,
            productVersion: e.productVersion,
            platform: e.platform,
            catalogEpoch: e.catalogEpoch,
          }),
        );
      } catch {
        // A stored event that no longer satisfies the closed schema is never sent.
      }
    }
    if (batch.events.length === 0) return { kind: 'nothing_to_upload' };

    const at = new Date(nowMs).toISOString();
    // The batch's identity is the cursor it starts at. The attempt budget is
    // PERSISTED against it and reserved atomically (`reserveUploadAttempt`),
    // so "at most three attempts per batch" holds across process restarts,
    // throttle windows AND concurrent processes — not just within one call.
    const batchKey = state.cursor ?? '';

    /** Move the cursor past this batch (sent, skipped as invalid, rejected, or out of attempts) — only if it is still where we started. */
    const dropBatch = (result: string): void => {
      advanceUploadCursor(tenantId, state.cursor, batch.nextCursor, result, at);
    };
    /** Record an outcome without touching the cursor or the reserved attempt count. */
    const noteResult = (result: string): void => noteUploadResult(tenantId, result, at);
    void batchKey;

    if (events.length === 0) {
      // Every pending row was schema-invalid; skip past them so they cannot wedge the queue.
      dropBatch('uploaded:0');
      return { kind: 'nothing_to_upload' };
    }

    const payload = JSON.stringify(events);
    const fetchImpl = options.fetchImpl ?? fetch;
    const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const url = options.url ?? TELEMETRY_UPLOAD_URL;
    let lastFailure: UploadOutcome = { kind: 'failed', stage: 'budget', status: 0, message: 'attempt budget exhausted' };
    let callAttempts = 0;

    for (;;) {
      if (callAttempts > 0) await sleep(1000 * 2 ** (callAttempts - 1));

      // Atomic, cross-process reservation of one attempt from the batch's budget.
      const reservation = reserveUploadAttempt(tenantId, state.cursor, MAX_ATTEMPTS, at);
      if (!reservation.ok) {
        if (reservation.reason === 'exhausted') {
          // The budget is spent: the batch is dropped so it can neither get
          // a further attempt nor wedge the queue.
          dropBatch(`dropped-exhausted:${lastFailure.kind === 'failed' ? lastFailure.stage : 'unknown'}`);
          return lastFailure;
        }
        return { kind: 'nothing_to_upload' }; // another process already sent or dropped this batch
      }
      callAttempts++;

      // LAST gate before the network: every consent / transport / license /
      // topology condition is re-evaluated immediately before EACH
      // transmission, the first one included — consent or the license can
      // change while the batch read or a backoff was pending.
      const now = await evaluateUploadEligibility(tenantId, options.licenseGate);
      if (!now.eligible) {
        noteResult(`ineligible:${now.code}`);
        return { kind: 'ineligible', code: now.code, reason: now.reason };
      }

      const nonce = randomBytes(32).toString('base64url');
      const ts = Math.floor(nowMs / 1000);
      const proof = computeTelemetryProof(now.secret, { companyId: now.companyId, jti: now.jti, nonce, ts, payload });
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      try {
        const res = await fetchImpl(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ company_id: now.companyId, current_jti: now.jti, nonce, ts, proof, payload }),
          signal: controller.signal,
          // A redirect could forward the batch to a host that is not the
          // license host (C4AMD §8: "and to no other destination"): refuse.
          redirect: 'error',
        });
        clearTimeout(timer);
        if (res.status === 200) {
          dropBatch(`uploaded:${events.length}`);
          return { kind: 'uploaded', count: events.length };
        }
        lastFailure = { kind: 'failed', stage: 'http', status: res.status, message: `HTTP ${res.status}` };
        // A batch the server rejects as malformed/oversized (400/413/422) can
        // never succeed on retry and would wedge every later event behind it:
        // drop it and move the cursor. Telemetry is best-effort by contract.
        if (res.status === 400 || res.status === 413 || res.status === 422) {
          dropBatch(`uploaded:dropped-${res.status}`);
          return lastFailure;
        }
        // Other 4xx (auth/unknown company/stale jti) is a definite answer —
        // retrying within this call cannot change it; the batch keeps its
        // reserved attempt and is retried only up to the three-attempt budget.
        if (res.status >= 400 && res.status < 500) {
          if (reservation.attempts >= MAX_ATTEMPTS) dropBatch(`dropped-exhausted:http:${res.status}`);
          else noteResult(`failed:http:${res.status}`);
          return lastFailure;
        }
      } catch (err) {
        clearTimeout(timer);
        lastFailure = { kind: 'failed', stage: 'network', status: 0, message: err instanceof Error ? err.message : String(err) };
      }

      if (reservation.attempts >= MAX_ATTEMPTS) {
        dropBatch(`dropped-exhausted:${lastFailure.kind === 'failed' ? lastFailure.stage : 'unknown'}`);
        return lastFailure;
      }
    }
  } catch (err) {
    return { kind: 'failed', stage: 'store', status: 0, message: err instanceof Error ? err.message : String(err) };
  }
}

const inFlight = new Set<string>();
const lastKickMs = new Map<string, number>();

/**
 * Fire-and-forget hook for the dispatch path. Never awaited, never throws,
 * at most one in-flight upload per tenant per process, and throttled twice:
 * in memory here (no I/O at all on the hot path between kicks) and by the
 * persisted last-attempt time inside `uploadPending`, so short-lived CLI
 * processes cannot hammer the license host.
 */
export function maybeUploadAfterCapture(tenantId: string): void {
  const now = Date.now();
  const last = lastKickMs.get(tenantId);
  if (last !== undefined && now - last < MIN_ATTEMPT_INTERVAL_MS) return;
  if (inFlight.has(tenantId)) return;
  lastKickMs.set(tenantId, now);
  inFlight.add(tenantId);
  uploadPending(tenantId)
    .then((o) => {
      if (o.kind === 'failed') log.warn('telemetry upload failed (non-fatal)', { stage: o.stage, status: o.status });
    })
    .catch(() => undefined)
    .finally(() => inFlight.delete(tenantId));
}
