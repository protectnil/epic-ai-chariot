/**
 * Operational-telemetry capture (C4AMD §8::2, §8::4).
 *
 * Governing clause bytes (traceability.spec_nodes, C4AMD::§8::2):
 *   "Operational telemetry SHALL be off by default."
 * Governing clause bytes (C4AMD::§8::4):
 *   "Customer authorization to use an adapter SHALL NOT imply telemetry
 *   permission."
 * Governing ruling (item 93, 2026-09-04): "v4.0 telemetry has NO automatic
 * transport in any mode — local store plus a deliberate, customer-
 * triggered, redacted, signed export everywhere."
 *
 * `captureEvent` is the ONLY write path into the local
 * `operational_telemetry_events` collection, and it is a hard no-op
 * (returns `null`, never throws to the caller) unless
 * `telemetry-consent.getCurrentConsent(tenantId).enabled` is `true` at
 * call time — read fresh on every call, never cached, so a mid-session
 * revoke (C4AMD §8::6) takes effect on the very next call. This module
 * imports `telemetry-consent.ts` (this tenant's OWN opt-in state) and
 * NOTHING from the adapter-authorization surface (`tenant.ts`, `oauth.ts`,
 * `id-jag-*.ts`) — §8::4's independence is enforced by the plain fact
 * that no adapter-authorization code path can set the flag this module
 * reads.
 *
 * NO NETWORK I/O: this file imports nothing that can perform egress
 * (`fetch`, `http`, `https`, an HTTP client, a message-queue producer).
 * `captureEvent` writes to the LOCAL Mongo store only, via
 * `src/iam/db.ts`'s already-configured connection (not a new remote
 * target) — see `export.ts` for the one deliberate, customer-triggered
 * path data can ever leave through (§8::7-9), and
 * `egress-guard.test.ts` for the grep-guard proving no fetch/http import
 * exists anywhere under this directory.
 *
 * Capture failures (a bad DB write, a malformed candidate event) are
 * swallowed and logged, never thrown — telemetry, being off by default
 * and non-critical, must never be able to fail or block a real
 * chariot_call/chariot_query completion.
 */

import { getCollection, hasMongoClient } from '../../iam/db.js';
import { getCurrentConsent } from '../../iam/services/telemetry-consent.js';
import { createLogger } from '../../engine/logger.js';
import {
  redactEvent,
  toHourBucket,
  type OperationalTelemetryEvent,
  type TelemetryOutcome,
  type TelemetryFailureStage,
} from './redact.js';
import { localAppendEvent, localReadEvents } from './local-store.js';
import { getLoadedCatalogEpoch, getPlatformKey, getProductVersion } from './runtime-context.js';

const COLLECTION = 'operational_telemetry_events';
/** Exported so `export.ts` reads the SAME collection name — never a second hard-coded copy that could drift. */
export const OPERATIONAL_TELEMETRY_COLLECTION = COLLECTION;
const moduleLog = createLogger('observability.operational-telemetry');

export interface CaptureInput {
  tenantId: string;
  canonicalToolId: string;
  outcome: TelemetryOutcome;
  latencyMs: number;
  /** Required when `outcome === 'failure'`; ignored (forced to `null`) when `outcome === 'success'`. */
  failureStage: TelemetryFailureStage | null;
  /** The event's wall-clock time — floored to the hour by `toHourBucket` before storage (§8::3 minimization). */
  occurredAt: Date;
}

/**
 * Capture one operational-telemetry event IF AND ONLY IF the tenant has
 * current opted-in consent. Returns the stored (redacted) event, or
 * `null` when consent is absent/false/revoked, or when capture failed for
 * any reason (logged, never thrown).
 */
export async function captureEvent(input: CaptureInput): Promise<OperationalTelemetryEvent | null> {
  try {
    if (!input.tenantId) return null;

    const consent = await getCurrentConsent(input.tenantId);
    if (!consent.enabled) return null;

    const productVersion = getProductVersion();
    if (productVersion === null) {
      // productVersion is the installed package version (C4AMD §8); if it
      // cannot be determined the event is not emitted rather than mislabelled.
      moduleLog.warn('operational-telemetry capture skipped: installed package version unreadable');
      return null;
    }

    const event = redactEvent({
      tenantId: input.tenantId,
      canonicalToolId: input.canonicalToolId,
      outcome: input.outcome,
      latencyMs: input.latencyMs,
      failureStage: input.outcome === 'success' ? null : input.failureStage,
      hourBucket: toHourBucket(input.occurredAt),
      productVersion,
      platform: getPlatformKey(),
      catalogEpoch: getLoadedCatalogEpoch(),
    });

    if (hasMongoClient()) {
      // The event is stored as a NESTED object so its persisted representation
      // is exactly the nine closed fields (C4AMD §8::19); MongoDB's own `_id`
      // belongs to the wrapper document, never to the telemetry event.
      const col = await getCollection(COLLECTION);
      await col.insertOne({ event: { ...event } });
    } else {
      localAppendEvent(event);
    }
    return event;
  } catch (err) {
    moduleLog.error('operational-telemetry capture failed (non-fatal, call completion unaffected)', {
      error: err instanceof Error ? err.message : String(err),
    });
    return null;
  }
}

/**
 * Read back a tenant's locally-stored events, oldest first — the ONLY
 * consumer of this is `export.ts`'s deliberate, customer-triggered export
 * flow (§8::7-9). This is a local Mongo read, not a network call.
 */
export async function getStoredEvents(
  tenantId: string,
  opts: { sinceHourBucket?: string } = {},
): Promise<OperationalTelemetryEvent[]> {
  if (!hasMongoClient()) return localReadEvents(tenantId, opts);
  const col = await getCollection(COLLECTION);
  const filter: Record<string, unknown> = { 'event.tenantId': tenantId };
  if (opts.sinceHourBucket) filter['event.hourBucket'] = { $gte: opts.sinceHourBucket };
  const docs = await col.find(filter).sort({ 'event.hourBucket': 1 }).toArray();
  return docs.map((d) => d['event'] as OperationalTelemetryEvent);
}
